"""Company / Workspace tier — registry, membership, grouping (Epic F-C1, offline).

The companies registry and project metadata both land on per-test temp paths
(conftest ``_isolate_companies_registry`` + the project tree under ``tmp_path``),
so nothing touches the real working tree.
"""

import pytest

from core.company import (
    UNASSIGNED, UNASSIGNED_LABEL, CompanyRegistry, company_slug, group_projects,
)
from core.project import ProjectStore


# ── company_slug ────────────────────────────────────────────────────────────

def test_company_slug_normalises():
    assert company_slug("Acme Corp") == "acme_corp"
    assert company_slug("  ACME  ") == "acme"
    assert company_slug("a.b-c") == "a.b-c"          # dots/hyphens kept


def test_company_slug_empty_and_garbage():
    assert company_slug("") == ""
    assert company_slug("   ") == ""
    assert company_slug("***") == ""                 # collapses → stripped to ''
    # Cannot collide with the reserved Unassigned sentinel (leading _ stripped).
    assert company_slug("__unassigned__") != UNASSIGNED


# ── CompanyRegistry ─────────────────────────────────────────────────────────

def test_registry_create_get_and_display():
    reg = CompanyRegistry()
    slug = reg.create("Acme Corp")
    assert slug == "acme_corp"
    assert reg.get(slug)["name"] == "Acme Corp"
    assert reg.display_name(slug) == "Acme Corp"


def test_registry_create_is_idempotent_and_refreshes_name():
    reg = CompanyRegistry()
    s1 = reg.create("Acme")
    created = reg.get(s1)["created_at"]
    s2 = reg.create("ACME")                          # same slug, new casing
    assert s1 == s2
    assert reg.get(s1)["name"] == "ACME"             # display refreshed
    assert reg.get(s1)["created_at"] == created      # creation time preserved
    assert len(reg.list()) == 1


def test_registry_empty_name_raises():
    with pytest.raises(ValueError):
        CompanyRegistry().create("   ")


def test_registry_rename_and_delete():
    reg = CompanyRegistry()
    slug = reg.create("Old")
    reg.rename(slug, "New")
    assert reg.display_name(slug) == "New"
    reg.delete(slug)
    assert reg.get(slug) is None


def test_display_name_falls_back_to_slug_and_unassigned():
    reg = CompanyRegistry()
    assert reg.display_name("ghost") == "ghost"      # not registered → slug
    assert reg.display_name(UNASSIGNED) == UNASSIGNED_LABEL
    assert reg.display_name("") == UNASSIGNED_LABEL


def test_registry_missing_file_is_empty():
    assert CompanyRegistry().list() == []            # no file yet → no crash


# ── Project membership (RMW, composes with other metadata keys) ─────────────

def test_project_set_get_company(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create("https://acme.com")
    assert p.get_company() is None                   # absent → unassigned
    p.set_company("acme_corp")
    assert store.get(p.slug).get_company() == "acme_corp"


def test_set_company_preserves_other_metadata(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create("https://acme.com")
    p.set_monitor({"interval": 3600})
    p.set_company("acme_corp")
    meta = p.load_metadata()
    assert meta["company"] == "acme_corp"
    assert meta["monitor"] == {"interval": 3600}     # not clobbered
    assert meta["url"] == "https://acme.com"


def test_set_company_clear(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create("https://acme.com")
    p.set_company("acme_corp")
    p.set_company(None)
    assert p.get_company() is None
    assert "company" not in p.load_metadata()


def test_assign_via_store(tmp_path):
    store = ProjectStore(tmp_path)
    store.get_or_create("https://acme.com")
    assert store.assign("acme.com", "acme_corp") is True
    assert store.get("acme.com").get_company() == "acme_corp"
    assert store.assign("ghost.com", "x") is False   # unknown project


# ── group_projects (derive-on-read) ─────────────────────────────────────────

def test_group_projects_buckets_and_unassigned_last():
    reg = CompanyRegistry()
    reg.create("Acme Corp")                          # slug acme_corp
    metas = [
        {"slug": "acme.com",    "company": "acme_corp", "updated_at": "2026-06-01"},
        {"slug": "api.acme.io", "company": "acme_corp", "updated_at": "2026-06-10"},
        {"slug": "lonely.net",                          "updated_at": "2026-06-05"},
    ]
    groups = group_projects(metas, reg)
    assert [g["slug"] for g in groups] == ["acme_corp", UNASSIGNED]
    acme = groups[0]
    assert acme["name"] == "Acme Corp"
    assert acme["project_count"] == 2
    assert set(acme["project_slugs"]) == {"acme.com", "api.acme.io"}
    assert acme["updated_at"] == "2026-06-10"         # newest of its projects
    assert groups[1]["name"] == UNASSIGNED_LABEL


def test_group_projects_orphan_company_uses_slug():
    # Project references a company with no registry entry → slug as name.
    groups = group_projects([{"slug": "x.com", "company": "ghostco"}])
    assert groups[0]["slug"] == "ghostco"
    assert groups[0]["name"] == "ghostco"


def test_store_companies_end_to_end(tmp_path):
    store = ProjectStore(tmp_path)
    store.get_or_create("https://acme.com").set_company("acme_corp")
    store.get_or_create("https://other.com")          # unassigned
    CompanyRegistry().create("Acme Corp")
    groups = store.companies()
    by_slug = {g["slug"]: g for g in groups}
    assert by_slug["acme_corp"]["name"] == "Acme Corp"
    assert by_slug["acme_corp"]["project_count"] == 1
    assert UNASSIGNED in by_slug
