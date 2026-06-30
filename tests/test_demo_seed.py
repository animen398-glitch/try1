"""demo_seed.py — the self-contained demo workspace builder (offline).

Seeds into a tmp dir and reads the portfolio back through the SAME stores the
app uses (pointed at that dir), so the test proves both the on-disk layout and
that the seeded content is loadable — without the ASA_DATA_ROOT env override
(``seed()`` uses explicit PathManager-derived paths, so no global state leaks).
"""
import json

import demo_seed
from core.asset_store import AssetStore
from core.audit_store import AuditRunStore
from core.company import CompanyRegistry
from core.findings_store import FindingsStore
from core.iac_scanner import scan_path
from core.paths import PathManager
from core.project import ProjectStore


def _seed(tmp_path):
    root = tmp_path / "demo"
    root.mkdir()
    summary = demo_seed.seed(root)
    return root, summary


# ── summary + layout ───────────────────────────────────────────────────────────

def test_seed_returns_portfolio_summary(tmp_path):
    _, s = _seed(tmp_path)
    assert s["projects"] == 3
    assert s["scans"] == 7
    assert s["findings"] == 17
    assert s["remediation"] == 4
    assert s["audit_runs"] == 3
    assert s["missions"] == 3
    assert s["engagements"] == 1
    assert s["company"] == "Acme Corp"


def test_seed_engagement_present_and_linked(tmp_path):
    root, _ = _seed(tmp_path)
    from core.engagement_store import EngagementStore
    store = EngagementStore(root / "data" / "engagements.db")
    rows = store.list_engagements()
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert payload["status"] == "reporting"
    assert payload["authorization"]["accepted"] is True
    assert payload["linked_mission_ids"] and payload["linked_audit_run_ids"]
    assert payload["linked_finding_ids"]


def test_seed_writes_self_contained_layout(tmp_path):
    root, _ = _seed(tmp_path)
    assert (root / "data" / "findings.db").exists()
    assert (root / "data" / "assets.db").exists()
    assert (root / "data" / "audit_runs.db").exists()
    assert (root / "data" / "companies.json").exists()
    assert (root / "Projects").is_dir()
    assert (root / "demo_iac" / "main.tf").exists()
    settings = json.loads((root / "configs" / "settings.json").read_text("utf-8"))
    # output_dir points back at the workspace so the app reads it verbatim.
    assert settings["output_dir"] == str(root)


# ── content is loadable through the real stores ──────────────────────────────────

def test_projects_assigned_to_company(tmp_path):
    root, _ = _seed(tmp_path)
    store = ProjectStore(str(root))
    slugs = {p["slug"] for p in store.list_projects()}
    assert slugs == {"shop.acme.com", "api.acme.com", "blog.acme.com"}
    assert store.get("shop.acme.com").get_company() == "acme_corp"
    assert CompanyRegistry(path=root / "data" / "companies.json").get("acme_corp")


def test_findings_lifecycle_present(tmp_path):
    root, _ = _seed(tmp_path)
    fs = FindingsStore(db_path=root / "data" / "findings.db")
    rows = fs.list_findings("shop.acme.com")
    assert rows
    # The first scan's HSTS finding is absent from later scans → auto-FIXED.
    fixed = [r for r in rows if r["rule_id"] == "missing-hsts"]
    assert fixed and fixed[0]["status"] == "FIXED"
    # A remediation task was attached to a live finding.
    idor = [r for r in rows if r["rule_id"] == "idor-cart"][0]
    assert fs.get_remediation(idor["id"])["status"] == "in_progress"


def test_assets_and_business_context(tmp_path):
    root, _ = _seed(tmp_path)
    store = ProjectStore(str(root))
    ctx = store.get("shop.acme.com").get_business_context()
    assert ctx["default"] == {"criticality": "critical",
                              "data_sensitivity": "restricted"}
    assets = AssetStore(db_path=root / "data" / "assets.db")
    assert len(assets.list_assets("shop.acme.com")) == 5


def test_missions_seeded_with_schedule_run_and_stale_link(tmp_path):
    from core.mission_links import resolve_links
    from core.mission_store import MissionStore
    root, _ = _seed(tmp_path)
    missions = MissionStore(root / "data" / "missions.db")
    rows = missions.list_missions("shop.acme.com")
    assert len(rows) == 3
    # one mission is scheduled (weekly)
    assert any(isinstance(m.get("schedule"), dict)
               and m["schedule"].get("interval") == "weekly" for m in rows)
    # one executed mission has a linked audit run + finding
    assert any(m["payload"].get("linked_audit_run_ids")
               and m["payload"].get("linked_finding_ids") for m in rows)
    # one mission carries a stale link (M11 surfaces it)
    astore = AuditRunStore(db_path=root / "data" / "audit_runs.db")
    fstore = FindingsStore(db_path=root / "data" / "findings.db")
    assert any(resolve_links(m["payload"], audit_store=astore,
                             findings_store=fstore)["stale_runs"] for m in rows)


def test_audit_runs_and_iac_demo_content(tmp_path):
    root, _ = _seed(tmp_path)

    audits = AuditRunStore(db_path=root / "data" / "audit_runs.db")
    runs = audits.list_runs("api.acme.com")
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["payload"]["findings"]
    assert audits.events(runs[0]["id"])

    iac = scan_path(root / "demo_iac")
    rule_ids = {row["rule_id"] for row in iac["findings"]}
    assert {"iac-tf-open-ingress", "iac-tf-public-bucket", "iac-docker-root"} <= rule_ids


# ── PathManager-derived paths match the override layout ──────────────────────────

def test_seed_paths_match_pathmanager(tmp_path):
    root, _ = _seed(tmp_path)
    pm = PathManager(data_root=root)
    # what the launched app (ASA_DATA_ROOT=root) would resolve == what we wrote.
    assert pm.get_db_path("findings.db").exists()
    assert pm.get_db_path("companies.json").exists()


# ── CLI guardrails ───────────────────────────────────────────────────────────

def test_main_rejects_non_empty_dir_without_force(tmp_path, capsys):
    root = tmp_path / "demo"
    root.mkdir()
    marker = root / "keep.txt"
    marker.write_text("do not wipe", encoding="utf-8")

    rc = demo_seed.main(["--dir", str(root)])

    err = capsys.readouterr().err
    assert rc == 1
    assert "exists and is not empty" in err
    assert marker.read_text("utf-8") == "do not wipe"


def test_main_force_wipes_and_seeds_demo_workspace(tmp_path, capsys):
    root = tmp_path / "demo"
    root.mkdir()
    (root / "old.txt").write_text("old", encoding="utf-8")

    rc = demo_seed.main(["--dir", str(root), "--force"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Demo workspace seeded" in out
    assert not (root / "old.txt").exists()
    assert (root / "Projects").is_dir()
    assert (root / "data" / "findings.db").exists()
