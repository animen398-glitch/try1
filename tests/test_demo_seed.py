"""demo_seed.py — the self-contained demo workspace builder (offline).

Seeds into a tmp dir and reads the portfolio back through the SAME stores the
app uses (pointed at that dir), so the test proves both the on-disk layout and
that the seeded content is loadable — without the ASA_DATA_ROOT env override
(``seed()`` uses explicit PathManager-derived paths, so no global state leaks).
"""
import json

import demo_seed
from core.asset_store import AssetStore
from core.company import CompanyRegistry
from core.findings_store import FindingsStore
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
    assert s["company"] == "Acme Corp"


def test_seed_writes_self_contained_layout(tmp_path):
    root, _ = _seed(tmp_path)
    assert (root / "data" / "findings.db").exists()
    assert (root / "data" / "assets.db").exists()
    assert (root / "data" / "companies.json").exists()
    assert (root / "Projects").is_dir()
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
