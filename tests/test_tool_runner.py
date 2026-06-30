"""core/tool_runner.py — end-to-end tool-run orchestrator.

Composes the store-free pipeline (gate → parse → map) with gated, idempotent
ingestion into FindingsStore / AssetStore. Explicit db paths keep it off the
global stores. Pure composition: blocked/skipped flow through, completed
persists once.
"""

from core import pentest_mission as pm
from core.asset_store import AssetStore
from core.findings_store import FindingsStore
from core.tool_adapter import ToolCapability
from core.tool_runner import run_tool_for_mission


def _mission():
    return pm.create_mission(
        "shop.io", "External review",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check", "safe_active_probe"])


def _stores(tmp_path):
    return (FindingsStore(db_path=tmp_path / "f.db"),
            AssetStore(db_path=tmp_path / "a.db"))


def test_run_completed_persists_and_returns_result(tmp_path):
    fs, as_ = _stores(tmp_path)
    out = run_tool_for_mission(
        _mission(), "header_audit", {"url": "https://shop.io/app", "headers": {}},
        scan_id="s1", findings_store=fs, asset_store=as_)

    assert out["result"].status == "completed"
    assert out["ingest"]["written"] is True
    assert out["ingest"]["findings"] == 1 and out["ingest"]["assets"] == 1
    rows = fs.list_findings("shop.io")
    assert any("Strict-Transport-Security" in r["title"] for r in rows)
    assert any(a["value"] == "shop.io" for a in as_.list_assets("shop.io"))


def test_project_defaults_to_mission_project(tmp_path):
    fs, as_ = _stores(tmp_path)
    # no explicit project — taken from the mission's own project
    run_tool_for_mission(
        _mission(), "header_audit", {"url": "https://shop.io", "headers": {}},
        scan_id="s1", findings_store=fs, asset_store=as_)
    assert fs.list_findings("shop.io")  # persisted under the mission's project


def test_run_is_idempotent(tmp_path):
    fs, as_ = _stores(tmp_path)
    args = dict(scan_id="s1", findings_store=fs, asset_store=as_)
    run_tool_for_mission(_mission(), "header_audit",
                         {"url": "https://shop.io", "headers": {}}, **args)
    run_tool_for_mission(_mission(), "header_audit",
                         {"url": "https://shop.io", "headers": {}}, **args)
    assert len(fs.list_findings("shop.io")) == 1
    assert len(as_.list_assets("shop.io")) == 1


def test_blocked_run_persists_nothing(tmp_path):
    fs, as_ = _stores(tmp_path)
    passive = pm.create_mission(
        "shop.io", "Passive",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": False,
             "passive_only": True},
        allowed_actions=["headers_check"])
    out = run_tool_for_mission(
        passive, "header_audit", {"url": "https://shop.io", "headers": {}},
        scan_id="s1", findings_store=fs, asset_store=as_)
    assert out["result"].status == "blocked"
    assert out["ingest"]["written"] is False
    assert fs.list_findings("shop.io") == []
    assert as_.list_assets("shop.io") == []


def test_skipped_run_persists_nothing(tmp_path):
    fs, as_ = _stores(tmp_path)
    custom = ToolCapability("custom_probe", "safe_active_probe", passive=False)
    out = run_tool_for_mission(
        _mission(), custom, {}, scan_id="s1", target="https://shop.io",
        findings_store=fs, asset_store=as_)
    assert out["result"].status == "skipped"
    assert out["ingest"]["written"] is False
    assert fs.list_findings("shop.io") == []
    assert as_.list_assets("shop.io") == []
