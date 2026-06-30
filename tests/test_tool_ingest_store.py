"""core/tool_ingest_store.py — gated, idempotent ingestion of a tool run.

Persists a completed ToolRunResult's findings/assets into FindingsStore /
AssetStore via the bridge. Gated on status (blocked/skipped never write) and
idempotent by identity. Explicit db paths keep it off the global stores.
"""

import pytest

from core import pentest_mission as pm
from core.asset_store import AssetStore
from core.findings_store import FindingsStore
from core.tool_adapter import ToolRunResult
from core.tool_ingest_store import ingest_tool_run
from core.tool_pipeline import assemble_tool_run


def _mission():
    return pm.create_mission(
        "shop.io", "External review",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check", "safe_active_probe"])


def _completed_result():
    # a header finding + a domain asset
    return assemble_tool_run(
        _mission(), "header_audit", {"url": "https://shop.io/app", "headers": {}})


def _stores(tmp_path):
    return (FindingsStore(db_path=tmp_path / "f.db"),
            AssetStore(db_path=tmp_path / "a.db"))


def test_ingest_completed_persists_findings_and_assets(tmp_path):
    fs, as_ = _stores(tmp_path)
    out = ingest_tool_run(_completed_result(), "shop.io", "s1",
                          findings_store=fs, asset_store=as_)
    assert out["written"] is True and out["status"] == "completed"
    assert out["findings"] == 1 and out["assets"] == 1
    rows = fs.list_findings("shop.io")
    assert any("Strict-Transport-Security" in r["title"] for r in rows)
    assert any(a["value"] == "shop.io" for a in as_.list_assets("shop.io"))


def test_ingest_is_idempotent(tmp_path):
    fs, as_ = _stores(tmp_path)
    result = _completed_result()
    ingest_tool_run(result, "shop.io", "s1", findings_store=fs, asset_store=as_)
    ingest_tool_run(result, "shop.io", "s1", findings_store=fs, asset_store=as_)
    # re-ingesting the same result does not duplicate
    assert len(fs.list_findings("shop.io")) == 1
    assert len(as_.list_assets("shop.io")) == 1


def test_blocked_result_writes_nothing(tmp_path):
    fs, as_ = _stores(tmp_path)
    passive = pm.create_mission(
        "shop.io", "Passive",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": False,
             "passive_only": True},
        allowed_actions=["headers_check"])
    blocked = assemble_tool_run(
        passive, "header_audit", {"url": "https://shop.io", "headers": {}})
    assert blocked.status == "blocked"

    out = ingest_tool_run(blocked, "shop.io", "s1",
                          findings_store=fs, asset_store=as_)
    assert out["written"] is False and out["status"] == "blocked"
    assert fs.list_findings("shop.io") == []
    assert as_.list_assets("shop.io") == []


def test_skipped_result_writes_nothing(tmp_path):
    fs, as_ = _stores(tmp_path)
    from core.tool_adapter import ToolCapability
    custom = ToolCapability("custom_probe", "safe_active_probe", passive=False)
    skipped = assemble_tool_run(_mission(), custom, {}, target="https://shop.io")
    assert skipped.status == "skipped"

    out = ingest_tool_run(skipped, "shop.io", "s1",
                          findings_store=fs, asset_store=as_)
    assert out["written"] is False
    assert fs.list_findings("shop.io") == [] and as_.list_assets("shop.io") == []


def test_guards(tmp_path):
    fs, as_ = _stores(tmp_path)
    with pytest.raises(TypeError):
        ingest_tool_run({"not": "a result"}, "shop.io", "s1",
                        findings_store=fs, asset_store=as_)
    empty = ToolRunResult(tool="header_audit", action="headers_check",
                          mission_id="m1", target="https://shop.io",
                          status="completed")
    with pytest.raises(ValueError, match="project is required"):
        ingest_tool_run(empty, "", "s1", findings_store=fs, asset_store=as_)
