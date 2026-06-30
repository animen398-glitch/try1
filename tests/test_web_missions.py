"""Web console Missions read parity (remote/web_app.py, Mission Center M3)."""

import pytest

import remote.web_app as wa
from core import pentest_mission as pm
from core.mission_store import MissionStore


def _save_mission(project="shop.com", objective="Authorized external review"):
    mission = pm.create_mission(project, objective,
                               allowed_actions=["headers_check"])
    return MissionStore().save_mission(mission)


def test_missions_list_helper():
    saved = _save_mission("shop.com")
    out = wa._missions_list("shop.com")
    assert "error" not in out
    assert {m["mission_id"] for m in out["missions"]} == {saved["id"]}
    assert out["missions"][0]["objective"] == "Authorized external review"


def test_mission_view_returns_canonical_payload():
    saved = _save_mission("shop.com")
    out = wa._mission_view(saved["id"])
    assert "error" not in out
    assert out["mission"]["mission_id"] == saved["id"]
    assert out["mission"]["profile"] == "client_safe"


def test_mission_view_unknown_is_not_found():
    out = wa._mission_view("nope")
    assert "not found" in out.get("error", "")


def test_mission_schedule_helper_enable_disable():
    saved = _ready_mission()
    out = wa._mission_set_schedule(saved["id"], "daily", True)
    assert "error" not in out and out["schedule"]["interval"] == "daily"
    off = wa._mission_set_schedule(saved["id"], "daily", False)
    assert off["schedule"]["enabled"] is False


def test_mission_schedule_helper_unknown_is_not_found():
    out = wa._mission_set_schedule("nope", "daily", True)
    assert "not found" in out.get("error", "")


def test_missions_run_due_helper():
    saved = _ready_mission()
    from core.mission_schedule import set_mission_schedule
    from core.mission_store import MissionStore
    set_mission_schedule(saved["id"], "daily")
    MissionStore().set_schedule(
        saved["id"], {**MissionStore().get_schedule(saved["id"]),
                      "next_run": "2020-01-01T00:00:00"})
    out = wa._missions_run_due()
    assert "error" not in out
    assert [r["mission_id"] for r in out["results"]] == [saved["id"]]


def test_missions_overview_helper_counts_by_status():
    _ready_mission("a.io", "one")
    _ready_mission("b.io", "two")
    out = wa._missions_overview()
    assert "error" not in out
    assert out["total"] == 2
    assert out["counts"]["ready"] == 2


def test_missions_csv_helper():
    saved = _ready_mission("shop.com", "review")
    csv_text = wa._missions_csv("shop.com")
    assert csv_text.splitlines()[0].startswith("Mission ID,Project")
    assert saved["id"] in csv_text


def test_mission_create_helper_persists_and_validates():
    out = wa._mission_create("newshop.io", "Authorized review",
                            allowed_actions=["headers_check"])
    assert "error" not in out and out["mission_id"]
    assert len(MissionStore().list_missions("newshop.io")) == 1

    bad = wa._mission_create("shop.com", "Bad", allowed_actions=["exploit"])
    assert "error" in bad
    assert MissionStore().list_missions("shop.com") == []


def _ready_mission(project="shop.com", objective="Authorized external review"):
    mission = pm.create_mission(project, objective,
                               allowed_actions=["headers_check"])
    mission = pm.advance_mission_status(mission, "ready")
    return MissionStore().save_mission(mission)


def _scoped_mission(project="shop.io", objective="External review"):
    """A mission whose ROE puts the project host in scope, so a passive tool
    (header_audit) is allowed against it."""
    mission = pm.create_mission(
        project, objective,
        roe={"allowed_domains": [project], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["headers_check"])
    return MissionStore().save_mission(mission)


def test_mission_run_tool_helper_completed_ingests():
    from core.findings_store import FindingsStore
    saved = _scoped_mission()
    out = wa._mission_run_tool(
        saved["id"], "header_audit", {"url": "https://shop.io/app", "headers": {}})
    assert "error" not in out
    assert out["status"] == "completed" and out["written"] is True
    assert out["findings"] >= 1
    assert FindingsStore().list_findings("shop.io")        # ingested into the store


def test_mission_run_tool_helper_blocked_not_ingested():
    from core.findings_store import FindingsStore
    mission = pm.create_mission(
        "shop.io", "Passive review",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": False,
             "passive_only": True},
        allowed_actions=["headers_check"])
    saved = MissionStore().save_mission(mission)
    # an active tool under a passive-only ROE is blocked → nothing ingested
    out = wa._mission_run_tool(
        saved["id"], "graphql_introspector", {"url": "https://shop.io"})
    assert "error" not in out
    assert out["status"] == "blocked" and out["written"] is False
    assert FindingsStore().list_findings("shop.io") == []


def test_mission_run_tool_helper_unknown_is_not_found():
    out = wa._mission_run_tool("nope", "header_audit", {})
    assert "not found" in out.get("error", "")


def test_mission_run_tool_helper_requires_tool():
    saved = _scoped_mission()
    out = wa._mission_run_tool(saved["id"], "", {})
    assert "tool is required" in out.get("error", "")


def test_mission_run_tool_from_scan_pulls_evidence(tmp_path, monkeypatch):
    # from_scan resolves evidence from the mission's project scan under _REPORT_BASE
    import json as _json

    from core.project import ProjectStore
    monkeypatch.setattr(wa, "_REPORT_BASE", tmp_path)
    proj = ProjectStore(str(tmp_path)).get_or_create("https://shop.io")
    sid = "20260101_000000"
    d = proj.start_scan(sid)
    report = {"url": "https://shop.io", "finished_at": sid,
              "phases": {"subdomains": {"data": {
                  "results": [{"subdomain": "a.shop.io"}]}}}}
    (d / "report.json").write_text(_json.dumps(report), encoding="utf-8")
    proj.record_scan(d, report)

    mission = pm.create_mission(
        "shop.io", "review",
        roe={"allowed_domains": ["shop.io"], "active_scan_enabled": True,
             "passive_only": False, "authorized_by": "client"},
        allowed_actions=["safe_active_probe"])
    saved = MissionStore().save_mission(mission)

    out = wa._mission_run_tool(saved["id"], "safe_active_prober", from_scan=True)
    assert "error" not in out
    assert out["status"] == "completed" and out["assets"] >= 1


def test_mission_run_helper_executes_ready_mission():
    saved = _ready_mission()
    out = wa._mission_run(saved["id"])
    assert "error" not in out
    assert out["status"] == "completed" and out["run_id"]
    assert MissionStore().get_mission(saved["id"])["status"] == "completed"


def test_mission_run_helper_rejects_non_ready():
    mission = pm.create_mission("shop.com", "Draft",
                               allowed_actions=["headers_check"])
    saved = MissionStore().save_mission(mission)            # draft
    out = wa._mission_run(saved["id"])
    assert "ready" in out.get("error", "")


def test_mission_run_helper_unknown_is_not_found():
    out = wa._mission_run("nope")
    assert "not found" in out.get("error", "")


def test_mission_prune_links_helper():
    saved = _save_mission("shop.com")
    linked = pm.link_audit_run(pm.link_finding(saved["payload"], "gone-finding"),
                              "gone-run")
    MissionStore().save_mission(linked)
    out = wa._mission_prune_links(saved["id"])
    assert "error" not in out
    assert out["removed_runs"] == ["gone-run"]
    assert out["removed_findings"] == ["gone-finding"]
    payload = MissionStore().get_mission(saved["id"])["payload"]
    assert payload["linked_finding_ids"] == []


def test_mission_prune_links_unknown_is_not_found():
    out = wa._mission_prune_links("nope")
    assert "not found" in out.get("error", "")


def test_mission_runs_trend_helper():
    saved = _ready_mission()
    out = wa._mission_run(saved["id"])                     # execute → linked run
    runs = wa._mission_runs(saved["id"])
    assert "error" not in runs
    assert [r["run_id"] for r in runs["runs"]] == [out["run_id"]]


def test_mission_runs_helper_unknown_is_not_found():
    out = wa._mission_runs("nope")
    assert "not found" in out.get("error", "")


def test_mission_report_helper_aggregates_run():
    saved = _ready_mission()
    wa._mission_run(saved["id"])                            # execute → links a run
    out = wa._mission_report(saved["id"])
    assert "error" not in out
    assert out["report"]["mission"]["mission_id"] == saved["id"]
    assert out["report"]["summary"]["linked_runs"] == 1


def test_mission_report_helper_unknown_is_not_found():
    out = wa._mission_report("nope")
    assert "not found" in out.get("error", "")


def test_mission_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    saved = _save_mission("shop.com")
    client = TestClient(wa.app)

    r = client.get("/missions", params={"project": "shop.com"})
    assert r.status_code == 200
    assert {m["mission_id"] for m in r.json()["missions"]} == {saved["id"]}

    # creation endpoint: valid → 200, non-client-safe action → 400
    r = client.post("/missions", json={"project": "web.io",
                                       "objective": "Authorized review",
                                       "allowed_actions": ["headers_check"]})
    assert r.status_code == 200 and r.json()["mission_id"]
    r = client.post("/missions", json={"project": "web.io",
                                       "objective": "Bad",
                                       "allowed_actions": ["exploit"]})
    assert r.status_code == 400

    r = client.get(f"/missions/{saved['id']}")
    assert r.status_code == 200 and r.json()["mission"]["mission_id"] == saved["id"]

    r = client.get("/missions/missing")
    assert r.status_code == 404

    # execution endpoint: draft mission → 400, ready mission → 200 completed
    r = client.post(f"/missions/{saved['id']}/run")
    assert r.status_code == 400 and "ready" in r.json()["error"]

    ready = _ready_mission("bank.example", "Portal review")
    r = client.post(f"/missions/{ready['id']}/run")
    assert r.status_code == 200 and r.json()["status"] == "completed"

    r = client.post("/missions/missing/run")
    assert r.status_code == 404

    # tool-run endpoint: completed for a scoped mission, 404 for unknown
    scoped = _scoped_mission("toolshop.io", "tool review")
    r = client.post(f"/missions/{scoped['id']}/tools/run",
                    json={"tool": "header_audit",
                          "evidence": {"url": "https://toolshop.io", "headers": {}}})
    assert r.status_code == 200
    assert r.json()["status"] == "completed" and r.json()["written"] is True
    r = client.post("/missions/missing/tools/run", json={"tool": "header_audit"})
    assert r.status_code == 404

    # report surfaces: JSON + markdown for the executed mission
    r = client.get(f"/missions/{ready['id']}/report")
    assert r.status_code == 200
    assert r.json()["report"]["mission"]["mission_id"] == ready["id"]

    # run-history trend endpoint
    r = client.get(f"/missions/{ready['id']}/runs")
    assert r.status_code == 200 and "runs" in r.json()
    r = client.get("/missions/missing/runs")
    assert r.status_code == 404

    r = client.get(f"/missions/{ready['id']}/report.md")
    assert r.status_code == 200
    assert r.text.startswith(f"# Mission Report {ready['id']}")

    r = client.get("/missions/missing/report")
    assert r.status_code == 404

    # overview endpoint (literal route resolves before /missions/{id})
    r = client.get("/missions/overview")
    assert r.status_code == 200
    assert "total" in r.json() and "counts" in r.json()

    # CSV export endpoint
    r = client.get("/missions.csv", params={"project": "shop.com"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("Mission ID,Project")

    # schedule + run-due endpoints
    r = client.post(f"/missions/{ready['id']}/schedule",
                    json={"interval": "daily", "enabled": True})
    assert r.status_code == 200 and r.json()["schedule"]["interval"] == "daily"
    r = client.post("/missions/nope/schedule", json={"interval": "daily"})
    assert r.status_code == 404
    r = client.post("/missions/run-due")
    assert r.status_code == 200 and "results" in r.json()

    # prune stale links
    staled = _save_mission("web.io", "stale review")
    MissionStore().save_mission(pm.link_audit_run(staled["payload"], "gone-run"))
    r = client.post(f"/missions/{staled['id']}/links/prune")
    assert r.status_code == 200 and r.json()["removed_runs"] == ["gone-run"]
    r = client.post("/missions/nope/links/prune")
    assert r.status_code == 404
