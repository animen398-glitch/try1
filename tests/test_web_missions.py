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


def _ready_mission(project="shop.com", objective="Authorized external review"):
    mission = pm.create_mission(project, objective,
                               allowed_actions=["headers_check"])
    mission = pm.advance_mission_status(mission, "ready")
    return MissionStore().save_mission(mission)


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

    # report surfaces: JSON + markdown for the executed mission
    r = client.get(f"/missions/{ready['id']}/report")
    assert r.status_code == 200
    assert r.json()["report"]["mission"]["mission_id"] == ready["id"]

    r = client.get(f"/missions/{ready['id']}/report.md")
    assert r.status_code == 200
    assert r.text.startswith(f"# Mission Report {ready['id']}")

    r = client.get("/missions/missing/report")
    assert r.status_code == 404
