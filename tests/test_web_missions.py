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
