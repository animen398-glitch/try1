"""Web console Engagement parity (remote/web_app.py, F-engagement S2).

Pure helpers over EngagementStore + the pure core.engagement contract, plus the
live HTTP endpoints via TestClient. Stores are isolated per test by conftest.
"""

import pytest

import remote.web_app as wa
from core import engagement as eng
from core.engagement_store import EngagementStore


def _save(client="Acme", project="shop.io", **kw):
    return EngagementStore().save_engagement(
        eng.create_engagement(client, project, **kw))


# ── pure helpers ───────────────────────────────────────────────────────────────

def test_list_and_view_helpers():
    saved = _save()
    out = wa._engagements_list("shop.io")
    assert {e["engagement_id"] for e in out["engagements"]} == {saved["id"]}
    view = wa._engagement_view(saved["id"])
    assert view["engagement"]["engagement_id"] == saved["id"]
    assert view["engagement"]["profile"] == "client_safe"


def test_view_unknown_is_not_found():
    assert "not found" in wa._engagement_view("nope").get("error", "")


def test_create_helper_persists_and_rejects_invalid():
    out = wa._engagement_create("Acme", "newshop.io",
                                authorization={"accepted": True})
    assert "error" not in out and out["engagement_id"]
    assert len(EngagementStore().list_engagements("newshop.io")) == 1
    # invalid ROE (active + passive_only, no domains) → 400-shaped error
    bad = wa._engagement_create("Acme", "shop.io",
                                roe={"active_scan_enabled": True,
                                     "passive_only": True})
    assert "error" in bad


def test_advance_helper():
    saved = _save(authorization={"accepted": True})
    out = wa._engagement_advance(saved["id"], "authorized")
    assert out["status"] == "authorized"
    # not-accepted → 400-shaped (advance raises ValueError)
    plain = _save("Beta", "b.io")
    assert "accepted" in wa._engagement_advance(plain["id"], "authorized").get("error", "")
    assert "not found" in wa._engagement_advance("nope", "authorized").get("error", "")


def test_link_helper_checked():
    from core.mission_store import MissionStore
    from core import pentest_mission as pm
    saved = _save()
    mid = MissionStore().save_mission(
        pm.create_mission("shop.io", "m", allowed_actions=["headers_check"]))["id"]
    out = wa._engagement_link(saved["id"], "mission", mid)
    assert out["ref_id"] == mid
    assert "not found" in wa._engagement_link(saved["id"], "mission", "ghost").get("error", "")
    assert "unknown link kind" in wa._engagement_link(saved["id"], "bogus", "x").get("error", "")


def test_report_helper():
    saved = _save(authorization={"accepted": True})
    out = wa._engagement_report(saved["id"])
    assert out["report"]["engagement"]["engagement_id"] == saved["id"]
    assert "not found" in wa._engagement_report("nope").get("error", "")


def test_retest_overview_csv_helpers():
    saved = _save("Acme", "shop.io")
    assert wa._engagement_retest(saved["id"])["retest"]["engagement_id"] == saved["id"]
    assert "not found" in wa._engagement_retest("nope").get("error", "")
    ov = wa._engagements_overview("shop.io")
    assert ov["total"] == 1 and ov["engagements"][0]["client"] == "Acme"
    csv_text = wa._engagements_csv("shop.io")
    assert csv_text.splitlines()[0].startswith("Engagement ID,Client")
    assert saved["id"] in csv_text


# ── live endpoints ───────────────────────────────────────────────────────────--

def test_engagement_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    client = TestClient(wa.app)

    # create (valid) → 200, invalid → 400
    r = client.post("/engagements", json={"client": "Acme", "project": "web.io",
                                          "authorization": {"accepted": True}})
    assert r.status_code == 200
    eid = r.json()["engagement_id"]
    r = client.post("/engagements", json={"client": "", "project": ""})
    assert r.status_code == 400

    r = client.get("/engagements", params={"project": "web.io"})
    assert r.status_code == 200
    assert eid in {e["engagement_id"] for e in r.json()["engagements"]}

    r = client.get(f"/engagements/{eid}")
    assert r.status_code == 200 and r.json()["engagement"]["client"] == "Acme"
    assert client.get("/engagements/missing").status_code == 404

    # advance: accepted authorization → authorized
    r = client.post(f"/engagements/{eid}/advance", json={"status": "authorized"})
    assert r.status_code == 200 and r.json()["status"] == "authorized"
    r = client.post("/engagements/missing/advance", json={"status": "authorized"})
    assert r.status_code == 404

    # link a finding then report
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore
    fid = FindingsStore().upsert("web.io", Finding(
        category="vuln", rule_id="r", title="t", severity="high",
        location="https://web.io/a").to_store(), scan_id="s1")["finding"]["id"]
    r = client.post(f"/engagements/{eid}/link",
                    json={"kind": "finding", "ref_id": fid})
    assert r.status_code == 200
    r = client.post(f"/engagements/{eid}/link",
                    json={"kind": "finding", "ref_id": "ghost"})
    assert r.status_code == 404                       # referenced finding missing
    r = client.post(f"/engagements/{eid}/link",
                    json={"kind": "bogus", "ref_id": "x"})
    assert r.status_code == 400                       # unknown link kind

    r = client.get(f"/engagements/{eid}/report")
    assert r.status_code == 200
    assert r.json()["report"]["summary"]["linked_findings"] == 1
    r = client.get(f"/engagements/{eid}/report.md")
    assert r.status_code == 200 and r.text.startswith("# Engagement Report ")

    # retest + overview + csv endpoints
    r = client.get(f"/engagements/{eid}/retest")
    assert r.status_code == 200 and r.json()["retest"]["summary"]["total"] == 1
    assert client.get("/engagements/missing/retest").status_code == 404
    r = client.get("/engagements/overview")        # literal route before /{id}
    assert r.status_code == 200 and "total" in r.json() and "counts" in r.json()
    r = client.get("/engagements.csv", params={"project": "web.io"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("Engagement ID,Client")
