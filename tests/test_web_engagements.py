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


def test_retest_run_helpers():
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore
    saved = _save("Acme", "shop.io")
    fid = FindingsStore().upsert("shop.io", Finding(
        category="vuln", rule_id="r", title="t", severity="high",
        location="https://shop.io/a").to_store(), scan_id="s1")["finding"]["id"]
    wa._engagement_link(saved["id"], "finding", fid)
    run = wa._engagement_retest_run(saved["id"])
    assert "error" not in run and run["status"] == "completed"
    rid = run["retest_run_id"]
    lst = wa._engagement_retest_runs(saved["id"])
    assert [r["retest_run_id"] for r in lst["retest_runs"]] == [rid]
    view = wa._retest_run_view(rid)
    assert view["retest_run"]["retest_run_id"] == rid
    assert view["retest_run"]["summary"]["total"] == 1
    assert "not found" in wa._engagement_retest_run("nope").get("error", "")
    assert "not found" in wa._retest_run_view("rt-nope").get("error", "")


def test_create_mission_under_engagement_helper():
    saved = _save("Acme", "shop.io")
    out = wa._engagement_create_mission(saved["id"], "External review",
                                        ["headers_check"])
    assert "error" not in out and out["mission_id"]
    from core.engagement_store import EngagementStore
    linked = EngagementStore().get_engagement(saved["id"])["payload"]
    assert out["mission_id"] in linked["linked_mission_ids"]
    assert "not found" in wa._engagement_create_mission("nope", "x").get("error", "")
    assert "invalid" in wa._engagement_create_mission(
        saved["id"], "y", ["exploit"]).get("error", "")


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

    # create a mission under the engagement (ROE inherited) → linked
    r = client.post(f"/engagements/{eid}/missions",
                    json={"objective": "Spin-up review",
                          "allowed_actions": ["headers_check"]})
    assert r.status_code == 200 and r.json()["mission_id"]
    assert client.post("/engagements/missing/missions",
                       json={"objective": "x"}).status_code == 404

    # persisted retest run: POST run → list → view → report.md
    r = client.post(f"/engagements/{eid}/retest/run")
    assert r.status_code == 200 and r.json()["status"] == "completed"
    rid = r.json()["retest_run_id"]
    assert client.post("/engagements/missing/retest/run").status_code == 404
    r = client.get(f"/engagements/{eid}/retest-runs")
    assert r.status_code == 200
    assert rid in {x["retest_run_id"] for x in r.json()["retest_runs"]}
    r = client.get(f"/retest-runs/{rid}")
    assert r.status_code == 200 and r.json()["retest_run"]["retest_run_id"] == rid
    assert client.get("/retest-runs/rt-nope").status_code == 404
    r = client.get(f"/retest-runs/{rid}/report.md")
    assert r.status_code == 200 and r.text.startswith("# Retest Run ")
