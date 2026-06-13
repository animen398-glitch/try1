"""Tests for the web console job registry and (optionally) its HTTP endpoints."""

import threading

import pytest

import remote.web_app as wa


def test_job_registry_covers_gui_features():
    expected = {"recon", "subdomain", "apikeys", "capture",
                "paywall", "cookies", "images", "design", "collection",
                "scandiff"}
    assert expected.issubset(set(wa.JOBS))
    for spec in wa.JOBS.values():
        assert spec["label"] and callable(spec["fn"])


def test_scandiff_job_needs_existing_project(monkeypatch, tmp_path):
    # No project on disk → the job reports cleanly instead of failing.
    monkeypatch.setattr(wa.Path, "home", staticmethod(lambda: tmp_path))
    msgs = []
    out = wa._run_scandiff("https://nope.example.com", msgs.append)
    assert out["status"] == "No project"


def test_scandiff_job_needs_two_scans(monkeypatch, tmp_path):
    from core.project import ProjectStore
    monkeypatch.setattr(wa.Path, "home", staticmethod(lambda: tmp_path))
    # One scan only → not enough to diff.
    p = ProjectStore(tmp_path / "SiteAnalyzer").get_or_create("https://x.com")
    p.record_scan(p.start_scan("20260613_010000"),
                  {"url": "https://x.com", "status": "Success",
                   "executive_summary": {"risk_level": "Low"}})
    out = wa._run_scandiff("https://x.com", lambda m: None)
    assert out["status"] == "Need >=2 scans" and out["scans"] == 1


def test_scandiff_job_diffs_last_two_scans(monkeypatch, tmp_path):
    import json

    from core.project import ProjectStore
    monkeypatch.setattr(wa.Path, "home", staticmethod(lambda: tmp_path))
    store = ProjectStore(tmp_path / "SiteAnalyzer")
    p = store.get_or_create("https://x.com")
    for sid, lvl in (("20260613_010000", "Low"), ("20260613_020000", "High")):
        sd = p.start_scan(sid)
        report = {"url": "https://x.com", "status": "Success", "scan_id": sid,
                  "phases": {"capture": {"status": "Success", "data": {
                      "site_map": [{"url": f"/{sid}", "status": 200}]}}},
                  "executive_summary": {"risk_level": lvl, "risk_100": 4,
                                        "metrics": {"risk_100": 4}}}
        (sd / "report.json").write_text(json.dumps(report), encoding="utf-8")
        p.record_scan(sd, report)
    out = wa._run_scandiff("https://x.com", lambda m: None)
    assert out["status"] == "Success"
    assert out["report_html"].endswith(".html")
    assert "Страницы" in out["line"]


def test_safe_report_path_allows_html_inside_base(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, "_REPORT_BASE", tmp_path.resolve())
    report = tmp_path / "proj" / "report.html"
    report.parent.mkdir(parents=True)
    report.write_text("<html></html>", encoding="utf-8")
    assert wa._safe_report_path(str(report)) == report.resolve()
    # relative-to-base form also works
    assert wa._safe_report_path("proj/report.html") == report.resolve()


def test_safe_report_path_blocks_traversal(tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    monkeypatch.setattr(wa, "_REPORT_BASE", base.resolve())
    secret = tmp_path / "secret.html"
    secret.write_text("<html>secret</html>", encoding="utf-8")
    assert wa._safe_report_path(str(secret)) is None          # outside base
    assert wa._safe_report_path("../secret.html") is None       # traversal
    assert wa._safe_report_path("") is None


def test_safe_report_path_rejects_non_html(tmp_path, monkeypatch):
    monkeypatch.setattr(wa, "_REPORT_BASE", tmp_path.resolve())
    j = tmp_path / "report.json"
    j.write_text("{}", encoding="utf-8")
    assert wa._safe_report_path(str(j)) is None
    assert wa._safe_report_path(str(tmp_path / "missing.html")) is None


def test_recent_history_returns_list():
    assert isinstance(wa._recent_history(5), list)


def test_registry_data_returns_summary_and_records():
    d = wa._registry_data(5)
    assert isinstance(d, dict)
    assert "summary" in d and "records" in d
    assert isinstance(d["records"], list)


def test_strip_heavy_drops_large_payloads():
    out = wa._strip_heavy({"html": "x" * 50, "reader_view": "y", "body": "z",
                           "status": "Success", "n": 3})
    assert "html" not in out and "reader_view" not in out and "body" not in out
    assert out["status"] == "Success" and out["n"] == 3
    assert out["html_size"] == 50


def test_strip_heavy_non_dict():
    assert wa._strip_heavy(["a", "b"]) == {"result": ["a", "b"]}


def test_out_dir_naming():
    p = wa._out_dir("https://www.example.com/path", "capture")
    assert p.name.endswith("_capture")
    assert "example.com" in p.name


def test_get_local_ip_returns_str():
    assert isinstance(wa.get_local_ip(), str)


def test_dashboard_is_registry_driven():
    html = wa._DASHBOARD
    assert "/jobs" in html and "loadJobs()" in html and "/run/" in html
    # The old hard-coded per-job endpoints are gone.
    assert "go('/scan'" not in html


def test_dashboard_has_history_and_report():
    html = wa._DASHBOARD
    assert "showHistory()" in html and "/history" in html
    assert "/report?file=" in html
    assert "showData()" in html and "/data" in html


# ── Cancellation (P-backlog: stop a running web-console job) ─────────────────

class _FakeCancellable:
    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


def _reset_cancel_state():
    wa._active_job = None
    wa._active_cancellable = None


def test_request_cancel_no_job_running():
    _reset_cancel_state()
    assert wa._request_cancel() == {"error": "no job running"}


def test_request_cancel_job_not_cancellable():
    _reset_cancel_state()
    wa._active_job = "recon"          # registered nothing cancellable
    out = wa._request_cancel()
    assert "not cancellable" in out["error"]
    _reset_cancel_state()


def test_request_cancel_signals_registered_engine():
    _reset_cancel_state()
    wa._active_job = "collection"
    engine = _FakeCancellable()
    wa._register_cancellable(engine)
    out = wa._request_cancel()
    assert out == {"status": "cancelling", "job": "collection"}
    assert engine.cancelled is True
    _reset_cancel_state()


def test_event_canceller_sets_the_event():
    ev = threading.Event()
    wa._EventCanceller(ev).cancel()
    assert ev.is_set()


def test_dashboard_exposes_cancel_control():
    html = wa._DASHBOARD
    assert "cancelJob()" in html and "/cancel" in html
    assert 'id="b-cancel"' in html


# ── Continuous Monitoring surface (#8) ───────────────────────────────────────

def test_monitor_event_text_formats_kinds():
    assert 'scan start' in wa._monitor_event_text(
        {'type': 'scan_start', 'slug': 'x.com'})
    assert 'first scan' in wa._monitor_event_text(
        {'type': 'scan_done', 'slug': 'x.com', 'scan_id': '1'})
    done = wa._monitor_event_text(
        {'type': 'scan_done', 'slug': 'x.com', 'scan_id': '2', 'diff_line': 'd'})
    assert 'd' in done and 'first scan' not in done
    assert 'error' in wa._monitor_event_text(
        {'type': 'error', 'slug': 'x.com', 'error': 'boom'})


def test_dashboard_exposes_monitor_controls():
    html = wa._DASHBOARD
    for token in ("monEnable()", "monDisable()", "monStatus()", "monRun()",
                  "/monitor/enable", "/monitor/disable", "/monitor",
                  'id="mon-interval"'):
        assert token in html, token


def test_monitor_endpoints_with_testclient(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    # Point the monitor store at a tmp home so the test is isolated.
    monkeypatch.setattr(wa.Path, "home", staticmethod(lambda: tmp_path))
    client = TestClient(wa.app)

    # Empty to start.
    assert client.get("/monitor").json() == []

    # Enable with a bad interval -> 400.
    r = client.post("/monitor/enable",
                    json={"url": "https://x.com", "interval": "hourly"})
    assert r.status_code == 400

    # Enable properly.
    r = client.post("/monitor/enable",
                    json={"url": "https://x.com", "interval": "daily"})
    assert r.status_code == 200 and r.json()["slug"] == "x.com"

    rows = client.get("/monitor").json()
    assert [m["slug"] for m in rows] == ["x.com"] and rows[0]["enabled"] is True

    # Disable.
    r = client.post("/monitor/disable", json={"url": "https://x.com"})
    assert r.status_code == 200 and r.json()["disabled"] is True
    assert client.get("/monitor").json()[0]["enabled"] is False

    # Disable unknown -> 404.
    r = client.post("/monitor/disable", json={"url": "https://nope.com"})
    assert r.status_code == 404


# ── Alert Center surface (#9) ────────────────────────────────────────────────

def test_alerts_overview_reports_channels_without_tokens(monkeypatch):
    monkeypatch.setattr(wa, "load_settings", lambda: {"alerts": {
        "enabled": True, "discord": {"webhook_url": "https://d"},
        "telegram": {"token": "t"}}})   # telegram incomplete -> not a channel
    ov = wa._alerts_overview()
    assert ov["enabled"] is True
    assert ov["channels"] == ["discord"]
    assert "new_secret" in ov["types"]
    # no token value leaks into the overview
    assert "https://d" not in str(ov["channels"])


def test_dashboard_exposes_alert_controls():
    html = wa._DASHBOARD
    for token in ("alertStatus()", "alertTest()", "/alerts", "/alerts/test"):
        assert token in html, token


def test_alert_endpoints_with_testclient(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient

    monkeypatch.setattr(wa, "load_settings", lambda: {"alerts": {
        "enabled": True, "discord": {"webhook_url": "https://d"}}})
    monkeypatch.setattr(wa.alerts, "_http_post", lambda *a, **k: 204)
    client = TestClient(wa.app)

    assert client.get("/alerts").json()["channels"] == ["discord"]
    r = client.post("/alerts/test")
    assert r.status_code == 200 and r.json()["sent"] == 1

    # No channels -> 400 with a reason.
    monkeypatch.setattr(wa, "load_settings", lambda: {"alerts": {"enabled": True}})
    r = client.post("/alerts/test")
    assert r.status_code == 400 and "reason" in r.json()


# ── Optional: exercise the live endpoints if a test client is available ──────

def test_endpoints_with_testclient():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    if not wa._FASTAPI_OK:
        pytest.skip("fastapi not importable in web_app")
    from fastapi.testclient import TestClient
    client = TestClient(wa.app)

    r = client.get("/jobs")
    assert r.status_code == 200
    names = {j["name"] for j in r.json()}
    assert {"recon", "subdomain", "cookies", "collection"}.issubset(names)

    r = client.get("/")
    assert r.status_code == 200 and "Advanced Site Analyzer" in r.text

    r = client.post("/run/does-not-exist", json={"url": "https://x"})
    assert r.status_code == 404

    # No job running → /cancel reports cleanly with 409.
    _reset_cancel_state()
    r = client.post("/cancel")
    assert r.status_code == 409 and "no job running" in r.json()["error"]
