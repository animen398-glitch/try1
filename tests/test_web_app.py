"""Tests for the web console job registry and (optionally) its HTTP endpoints."""

import pytest

import remote.web_app as wa


def test_job_registry_covers_gui_features():
    expected = {"recon", "subdomain", "apikeys", "capture",
                "paywall", "cookies", "images", "design", "collection"}
    assert expected.issubset(set(wa.JOBS))
    for spec in wa.JOBS.values():
        assert spec["label"] and callable(spec["fn"])


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
