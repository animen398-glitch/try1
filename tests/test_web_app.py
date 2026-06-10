"""Tests for the web console job registry and (optionally) its HTTP endpoints."""

import pytest

import remote.web_app as wa


def test_job_registry_covers_gui_features():
    expected = {"recon", "subdomain", "apikeys", "capture",
                "paywall", "cookies", "collection"}
    assert expected.issubset(set(wa.JOBS))
    for spec in wa.JOBS.values():
        assert spec["label"] and callable(spec["fn"])


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
