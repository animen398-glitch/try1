"""Web console Clone Frontend job (offline)."""

import remote.web_app as wa


def test_clone_job_registered():
    assert "clone" in wa.JOBS
    assert wa.JOBS["clone"]["label"] == "Clone Frontend"
    assert callable(wa.JOBS["clone"]["fn"])


def test_clone_job_captures_then_clones(monkeypatch):
    class _FakeCap:
        def configure(self, *a, **k): pass
        def set_progress_callback(self, cb): pass
        def run_capture(self): return {"pages_captured": 2}

    class _FakeCloner:
        def configure(self, *a, **k): pass
        def set_progress_callback(self, cb): pass
        def clone(self):
            return {"status": "Success", "pages_processed": 2,
                    "assets_downloaded": 5}

    monkeypatch.setattr(wa, "SiteContentCapture", _FakeCap)
    monkeypatch.setattr(wa, "FrontendCloner", _FakeCloner)

    result = wa.JOBS["clone"]["fn"]("https://example.com", lambda m: None)
    assert result["status"] == "Success"
    assert result["pages_processed"] == 2
    assert "output_dir" in result


def test_clone_job_errors_when_nothing_captured(monkeypatch):
    class _FakeCap:
        def configure(self, *a, **k): pass
        def set_progress_callback(self, cb): pass
        def run_capture(self): return {"pages_captured": 0}

    # FrontendCloner must NOT be reached; make it explode if it is.
    class _Boom:
        def __init__(self): raise AssertionError("cloner should not run")

    monkeypatch.setattr(wa, "SiteContentCapture", _FakeCap)
    monkeypatch.setattr(wa, "FrontendCloner", _Boom)

    result = wa.JOBS["clone"]["fn"]("https://example.com", lambda m: None)
    assert result["status"] == "Error"


def test_heavy_stdout_stripped_from_browser_payload():
    # A job's noisy stdout ('output') must not be shipped to the browser.
    out = wa._strip_heavy({"status": "Success", "output": "x" * 9000,
                           "pages_processed": 2})
    assert "output" not in out
    assert out["pages_processed"] == 2
