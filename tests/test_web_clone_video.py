"""Web console Clone Frontend and Video Download jobs (offline)."""

import remote.web_app as wa


def test_clone_and_video_jobs_registered():
    for name, label in (("clone", "Clone Frontend"), ("video", "Video Download")):
        assert name in wa.JOBS
        assert wa.JOBS[name]["label"] == label
        assert callable(wa.JOBS[name]["fn"])


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


def test_video_job_forwards_result(monkeypatch):
    class _FakeDL:
        def set_progress_callback(self, cb): pass
        def download_video(self, url, out):
            return {"status": "Success", "file": "v.mp4", "quality": "best"}

    monkeypatch.setattr(wa, "VideoDownloader", _FakeDL)
    result = wa.JOBS["video"]["fn"]("https://youtube.com/watch?v=x", lambda m: None)
    assert result["status"] == "Success"
    assert result["quality"] == "best"
    assert "output_dir" in result


def test_yt_dlp_stdout_stripped_from_browser_payload():
    # The noisy yt-dlp stdout ('output') must not be shipped to the browser.
    out = wa._strip_heavy({"status": "Success", "output": "x" * 9000,
                           "quality": "best"})
    assert "output" not in out
    assert out["quality"] == "best"
