"""main_orchestrator CLI — --profile/--delay parity with the GUI.

The recon and capture phases must forward the chosen UA profile and the
inter-page delay (ms -> seconds) to the underlying engines.
"""

import main_orchestrator as mo


def test_phase_recon_forwards_profile(monkeypatch, tmp_path):
    seen = {}

    class _FakeEngine:
        def configure(self, output_dir=None, profile='chrome_windows', **k):
            seen["profile"] = profile

        def run_recon(self, url):
            return {"status": "Success"}

    monkeypatch.setattr(mo, "ReconEngine", _FakeEngine)
    mo.phase_recon("https://x.com", tmp_path, profile="firefox_windows")
    assert seen["profile"] == "firefox_windows"


def test_phase_capture_forwards_profile_and_delay(monkeypatch, tmp_path):
    seen = {}

    class _FakeCap:
        def configure(self, url, out, max_pages=50, profile='chrome_windows',
                      delay=0.5):
            seen.update(profile=profile, delay=delay, max_pages=max_pages)

        def set_progress_callback(self, cb):
            pass

        def run_capture(self):
            return {"pages_captured": 0, "errors": [], "files": []}

    monkeypatch.setattr(mo, "SiteContentCapture", _FakeCap)
    mo.phase_capture("https://x.com", tmp_path, max_pages=7,
                     profile="safari_mac", delay=1.0)
    assert seen == {"profile": "safari_mac", "delay": 1.0, "max_pages": 7}
