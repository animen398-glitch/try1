"""SiteContentCapture honours a configurable inter-page delay.

Regression: the 'request_delay' setting used to be dead — capture slept a
hardcoded 0.5s. configure(delay=...) now drives that pause (and 0 disables it).
"""

import core.content_capture as cc
from core.content_capture import SiteContentCapture


def _capturer_with_recorded_sleep(monkeypatch, tmp_path, html, delay):
    slept = []
    monkeypatch.setattr(cc.time, "sleep", lambda s: slept.append(s))

    cap = SiteContentCapture()
    cap.configure("https://x.com", str(tmp_path), max_pages=1, delay=delay)
    # One self-page, no outgoing links → exactly one fetch, then the pause.
    cap._fetch = lambda url: html
    cap.run_capture()
    return slept


def test_configured_delay_is_used(monkeypatch, tmp_path):
    slept = _capturer_with_recorded_sleep(
        monkeypatch, tmp_path, "<html>ok</html>", delay=2.5)
    assert slept == [2.5]


def test_zero_delay_skips_sleep(monkeypatch, tmp_path):
    slept = _capturer_with_recorded_sleep(
        monkeypatch, tmp_path, "<html>ok</html>", delay=0)
    assert slept == []


def test_default_delay_is_half_second(tmp_path):
    cap = SiteContentCapture()
    cap.configure("https://x.com", str(tmp_path))
    assert cap._delay == 0.5


def test_negative_delay_clamped_to_zero(tmp_path):
    cap = SiteContentCapture()
    cap.configure("https://x.com", str(tmp_path), delay=-5)
    assert cap._delay == 0.0
