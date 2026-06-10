"""Cooperative cancellation in the capture and clone engines (network-free)."""

import json

from core.content_capture import SiteContentCapture
from core.frontend_cloner import FrontendCloner


def test_capture_cancel_before_run_stops_immediately(tmp_path):
    cap = SiteContentCapture()
    cap.configure("https://example.com", str(tmp_path / "cap"), max_pages=50)
    cap.cancel()                       # set after configure (configure clears it)
    result = cap.run_capture()         # cancel is checked before any fetch
    assert result.get("cancelled") is True
    assert result["pages_captured"] == 0


def _make_capture_source(d):
    for n in ("a", "b", "c"):
        (d / f"{n}.html").write_text("<html><body>x</body></html>", encoding="utf-8")
    (d / "site_map.json").write_text(
        json.dumps([{"file": f"{n}.html", "url": f"https://ex.com/{n}"}
                    for n in ("a", "b", "c")]),
        encoding="utf-8",
    )


def test_clone_cancel_mid_run(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_capture_source(src)

    cloner = FrontendCloner()
    cloner.configure(str(src), str(tmp_path / "out"))
    # Cancel right after the first page is localised.
    cloner.set_progress_callback(
        lambda msg: cloner.cancel() if msg.startswith("Локализу") else None
    )
    result = cloner.clone()
    assert result.get("cancelled") is True
    assert result["status"] == "Cancelled"
    assert result["pages_processed"] < 3


def test_clone_cancel_before_run(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_capture_source(src)

    cloner = FrontendCloner()
    cloner.configure(str(src), str(tmp_path / "out"))
    cloner.cancel()
    result = cloner.clone()
    assert result.get("cancelled") is True
    assert result["pages_processed"] == 0
