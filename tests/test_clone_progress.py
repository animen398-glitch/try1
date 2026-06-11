"""Structured page-progress from FrontendCloner (network-free).

The cloner now reports progress through set_page_progress_callback(cur, total)
instead of the GUI parsing log strings. Pages without asset references touch no
network, so clone() runs fully offline here.
"""

import json

from core.frontend_cloner import FrontendCloner


def _make_source(d, names, with_urls=True):
    for n in names:
        (d / f"{n}.html").write_text("<html><body>x</body></html>", encoding="utf-8")
    if with_urls:
        (d / "site_map.json").write_text(
            json.dumps([{"file": f"{n}.html", "url": f"https://ex.com/{n}"}
                        for n in names]),
            encoding="utf-8",
        )


def test_page_progress_reaches_total(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_source(src, ("a", "b", "c"))

    events = []
    cloner = FrontendCloner()
    cloner.configure(str(src), str(tmp_path / "out"))
    cloner.set_page_progress_callback(lambda cur, tot: events.append((cur, tot)))
    result = cloner.clone()

    assert result["pages_processed"] == 3
    assert events[0] == (0, 3)          # total announced before work starts
    assert events[-1] == (3, 3)         # bar reaches 100%
    currents = [c for c, _ in events]
    assert currents == sorted(currents)  # monotonically non-decreasing
    assert all(t == 3 for _, t in events)


def test_skipped_pages_still_advance(tmp_path):
    # A file missing from site_map.json is skipped, but progress must not stall.
    src = tmp_path / "src"
    src.mkdir()
    _make_source(src, ("a", "b"), with_urls=False)
    (src / "site_map.json").write_text(
        json.dumps([{"file": "a.html", "url": "https://ex.com/a"}]),
        encoding="utf-8",
    )

    events = []
    cloner = FrontendCloner()
    cloner.configure(str(src), str(tmp_path / "out"))
    cloner.set_page_progress_callback(lambda cur, tot: events.append((cur, tot)))
    cloner.clone()

    assert events[0] == (0, 2)
    assert events[-1] == (2, 2)         # skipped page advanced the counter too


def test_no_callback_is_safe(tmp_path):
    # clone() must not require a page-progress callback to be registered.
    src = tmp_path / "src"
    src.mkdir()
    _make_source(src, ("a",))
    cloner = FrontendCloner()
    cloner.configure(str(src), str(tmp_path / "out"))
    result = cloner.clone()      # no set_page_progress_callback call
    assert result["pages_processed"] == 1
