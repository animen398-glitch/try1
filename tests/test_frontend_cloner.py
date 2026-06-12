"""FrontendCloner — asset download, CSS/HTML rewriting, circular-import safety.

All network is stubbed via a fake ``_session.fetch_bytes`` so the tests are
offline and deterministic.
"""

from core.frontend_cloner import FrontendCloner


def _make_cloner(tmp_path, pages):
    """Build a cloner whose session serves ``pages`` (url -> bytes)."""
    cloner = FrontendCloner()
    cloner.configure(source_dir=str(tmp_path), output_dir=str(tmp_path))
    cloner._session.fetch_bytes = lambda url: pages.get(url)
    return cloner


def test_circular_css_import_terminates(tmp_path):
    pages = {
        "http://x/a.css": b'@import "b.css";',
        "http://x/b.css": b'@import "a.css";',
    }
    cloner = _make_cloner(tmp_path, pages)

    # Before the fix this recursed until RecursionError.
    rel = cloner._download("http://x/a.css", "http://x/")

    assert rel.startswith("assets/css/")
    assert "http://x/a.css" in cloner._cache
    assert "http://x/b.css" in cloner._cache


def test_css_url_rewritten_to_relative_asset(tmp_path):
    pages = {
        "http://x/s.css": b".a{background:url(pic.png)}",
        "http://x/pic.png": b"PNGDATA",
    }
    cloner = _make_cloner(tmp_path, pages)
    rel = cloner._download("http://x/s.css", "http://x/")

    written = (tmp_path / rel).read_text(encoding="utf-8")
    # From assets/css/ the image is one level up, in assets/img/.
    assert "../img/pic_" in written
    assert "http://x/pic.png" in cloner._cache


def test_html_assets_localised_and_links_preserved(tmp_path):
    pages = {"http://x/app.js": b"console.log(1)"}
    cloner = _make_cloner(tmp_path, pages)

    html = ('<script src="app.js"></script>'
            '<a href="other.html">next</a>')
    out = cloner._process_html(html, "http://x/")

    assert 'src="assets/js/app_' in out      # asset rewritten
    assert 'href="other.html"' in out        # page link untouched


def test_failed_asset_recorded_and_reference_left_alone(tmp_path):
    pages = {}  # every fetch returns None
    cloner = _make_cloner(tmp_path, pages)

    out = cloner._process_html('<img src="gone.png">', "http://x/")
    assert 'src="gone.png"' in out
    assert "http://x/gone.png" in cloner._failed


def test_data_uri_and_anchor_skipped(tmp_path):
    cloner = _make_cloner(tmp_path, {})
    assert cloner._download("data:image/png;base64,AAAA", "http://x/") is None
    assert cloner._download("#section", "http://x/") is None
