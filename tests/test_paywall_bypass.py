"""Tests for PaywallBypass pure helpers (network-free)."""

from core.paywall_bypass import PaywallBypass


def test_discover_amp_from_link():
    html = '<head><link rel="amphtml" href="/article/amp"></head>'
    assert PaywallBypass._discover_amp(html, "https://site.com/article") \
        == "https://site.com/article/amp"


def test_discover_amp_absolute_href():
    html = '<link href="https://amp.site.com/x" rel="amphtml">'
    assert PaywallBypass._discover_amp(html, "https://site.com/x") \
        == "https://amp.site.com/x"


def test_discover_amp_absent():
    assert PaywallBypass._discover_amp("<html>no amp here</html>", "https://s/x") is None


def test_amp_candidates_variants():
    cands = PaywallBypass._amp_candidates("https://site.com/news/story")
    assert "https://site.com/news/story/amp" in cands
    assert any("outputType=amp" in c for c in cands)
    assert any("amp=1" in c for c in cands)
    assert len(cands) == len(set(cands))  # de-duped


def test_amp_candidates_preserves_existing_query():
    cands = PaywallBypass._amp_candidates("https://s.com/a?id=5")
    assert any("id=5&outputType=amp" in c for c in cands)


def test_google_cache_url_encoded():
    u = PaywallBypass._google_cache_url("https://s.com/a?b=1")
    assert u.startswith("https://webcache.googleusercontent.com/search?q=cache:")
    assert "%3A" in u or "%2F" in u  # the target URL is percent-encoded


def test_reader_view_extracts_article_text():
    html = (
        "<html><head><title>My Story</title></head><body>"
        "<nav>menu home about</nav>"
        "<article><h2>Heading</h2><p>First paragraph.</p>"
        "<script>tracker('x')</script><p>Second paragraph.</p></article>"
        "<footer>copyright junk</footer></body></html>"
    )
    out = PaywallBypass._reader_view(html)
    assert "First paragraph." in out
    assert "Second paragraph." in out
    assert "Heading" in out
    assert "My Story" in out
    # chrome / scripts excluded
    assert "menu home about" not in out
    assert "tracker" not in out
    assert "copyright junk" not in out


def test_reader_view_falls_back_without_article():
    html = "<html><body><p>Lone paragraph.</p></body></html>"
    out = PaywallBypass._reader_view(html)
    assert "Lone paragraph." in out
