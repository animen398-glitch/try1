"""Offline tests for Browser-Backed Accuracy Mode (Roadmap E4).

No browser is launched: the render seam is injected and the DOM/accuracy logic
is exercised over HTML strings.
"""

from core.browser_accuracy import (
    accuracy_delta,
    build_browser_accuracy,
    capture_rendered_html,
    extract_dom_assets,
    render_available,
)


_BASE = "https://shop.example.com/"

_STATIC = """
<html><body>
  <a href="/about">About</a>
  <script src="/app.js"></script>
</body></html>
"""

# The rendered DOM exposes more: a JS-injected internal link, an external link,
# a form, and a CDN subresource host.
_RENDERED = """
<html><body>
  <a href="/about">About</a>
  <a href="/account/settings">Settings</a>
  <a href="https://partner.other.com/ref">Partner</a>
  <form action="/api/login"></form>
  <script src="/app.js"></script>
  <img src="https://cdn.assets.io/logo.png">
</body></html>
"""


# --- extract_dom_assets ------------------------------------------------------

def test_extract_resolves_and_classifies():
    a = extract_dom_assets(_RENDERED, _BASE)
    assert "https://shop.example.com/about" in a["internal_links"]
    assert "https://shop.example.com/account/settings" in a["internal_links"]
    assert "partner.other.com" in a["external_hosts"]
    assert "https://shop.example.com/api/login" in a["forms"]
    assert "cdn.assets.io" in a["resource_hosts"]


def test_extract_dedups_and_sorts():
    html = '<a href="/x">1</a><a href="/x">2</a><a href="/a">a</a>'
    links = extract_dom_assets(html, _BASE)["internal_links"]
    assert links == ["https://shop.example.com/a", "https://shop.example.com/x"]


def test_extract_ignores_non_http_schemes():
    html = '<a href="mailto:x@y.com">m</a><a href="javascript:void(0)">j</a>'
    a = extract_dom_assets(html, _BASE)
    assert a["links"] == []


def test_extract_empty_and_malformed_safe():
    assert extract_dom_assets("", _BASE)["links"] == []
    assert extract_dom_assets(None, _BASE)["links"] == []
    # An unclosed tag must not raise.
    extract_dom_assets("<a href=/x>oops<script src=/a.js", _BASE)


# --- accuracy_delta ----------------------------------------------------------

def test_delta_reports_rendered_only_assets():
    static = extract_dom_assets(_STATIC, _BASE)
    rendered = extract_dom_assets(_RENDERED, _BASE)
    delta = accuracy_delta(static, rendered)
    assert "https://shop.example.com/account/settings" in delta["added"]["internal_links"]
    assert "https://shop.example.com/api/login" in delta["added"]["forms"]
    assert "cdn.assets.io" in delta["added"]["resource_hosts"]
    assert delta["summary"]["added_total"] > 0
    assert delta["summary"]["gain_pct"] > 0


def test_delta_zero_when_identical():
    a = extract_dom_assets(_STATIC, _BASE)
    delta = accuracy_delta(a, a)
    assert delta["summary"]["added_total"] == 0
    assert delta["summary"]["gain_pct"] == 0.0


def test_delta_tolerates_non_dicts():
    delta = accuracy_delta(None, None)
    assert delta["summary"]["added_total"] == 0


# --- build_browser_accuracy --------------------------------------------------

def test_build_combines_static_rendered_delta():
    report = build_browser_accuracy(static_html=_STATIC, rendered_html=_RENDERED,
                                    base_url=_BASE)
    assert report["base_url"] == _BASE
    assert report["static"]["internal_links"]
    assert report["delta"]["summary"]["added_total"] >= 3


# --- capture_rendered_html (injectable / gated seam) -------------------------

def test_capture_uses_injected_render_fn():
    out = capture_rendered_html("https://x", render_fn=lambda u: "<a href='/y'>y</a>")
    assert out["status"] == "rendered"
    assert "href" in out["html"]


def test_capture_render_fn_error_is_soft():
    def boom(u):
        raise RuntimeError("render crashed")

    out = capture_rendered_html("https://x", render_fn=boom)
    assert out["status"] == "error"
    assert out["html"] == ""


def test_capture_soft_skips_without_playwright(monkeypatch):
    monkeypatch.setattr("core.browser_accuracy.render_available", lambda: False)
    out = capture_rendered_html("https://x")
    assert out["status"] == "unavailable"
    assert "playwright" in out["reason"]


def test_render_available_is_bool():
    assert isinstance(render_available(), bool)


def test_end_to_end_with_injected_render():
    # Full path offline: inject the "browser" render, then build the accuracy view.
    rendered = capture_rendered_html(_BASE, render_fn=lambda u: _RENDERED)
    assert rendered["status"] == "rendered"
    report = build_browser_accuracy(static_html=_STATIC,
                                    rendered_html=rendered["html"], base_url=_BASE)
    assert report["delta"]["summary"]["added_total"] >= 3
