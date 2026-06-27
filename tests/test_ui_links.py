"""gui/ui_components.py — selectable/clickable link helpers (Task 4).

The pure ``linkify`` is tested without Qt; the widget helpers and the Findings
detail panel (one concrete tab application) are driven under the offscreen qapp.
"""
from qtpy.QtCore import Qt

from gui import ui_components as ui
from gui.ui_components import (
    LinkTextBrowser, linkify, make_link_label, make_selectable_label,
)


# ── pure linkify ────────────────────────────────────────────────────────────────

def test_linkify_wraps_url_in_anchor():
    out = linkify("see https://shop.io/a?x=1 now")
    assert '<a href="https://shop.io/a?x=1">https://shop.io/a?x=1</a>' in out


def test_linkify_keeps_trailing_punctuation_outside_anchor():
    out = linkify("see https://shop.io/a.")
    assert '<a href="https://shop.io/a">https://shop.io/a</a>.' in out
    assert 'href="https://shop.io/a."' not in out


def test_linkify_escapes_non_url_text():
    out = linkify('<script>alert(1)</script> https://x.io')
    assert '<script>' not in out                 # escaped, not raw markup
    assert '&lt;script&gt;' in out
    assert '<a href="https://x.io">' in out       # the URL still becomes a link


def test_linkify_newlines_to_br():
    assert linkify("a\nb") == "a<br>b"
    assert linkify("a\nb", newlines_to_br=False) == "a\nb"


def test_linkify_plain_text_has_no_anchor():
    assert "<a " not in linkify("just /a/local/path and an endpoint")


# ── widget helpers ──────────────────────────────────────────────────────────────

def test_make_selectable_label_flags(qapp):
    lbl = make_selectable_label("copy me")
    flags = lbl.textInteractionFlags()
    assert flags & Qt.TextSelectableByMouse
    assert flags & Qt.TextSelectableByKeyboard


def test_make_link_label_is_clickable_link(qapp):
    lbl = make_link_label("https://shop.io/x", "Open")
    assert 'href="https://shop.io/x"' in lbl.text()
    assert '>Open<' in lbl.text()
    assert lbl.openExternalLinks() is True
    assert lbl.textInteractionFlags() & Qt.LinksAccessibleByMouse
    assert lbl.wordWrap() is True


def test_make_link_label_escapes_url(qapp):
    lbl = make_link_label('https://x.io/"><img>')
    assert '"><img>' not in lbl.text()            # quote/markup escaped in href/text


def test_link_text_browser_linkifies(qapp):
    br = LinkTextBrowser()
    br.set_linkified("location: https://shop.io/cart\nrule: idor")
    html = br.toHtml()
    assert 'href="https://shop.io/cart"' in html
    assert br.openExternalLinks() is True
    assert br.isReadOnly() is True


def test_selectable_flags_constant():
    assert ui.SELECTABLE_FLAGS & Qt.LinksAccessibleByMouse


# ── Findings detail panel application ────────────────────────────────────────────

def test_findings_detail_makes_location_clickable(qapp):
    from tests.gui_test_helpers import FindingsHost
    host = FindingsHost()
    host._findings_chains = {}
    rec = {'title': 'IDOR', 'category': 'vuln', 'rule_id': 'idor',
           'severity': 'high', 'status': 'OPEN', 'id': 'f1',
           'evidence': {'location': 'https://shop.io/api/cart'}}
    host._show_finding_detail(rec)
    html = host.findings_detail.toHtml()
    assert 'href="https://shop.io/api/cart"' in html
