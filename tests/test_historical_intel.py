"""Tests for Historical URL Intelligence (core/historical_intel.py, #12).

Classification is pure; the Wayback fetch is exercised with urlopen_text stubbed
and discover() with an injected fetch, so nothing hits the network.
"""

import json

from core import attack_surface, historical_intel as hi, scan_diff


# ── classify (pure) ───────────────────────────────────────────────────────────

def test_classify_buckets():
    assert 'admin' in hi.classify('https://x.com/wp-admin/index.php')
    assert 'auth' in hi.classify('https://x.com/login')
    assert 'api' in hi.classify('https://x.com/api/v1/users.json')
    assert 'config' in hi.classify('https://x.com/.env')
    assert 'upload' in hi.classify('https://x.com/upload/avatar.png')
    assert hi.classify('https://x.com/about') == []


# ── analyze (pure) ────────────────────────────────────────────────────────────

def test_analyze_dedupes_and_buckets():
    entries = [
        {'url': 'https://x.com/admin'},
        {'url': 'https://x.com/admin'},          # dup
        {'url': 'https://x.com/login'},
        'https://x.com/api/data.json',
        'https://x.com/about',                   # uninteresting
    ]
    out = hi.analyze(entries)
    assert out['total'] == 4                      # deduped
    assert set(out['categories']) == {'admin', 'auth', 'api'}
    # interesting = admin/auth/api/config subset (not /about)
    assert 'https://x.com/about' not in out['interesting']
    assert len(out['interesting']) == 3


def test_analyze_empty():
    out = hi.analyze([])
    assert out == {'total': 0, 'categories': {}, 'interesting': []}


def test_analyze_degrades_on_malformed_entries():
    # analyze accepts heterogeneous entries; a malformed element (unhashable
    # list, int, None) must degrade, not raise (F-SR1 degrade-not-raise).
    out = hi.analyze([['/admin'], 123, None, 'https://x/login'])
    assert out['total'] >= 1                      # at least the valid login URL
    assert 'https://x/login' in out['interesting']
    assert hi.classify(123) == []                 # non-str url -> no categories


# ── fetch_wayback (network stubbed) ───────────────────────────────────────────

def test_fetch_wayback_parses_cdx(monkeypatch):
    cdx = [['original', 'timestamp', 'statuscode'],
           ['https://x.com/admin', '20200101', '200'],
           ['https://x.com/login', '20210101', '301']]
    monkeypatch.setattr(hi, 'urlopen_text', lambda req, t, **k: json.dumps(cdx))
    rows = hi.fetch_wayback('x.com')
    assert [r['url'] for r in rows] == ['https://x.com/admin', 'https://x.com/login']
    assert rows[0]['status'] == '200'


def test_fetch_wayback_empty_on_error(monkeypatch):
    def boom(req, t, **k):
        raise OSError('network down')
    monkeypatch.setattr(hi, 'urlopen_text', boom)
    assert hi.fetch_wayback('x.com') == []


# ── discover (injected fetch) ─────────────────────────────────────────────────

def test_discover_classifies_archive():
    def fake(domain):
        assert domain == 'x.com'
        return [{'url': 'https://x.com/admin'}, {'url': 'https://x.com/about'}]
    out = hi.discover('https://x.com/some/page', fetch=fake)
    assert out['status'] == 'Success' and out['domain'] == 'x.com'
    assert out['total'] == 2 and out['interesting'] == ['https://x.com/admin']


def test_discover_no_history():
    out = hi.discover('https://x.com', fetch=lambda d: [])
    assert out['status'] == 'No history' and out['total'] == 0


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    data = hi.discover('https://x.com',
                       fetch=lambda d: [{'url': 'https://x.com/admin'}])
    page = hi.render_html(data)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert '/admin' in page


def test_render_html_no_history():
    assert 'не найдено' in hi.render_html({'status': 'No history'})


# ── integration: scan_diff + attack_surface ───────────────────────────────────

def _report_with_historical(interesting):
    return {'phases': {'historical': {'status': 'Success', 'data': {
        'interesting': interesting}}}}


def test_scan_diff_reports_new_historical_urls():
    a = _report_with_historical(['https://x.com/admin'])
    b = _report_with_historical(['https://x.com/admin', 'https://x.com/.env'])
    d = scan_diff.diff(a, b)
    assert d['sections']['historical']['added'] == ['https://x.com/.env']


def test_attack_surface_includes_historical_category():
    report = _report_with_historical(['https://x.com/admin', 'https://x.com/.git'])
    surface = attack_surface.build_surface(report)
    hist = next((c for c in surface['categories'] if c['name'] == 'Historical'),
                None)
    assert hist is not None and hist['count'] == 2
