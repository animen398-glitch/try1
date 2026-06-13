"""Tests for Email Intelligence (core/email_intel.py, roadmap #13 OSINT).

Extraction and classification are pure; fetches are injected so nothing hits
the network.
"""

from core import email_intel as ei, scan_diff


# ── extract_emails (pure) ─────────────────────────────────────────────────────

def test_extract_basic_and_dedupe():
    text = 'Contact info@x.com or Info@X.com, sales@x.com'
    assert ei.extract_emails(text) == {'info@x.com', 'sales@x.com'}


def test_extract_filters_noise():
    text = ('sprite@2x.png logo@3x.svg react@18.2.0 '   # assets / version
            'user@example.com hi@sentry.io real@x.com')
    out = ei.extract_emails(text)
    assert out == {'real@x.com'}                          # placeholders dropped


def test_extract_ignores_version_strings():
    # "@18.2.0" has a numeric TLD -> not an email.
    assert ei.extract_emails('lib@1.2.3 and a@b.co') == {'a@b.co'}


# ── role_of (pure) ────────────────────────────────────────────────────────────

def test_role_of_buckets():
    assert ei.role_of('security@x.com') == 'security'
    assert ei.role_of('webmaster@x.com') == 'admin'
    assert ei.role_of('no-reply@x.com') == 'noreply'
    assert ei.role_of('john.doe@x.com') == 'personal'


# ── classify (pure) ───────────────────────────────────────────────────────────

def test_classify_on_domain_vs_external_and_roles():
    emails = {'info@x.com', 'admin@mail.x.com', 'ceo@gmail.com'}
    out = ei.classify(emails, 'x.com')
    assert out['total'] == 3
    assert out['on_domain'] == ['admin@mail.x.com', 'info@x.com']   # subdomain ok
    assert out['external'] == ['ceo@gmail.com']
    assert set(out['roles']) == {'info', 'admin', 'personal'}


# ── discover (injected fetch) ─────────────────────────────────────────────────

def test_discover_harvests_from_sources():
    pages = {
        'https://x.com': 'mail to info@x.com',
        'https://x.com/robots.txt': '# admin@x.com',
        'https://x.com/sitemap.xml': '<url>security@x.com</url>',
    }
    out = ei.discover('https://x.com/some/page', fetch=lambda u: pages.get(u, ''))
    assert out['status'] == 'Success' and out['domain'] == 'x.com'
    assert out['total'] == 3
    assert set(out['sources']) == {'homepage', 'robots', 'sitemap'}


def test_discover_no_emails():
    out = ei.discover('https://x.com', fetch=lambda u: 'nothing here')
    assert out['status'] == 'No emails' and out['total'] == 0


def test_discover_strips_www_for_on_domain_match():
    # Apex address on a www. site must count as on-domain.
    out = ei.discover('https://www.x.com', fetch=lambda u: 'info@x.com')
    assert out['domain'] == 'x.com'
    assert out['on_domain'] == ['info@x.com']


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    out = ei.discover('https://x.com', fetch=lambda u: 'security@x.com')
    page = ei.render_html(out)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert 'security@x.com' in page


def test_render_html_no_emails():
    assert 'не найдены' in ei.render_html({'status': 'No emails'})


# ── integration: scan_diff emails section ─────────────────────────────────────

def _report_with_emails(on_domain, external=None):
    return {'phases': {'emails': {'status': 'Success', 'data': {
        'on_domain': on_domain, 'external': external or []}}}}


def test_scan_diff_reports_new_email():
    a = _report_with_emails(['info@x.com'])
    b = _report_with_emails(['info@x.com', 'security@x.com'])
    d = scan_diff.diff(a, b)
    assert d['sections']['emails']['added'] == ['security@x.com']
