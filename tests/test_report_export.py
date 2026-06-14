"""CSV export of ASM data (core/report_export.py) — pure, offline.

Parsed back with csv.reader so assertions are independent of the line
terminator / quoting details that csv handles internally.
"""

import csv
import io

from core import report_export as rx


def _parse(text):
    return list(csv.reader(io.StringIO(text)))


# ── findings_csv ──────────────────────────────────────────────────────────────

def test_findings_csv_header_and_row():
    rows = [{'project': 'a.com', 'severity': 'high', 'status': 'OPEN',
             'category': 'header', 'title': 'Weak CSP', 'rule_id': 'csp',
             'first_seen_at': '2026-01-01', 'last_seen_at': '2026-02-01',
             'id': 'abc123'}]
    table = _parse(rx.findings_csv(rows))
    assert table[0] == ['Project', 'Severity', 'Status', 'Category', 'Title',
                        'Rule', 'First seen', 'Last seen', 'ID']
    assert table[1] == ['a.com', 'high', 'OPEN', 'header', 'Weak CSP', 'csp',
                        '2026-01-01', '2026-02-01', 'abc123']


def test_findings_csv_missing_keys_become_blank():
    table = _parse(rx.findings_csv([{'title': 'X'}]))
    assert table[1][table[0].index('Title')] == 'X'
    assert table[1][table[0].index('Project')] == ''


def test_findings_csv_quotes_commas_and_quotes():
    rows = [{'title': 'a, b "c"', 'severity': 'low'}]
    out = rx.findings_csv(rows)
    # Round-trips cleanly despite the comma + embedded quotes.
    assert _parse(out)[1][rx_idx('Title')] == 'a, b "c"'


def test_findings_csv_empty_is_header_only():
    table = _parse(rx.findings_csv([]))
    assert len(table) == 1 and table[0][0] == 'Project'
    assert _parse(rx.findings_csv(None))[0][0] == 'Project'


# ── assets_csv ────────────────────────────────────────────────────────────────

def test_assets_csv_header_and_row():
    rows = [{'project': 'x.com', 'type': 'subdomain', 'value': 'api.x.com',
             'label': 'api.x.com', 'status': 'ACTIVE',
             'first_seen_at': '2026-01-01', 'last_seen_at': '2026-02-01',
             'id': 'abc123'}]
    table = _parse(rx.assets_csv(rows))
    assert table[0] == ['Project', 'Type', 'Value', 'Label', 'Status',
                        'First seen', 'Last seen', 'ID']
    assert table[1] == ['x.com', 'subdomain', 'api.x.com', 'api.x.com', 'ACTIVE',
                        '2026-01-01', '2026-02-01', 'abc123']


def test_assets_csv_empty_is_header_only():
    assert _parse(rx.assets_csv([]))[0][0] == 'Project'
    assert _parse(rx.assets_csv(None))[0][0] == 'Project'


# ── portfolio_csv ─────────────────────────────────────────────────────────────

def test_portfolio_csv_from_full_dict():
    portfolio = {'rows': [{'slug': 'x.com', 'url': 'https://x', 'risk_level': 'High',
                           'risk_score': 12, 'risk_delta': 50, 'attack_surface': 11,
                           'secrets': 1, 'high': 2, 'medium': 1,
                           'active_findings': 0, 'scan_count': 2,
                           'updated_at': '2026-06-14'}]}
    table = _parse(rx.portfolio_csv(portfolio))
    assert table[0][0] == 'Project' and 'Risk' in table[0]
    row = table[1]
    assert row[0] == 'x.com'
    assert row[table[0].index('Score')] == '12'
    assert row[table[0].index('Delta')] == '50'


def test_portfolio_csv_accepts_bare_row_list():
    table = _parse(rx.portfolio_csv([{'slug': 'y.com', 'risk_level': 'Low'}]))
    assert table[1][0] == 'y.com'


def test_portfolio_csv_empty():
    assert _parse(rx.portfolio_csv({'rows': []}))[0][0] == 'Project'
    assert _parse(rx.portfolio_csv(None))[0][0] == 'Project'


def rx_idx(header):
    return [h for _, h in rx._FINDINGS_COLUMNS].index(header)
