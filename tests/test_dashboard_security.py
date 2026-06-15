"""Dashboard Security Overview — loading the latest collection verdict and
populating the cards. Offline (filesystem + Qt headless)."""

import json
import os

from core.executive_summary import load_latest_summary


def _write_report(path, mtime, *, level='High', score=10, secrets=1,
                  high=2, medium=1):
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        'url': 'https://ex.com',
        'executive_summary': {
            'risk_level': level, 'risk_score': score,
            'metrics': {'secrets': secrets, 'high': high, 'medium': medium},
        },
    }
    path.write_text(json.dumps(report), encoding='utf-8')
    os.utime(path, (mtime, mtime))


# ── load_latest_summary ─────────────────────────────────────────────────────

def test_load_latest_summary_picks_newest(tmp_path):
    _write_report(tmp_path / 'a_20240101' / 'report.json', mtime=1000,
                  level='Low', score=1)
    _write_report(tmp_path / 'b_20240202' / 'report.json', mtime=2000,
                  level='Critical', score=21)
    sec = load_latest_summary([str(tmp_path)])
    assert sec['risk_level'] == 'Critical'
    assert sec['risk_score'] == 21
    assert sec['_source'].endswith('report.json')


def test_load_latest_summary_none_when_absent(tmp_path):
    assert load_latest_summary([str(tmp_path)]) is None
    assert load_latest_summary([None, '']) is None


def test_load_latest_summary_skips_corrupt(tmp_path):
    bad = tmp_path / 'bad' / 'report.json'
    bad.parent.mkdir(parents=True)
    bad.write_text('{not json', encoding='utf-8')
    os.utime(bad, (3000, 3000))
    _write_report(tmp_path / 'good' / 'report.json', mtime=2000, level='Medium')
    # Newest is corrupt → falls through to the next readable report.
    sec = load_latest_summary([str(tmp_path)])
    assert sec is not None
    assert sec['risk_level'] == 'Medium'


def test_load_latest_summary_builds_for_legacy_report(tmp_path):
    # Old report without an 'executive_summary' → one is built on the fly.
    legacy = tmp_path / 'old' / 'report.json'
    legacy.parent.mkdir(parents=True)
    legacy.write_text(json.dumps({
        'phases': {'api': {'data': {'keys_found': 1}}}}), encoding='utf-8')
    sec = load_latest_summary([str(tmp_path)])
    assert sec['risk_level'] == 'Critical'   # a leaked secret → Critical


# ── Dashboard population (Qt headless) ──────────────────────────────────────

def test_display_cards_fills_from_summary(tmp_path):
    # The Dashboard's _populate_security is a thin setter over this pure helper.
    from core.executive_summary import RISK_COLORS, display_cards
    c = display_cards({'risk_level': 'High', 'risk_score': 12,
                       'metrics': {'secrets': 1, 'high': 2, 'medium': 3},
                       '_source': str(tmp_path / 'report.json')})
    assert c['available'] is True
    assert c['risk_level'] == 'High'
    assert c['risk_color'] == RISK_COLORS['High']
    assert (c['risk_score'], c['secrets'], c['high'], c['medium']) == \
           ('12', '1', '2', '3')
    assert str(tmp_path) in c['source']


def test_display_cards_exposes_attack_surface():
    from core.executive_summary import display_cards
    c = display_cards({'risk_level': 'Medium', 'risk_score': 5,
                       'metrics': {'attack_surface_score': 16,
                                   'attack_surface_band': 'Medium'}})
    assert c['attack_surface'] == '16'
    assert c['attack_surface_band'] == 'Medium'


def test_display_cards_empty_state():
    from core.executive_summary import display_cards
    c = display_cards(None)
    assert c['available'] is False
    assert c['risk_level'] == '—'
    assert (c['risk_score'], c['secrets'], c['high'], c['medium']) == \
           ('0', '0', '0', '0')
    assert c['source'] == ''


# ── F-P3: "10-second" headline chip strip (Qt headless) ───────────────────────

def test_dashboard_headline_chips(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    w._populate_security({'risk_level': 'Critical', 'risk_100': 80,
                          'metrics': {'secrets': 2, 'high': 1, 'medium': 0}})
    assert w._sec_headline_layout.count() == 2     # "2 Secrets" + "1 High"
    # A clean summary shows a single reassuring chip.
    w._populate_security({'risk_level': 'Clean', 'risk_100': 0, 'metrics': {}})
    assert w._sec_headline_layout.count() == 1
    # No report → strip cleared.
    w._populate_security(None)
    assert w._sec_headline_layout.count() == 0
