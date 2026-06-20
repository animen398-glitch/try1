"""Scan Diff integration — write_diff_report (core) + the Collection tab UI
(headless Qt): project/scan combos populate from the workspace and the
compare button gates on having two scans."""

import json

import pytest

from core.project import ProjectStore
from core.scan_diff import write_diff_report


def _seed_project(base, scan_specs):
    """A project with one report.json per (scan_id, risk_level) spec."""
    p = ProjectStore(base).get_or_create('https://example.com')
    for scan_id, level in scan_specs:
        scan_dir = p.start_scan(scan_id)
        report = {
            'url': 'https://example.com', 'status': 'Success',
            'scan_id': scan_id, 'finished_at': f'2026-06-13T{scan_id[-6:-4]}:00:00',
            'phases': {'capture': {'status': 'Success', 'data': {'site_map': [
                {'url': f'/{scan_id}', 'status': 200,
                 'content_type': 'text/html', 'depth': 1}]}}},
            'executive_summary': {'risk_level': level, 'risk_100': 4,
                                  'metrics': {'risk_100': 4}},
        }
        (scan_dir / 'report.json').write_text(
            json.dumps(report, ensure_ascii=False), encoding='utf-8')
        p.record_scan(scan_dir, report)
    return p


# ── core: write_diff_report ──────────────────────────────────────────────────

def test_write_diff_report_creates_html_in_reports(tmp_path):
    p = _seed_project(tmp_path, [('20260613_010000', 'Low'),
                                 ('20260613_020000', 'High')])
    result = write_diff_report(p, '20260613_010000', '20260613_020000')

    out = p.root / 'reports' / 'diff_20260613_010000_vs_20260613_020000.html'
    assert result['html_path'] == str(out)
    assert out.exists()
    page = out.read_text(encoding='utf-8')
    assert page.startswith('<!DOCTYPE html>')
    assert '<script' not in page
    assert result['evidence_integrity']['ok'] is False
    assert 'Evidence integrity warning' in page
    assert 'missing_manifest' in page
    # The two scans saw different pages → both show up in the diff.
    d = result['diff']
    assert d['sections']['pages']['added'] == ['/20260613_020000 [200]']
    assert d['sections']['pages']['removed'] == ['/20260613_010000 [200]']
    assert 'Страницы' in result['line']


def test_write_diff_report_missing_scan_raises(tmp_path):
    p = _seed_project(tmp_path, [('20260613_010000', 'Low')])
    with pytest.raises(ValueError, match='nope'):
        write_diff_report(p, '20260613_010000', 'nope')


# ── GUI: combos + gating (headless) ──────────────────────────────────────────

def _window_with_store(qapp, tmp_path):
    from gui.main_window import MainWindow
    w = MainWindow()
    w.collect_dir.setText(str(tmp_path))   # point the diff store at tmp
    return w


def test_diff_button_disabled_with_less_than_two_scans(qapp, tmp_path):
    _seed_project(tmp_path, [('20260613_010000', 'Low')])
    w = _window_with_store(qapp, tmp_path)
    w._refresh_diff_projects()
    assert w.diff_project.count() == 1
    assert not w.btn_scan_diff.isEnabled()


def test_diff_combos_populate_and_default_to_last_two(qapp, tmp_path):
    _seed_project(tmp_path, [('20260613_010000', 'Low'),
                             ('20260613_020000', 'High'),
                             ('20260613_030000', 'High')])
    w = _window_with_store(qapp, tmp_path)
    w._refresh_diff_projects()

    assert w.diff_project.currentData() == 'example.com'
    assert w.diff_scan_a.count() == 3
    # Default selection: previous → latest.
    assert w.diff_scan_a.currentText() == '20260613_020000'
    assert w.diff_scan_b.currentText() == '20260613_030000'
    assert w.btn_scan_diff.isEnabled()


def test_diff_refresh_tolerates_empty_store(qapp, tmp_path):
    w = _window_with_store(qapp, tmp_path / 'nothing_here')
    w._refresh_diff_projects()             # must not raise
    assert w.diff_project.count() == 0
    assert not w.btn_scan_diff.isEnabled()
