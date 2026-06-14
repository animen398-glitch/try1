"""Timeline GUI tab (gui/tab_timeline.py, F2 T2.3) — headless, thread-free.

Like the Findings/Dashboard tab tests: the off-GUI queries are plain
staticmethods exercised directly, and the populate logic is driven with real
data. The findings DB is conftest's per-test temp file; projects live under a
tmp base.
"""

from gui.tab_timeline import TimelineTabMixin


def _window(qapp):
    from gui.main_window import MainWindow
    return MainWindow()


def _seed_project(base):
    """Two recorded scans (risk rising) + a persisted finding, so the timeline
    has both series points and events."""
    import json

    from core.collection_runner import CollectionRunner
    from core.project import ProjectStore

    project = ProjectStore(base).get_or_create('https://x.com')
    runner = CollectionRunner()
    for sid, risk in (('20260101_000000', 10), ('20260102_000000', 60)):
        scan_dir = project.start_scan(sid)
        report = {
            'scan_id': sid, 'finished_at': sid,
            'executive_summary': {'risk_level': 'High' if risk == 60 else 'Low',
                                  'risk_score': risk, 'risk_100': risk,
                                  'metrics': {'risk_100': risk}},
            'phases': {
                'recon': {'status': 'Success', 'data': {}},
                'vulns': {'status': 'Success', 'findings': [
                    {'title': 'Weak Content-Security-Policy', 'severity': 'Medium'}]},
            },
        }
        runner._sync_findings(report, project, sid)
        (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        project.record_scan(scan_dir, report)
    return project


# ── build ─────────────────────────────────────────────────────────────────────

def test_tab_builds_with_two_tables(qapp):
    w = _window(qapp)
    assert hasattr(w, '_timeline_widget')
    assert (w.timeline_events.columnCount()
            == len(TimelineTabMixin.TIMELINE_EVENT_COLUMNS))
    assert (w.timeline_series.columnCount()
            == len(TimelineTabMixin.TIMELINE_SERIES_COLUMNS))


def test_timeline_registered_in_tab_bar(qapp):
    w = _window(qapp)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert 'Timeline' in titles


# ── off-GUI queries ─────────────────────────────────────────────────────────────

def test_query_projects_and_timeline(tmp_path):
    _seed_project(tmp_path)
    base = str(tmp_path)
    projects = TimelineTabMixin._query_timeline_projects(base)['projects']
    assert any(p.get('slug') == 'x.com' for p in projects)

    tl = TimelineTabMixin._query_timeline(base, 'x.com')
    assert tl['slug'] == 'x.com'
    assert [p['scan_id'] for p in tl['series']] == ['20260101_000000',
                                                    '20260102_000000']
    types = {e['type'] for e in tl['events']}
    assert 'new_finding' in types and 'risk_increase' in types


def test_query_timeline_unknown_project_is_clean(tmp_path):
    out = TimelineTabMixin._query_timeline(str(tmp_path), 'nope.com')
    assert 'error' in out and out['slug'] == 'nope.com'


# ── populate ────────────────────────────────────────────────────────────────────

def test_populate_events_and_series(qapp):
    w = _window(qapp)
    w._populate_timeline_events([
        {'at': '2026-01-02T00:00:00', 'scan_id': 's2', 'type': 'risk_increase',
         'severity': 'high', 'title': 'Low 10 → High 60'},
        {'at': '2026-01-01T00:00:00', 'scan_id': 's1', 'type': 'new_finding',
         'severity': 'medium', 'title': '[medium] Weak CSP'},
    ])
    assert w.timeline_events.rowCount() == 2
    assert w.timeline_events.item(0, 2).text() == 'Риск ↑'      # label mapped
    assert w.timeline_events.item(0, 0).text() == '2026-01-02 00:00:00'

    w._populate_timeline_series([
        {'scan_id': 's1', 'at': 's1', 'risk_score': 10, 'secrets': 0,
         'attack_surface': 5, 'high': 0, 'medium': 1},
        {'scan_id': 's2', 'at': 's2', 'risk_score': 60, 'secrets': 1,
         'attack_surface': 9, 'high': 2, 'medium': 3},
    ])
    assert w.timeline_series.rowCount() == 2
    # newest scan shown first
    assert w.timeline_series.item(0, 0).text() == 's2'
    assert w.timeline_series.item(0, 2).text() == '60'


def test_empty_project_selection_clears(qapp):
    w = _window(qapp)
    w._apply_timeline()        # no project selected → safe, clears
    assert w.timeline_events.rowCount() == 0
    assert 'Нет проектов' in w.timeline_status.text()
