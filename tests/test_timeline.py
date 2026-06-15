"""Timeline builders (core/timeline.py, F2 T2.1).

The pure builders (build_series / build_events) are tested on synthetic data; the
thin loader build_timeline is exercised against a real Project + isolated
findings DB. All offline.
"""

from core import timeline


# ── build_series ───────────────────────────────────────────────────────────────

def test_build_series_maps_metadata_entries_in_order():
    entries = [
        {'id': '20260102_000000', 'finished_at': 'b', 'risk_score': 30,
         'risk_level': 'Medium', 'attack_surface_score': 12, 'secrets': 1,
         'high': 2, 'medium': 3},
        {'id': '20260101_000000', 'finished_at': 'a', 'risk_score': 10,
         'risk_level': 'Low', 'attack_surface_score': 5, 'secrets': 0,
         'high': 0, 'medium': 1},
    ]
    series = timeline.build_series(entries)
    assert [p['scan_id'] for p in series] == ['20260101_000000', '20260102_000000']
    assert series[0]['risk_score'] == 10 and series[0]['attack_surface'] == 5
    assert series[1]['secrets'] == 1 and series[1]['high'] == 2


def test_build_series_tolerates_junk():
    assert timeline.build_series([None, {}, 'x']) == [
        {'scan_id': None, 'at': None, 'risk_score': None, 'risk_level': None,
         'attack_surface': None, 'secrets': None, 'high': None, 'medium': None}]


# ── build_events: structural / risk from consecutive scans ─────────────────────

def _report(scan_id, finished, *, secrets=None, techs=None, risk=('Low', 10)):
    return {
        'scan_id': scan_id, 'finished_at': finished,
        'executive_summary': {'risk_level': risk[0], 'risk_100': risk[1],
                              'metrics': {'risk_100': risk[1]}},
        'phases': {
            'api': {'status': 'Success', 'data': {'details': secrets or {}}},
            'recon': {'status': 'Success', 'data': {'technologies': techs or []}},
        },
    }


def test_first_scan_has_no_diff_events():
    a = _report('s1', '2026-01-01', secrets={'aws': ['AKIAEXAMPLE0001']})
    assert timeline.build_events([('s1', a)]) == []


def test_consecutive_scans_emit_change_events():
    a = _report('s1', '2026-01-01', techs=[{'name': 'React', 'version': '17'}])
    b = _report('s2', '2026-01-02',
                secrets={'aws': ['AKIAEXAMPLE0001']},
                techs=[{'name': 'React', 'version': '18'}],
                risk=('High', 60))
    events = timeline.build_events([('s1', a), ('s2', b)])
    by_type = {e['type']: e for e in events}
    assert 'new_secret' in by_type and 'tech_version_change' in by_type
    assert 'risk_increase' in by_type
    # all stamped with the newer scan + its finish time
    assert all(e['scan_id'] == 's2' for e in events)
    assert by_type['new_secret']['at'] == '2026-01-02'


def test_skipped_phase_produces_no_false_event():
    # api phase failed in A → scan_diff skips the secrets section → no new_secret,
    # even though B has a secret (a phase that didn't run ≠ "newly appeared").
    a = _report('s1', '2026-01-01')
    a['phases']['api']['status'] = 'Error'
    b = _report('s2', '2026-01-02', secrets={'aws': ['AKIAEXAMPLE0001']})
    types = [e['type'] for e in timeline.build_events([('s1', a), ('s2', b)])]
    assert 'new_secret' not in types


def test_missing_report_is_skipped_not_faked():
    b = _report('s2', '2026-01-02', secrets={'aws': ['AKIAEXAMPLE0001']})
    # s1 has no report; s2 becomes the first usable scan → no diff events.
    assert timeline.build_events([('s1', None), ('s2', b)]) == []


# ── build_events: asset lifecycle ──────────────────────────────────────────────

def test_asset_events_mapped_and_noise_dropped():
    aevents = [
        {'type': 'CREATED', 'scan_id': 's1', 'at': '2026-01-01',
         'asset_type': 'subdomain', 'value': 'api.x.com', 'label': 'api.x.com'},
        {'type': 'SEEN', 'scan_id': 's2', 'at': '2026-01-02',
         'asset_type': 'subdomain', 'value': 'api.x.com'},      # noise → dropped
        {'type': 'GONE', 'scan_id': 's3', 'at': '2026-01-03',
         'asset_type': 'subdomain', 'value': 'api.x.com'},
        {'type': 'REAPPEARED', 'scan_id': 's4', 'at': '2026-01-04',
         'asset_type': 'subdomain', 'value': 'api.x.com'},
    ]
    events = timeline.build_events([], None, aevents)
    seq = [(e['type'], e['severity'], e['section']) for e in events]
    assert seq == [('new_asset', 'low', 'assets'),
                   ('asset_gone', 'info', 'assets'),
                   ('asset_reappeared', 'low', 'assets')]
    assert events[0]['title'] == '[subdomain] api.x.com'


# ── build_events: findings lifecycle ───────────────────────────────────────────

def test_findings_events_mapped_and_noise_dropped():
    fevents = [
        {'type': 'CREATED', 'scan_id': 's1', 'at': '2026-01-01',
         'title': 'Weak CSP', 'severity': 'medium'},
        {'type': 'SEEN', 'scan_id': 's2', 'at': '2026-01-02',
         'title': 'Weak CSP', 'severity': 'medium'},          # noise → dropped
        {'type': 'RESOLVED_AUTO', 'scan_id': 's3', 'at': '2026-01-03',
         'title': 'Weak CSP', 'severity': 'medium'},
        {'type': 'REOPENED', 'scan_id': 's4', 'at': '2026-01-04',
         'title': 'Weak CSP', 'severity': 'medium'},
    ]
    events = timeline.build_events([], fevents)
    seq = [(e['type'], e['severity']) for e in events]
    assert seq == [('new_finding', 'medium'),       # carries finding severity
                   ('finding_resolved', 'info'),
                   ('finding_reopened', 'medium')]
    assert events[0]['title'] == '[medium] Weak CSP'


def test_sla_breach_events_merged_into_feed():
    # Already-shaped SLA-breach rows (from findings_sla.sla_events) are folded in
    # and ordered chronologically with the rest.
    sla_evts = [{'scan_id': None, 'at': '2026-02-01T00:00:00', 'type': 'sla_breach',
                 'title': '[high] Stale secret — SLA просрочено',
                 'severity': 'high', 'section': 'findings'}]
    fevents = [{'type': 'CREATED', 'scan_id': 's1', 'at': '2026-01-01',
                'title': 'Stale secret', 'severity': 'high'}]
    events = timeline.build_events([], fevents, None, sla_evts)
    types = [e['type'] for e in events]
    assert types == ['new_finding', 'sla_breach']     # chronological by 'at'


def test_events_are_deduped_and_time_ordered():
    a = _report('s1', '2026-01-01')
    b = _report('s2', '2026-01-02', risk=('High', 60))
    fe = [{'type': 'CREATED', 'scan_id': 's1', 'at': '2026-01-01',
           'title': 'X', 'severity': 'high'},
          {'type': 'CREATED', 'scan_id': 's1', 'at': '2026-01-01',
           'title': 'X', 'severity': 'high'}]      # duplicate
    events = timeline.build_events([('s1', a), ('s2', b)], fe)
    assert sum(e['type'] == 'new_finding' for e in events) == 1   # deduped
    ats = [e['at'] for e in events]
    assert ats == sorted(ats)                                    # chronological


# ── build_timeline: thin loader over a real project ────────────────────────────

def test_build_timeline_reads_project_and_findings(tmp_path):
    from core.collection_runner import CollectionRunner
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    runner = CollectionRunner()
    for sid, risk in (('20260101_000000', ('Low', 10)),
                      ('20260102_000000', ('High', 60))):
        scan_dir = project.start_scan(sid)
        report = _report(sid, sid, risk=risk,
                         secrets=({'aws': ['AKIAEXAMPLE0001']} if risk[1] == 60
                                  else {}))
        report['executive_summary']['risk_score'] = risk[1]
        # Persist findings for this scan so the timeline's findings source fills.
        report['phases']['vulns'] = {'status': 'Success', 'findings': [
            {'title': 'Weak Content-Security-Policy', 'severity': 'Medium'}]}
        runner._sync_findings(report, project, sid)
        (scan_dir / 'report.json').write_text(__import__('json').dumps(report),
                                              encoding='utf-8')
        project.record_scan(scan_dir, report)

    tl = timeline.build_timeline(project)
    assert tl['project'] == project.slug
    assert [p['scan_id'] for p in tl['series']] == ['20260101_000000',
                                                    '20260102_000000']
    types = {e['type'] for e in tl['events']}
    assert 'new_finding' in types          # from finding_events
    assert 'risk_increase' in types        # from consecutive scan_diff


def test_build_timeline_includes_asset_events(tmp_path):
    from core.asset_adapter import Asset
    from core.asset_store import AssetStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    AssetStore().sync(project.slug, 's1', [Asset('subdomain', 'api.x.com')])

    tl = timeline.build_timeline(project)
    asset_events = [e for e in tl['events'] if e['section'] == 'assets']
    assert [e['type'] for e in asset_events] == ['new_asset']
    assert asset_events[0]['title'] == '[subdomain] api.x.com'
