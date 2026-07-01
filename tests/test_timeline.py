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
         'high': 2, 'medium': 3, 'weak_cookies': 4, 'source_map_leaks': 1,
         'graphql': 2, 'graphql_introspection': 1},
        {'id': '20260101_000000', 'finished_at': 'a', 'risk_score': 10,
         'risk_level': 'Low', 'attack_surface_score': 5, 'secrets': 0,
         'high': 0, 'medium': 1},
    ]
    series = timeline.build_series(entries)
    assert [p['scan_id'] for p in series] == ['20260101_000000', '20260102_000000']
    assert series[0]['risk_score'] == 10 and series[0]['attack_surface'] == 5
    assert series[1]['secrets'] == 1 and series[1]['high'] == 2
    # Detection-category counts are carried for the trend layer.
    assert series[1]['weak_cookies'] == 4 and series[1]['graphql_introspection'] == 1
    assert series[0]['weak_cookies'] is None        # pre-EPIC entry → gap, not 0


def test_build_series_tolerates_junk():
    assert timeline.build_series([None, {}, 'x']) == [
        {'scan_id': None, 'at': None, 'risk_score': None, 'risk_level': None,
         'attack_surface': None, 'secrets': None, 'high': None, 'medium': None,
         'source_map_leaks': None, 'weak_cookies': None, 'graphql': None,
         'graphql_introspection': None}]


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


def test_secret_timeline_owned_by_f1_when_secret_findings_exist():
    # Secrets are findings (api phase + deep-JS audit), so F1 events own the secret
    # timeline: the Scan-Diff 'secrets' section is dropped (to avoid a double
    # appearance), but the F1 new_finding / lifecycle is kept and non-secret diff
    # events remain.
    a = _report('s1', '2026-01-01')
    b = _report('s2', '2026-01-02', secrets={'aws': ['AKIAEXAMPLE0001']},
                techs=[{'name': 'React', 'version': '18'}])
    fevents = [
        {'type': 'CREATED', 'scan_id': 's2', 'at': '2026-01-02',
         'title': 'Leaked secret: AWS Access Key', 'severity': 'high',
         'category': 'secret'},
        {'type': 'RESOLVED_AUTO', 'scan_id': 's3', 'at': '2026-01-03',
         'title': 'Leaked secret: AWS Access Key', 'severity': 'high',
         'category': 'secret'},
    ]
    events = timeline.build_events([('s1', a), ('s2', b)], fevents)
    types = [e['type'] for e in events]
    assert 'new_secret' not in types          # Scan-Diff secrets section dropped
    assert 'new_finding' in types             # F1 owns the secret's appearance
    assert 'finding_resolved' in types        # …and its lifecycle
    assert 'new_technology' in types          # non-secret diff events kept


def test_secret_diff_events_kept_when_no_secret_findings():
    # Backward compatible: a legacy project with no secret findings keeps its
    # Scan-Diff secret events in the timeline.
    a = _report('s1', '2026-01-01')
    b = _report('s2', '2026-01-02', secrets={'aws': ['AKIAEXAMPLE0001']})
    events = timeline.build_events([('s1', a), ('s2', b)], [])
    assert 'new_secret' in {e['type'] for e in events}


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


def test_audit_run_events_are_folded_into_timeline():
    audit_runs = [{
        'id': 'audit-shop-1',
        'profile': 'client_safe',
        'status': 'completed',
        'created_at': '2026-03-01T10:00:00',
        'updated_at': '2026-03-01T10:05:00',
    }]
    audit_events = [{
        'run_id': 'audit-shop-1',
        'type': 'finding_verified',
        'phase': 'validation',
        'finding_id': 'finding-1',
        'at': '2026-03-01T10:03:00',
    }]

    events = timeline.build_events(
        [],
        audit_runs=audit_runs,
        audit_events=audit_events,
    )

    assert [e['type'] for e in events] == [
        'audit_run_started',
        'audit_finding_verified',
        'audit_run_completed',
    ]
    assert {e['section'] for e in events} == {'audit_runs'}
    assert events[1]['title'] == 'audit-shop-1 finding_verified finding=finding-1'


def test_mission_events_are_folded_into_timeline():
    missions = [
        {  # still a draft → only a created event
            'id': 'mission-aaa',
            'profile': 'client_safe',
            'status': 'draft',
            'created_at': '2026-03-02T09:00:00',
            'updated_at': '2026-03-02T09:00:00',
            'payload': {'objective': 'External review'},
        },
        {  # advanced → created + a status event
            'id': 'mission-bbb',
            'profile': 'client_safe',
            'status': 'running',
            'created_at': '2026-03-02T08:00:00',
            'updated_at': '2026-03-02T10:00:00',
            'payload': {'objective': 'Portal audit'},
        },
    ]

    events = timeline.build_events([], missions=missions)

    assert {e['section'] for e in events} == {'missions'}
    types = [e['type'] for e in events]
    assert types.count('mission_created') == 2
    assert 'mission_running' in types
    # draft missions emit no status event
    assert 'mission_draft' not in types
    running = next(e for e in events if e['type'] == 'mission_running')
    assert running['at'] == '2026-03-02T10:00:00'
    assert 'Portal audit' in running['title']


def test_mission_run_events_are_shaped_from_linked_runs():
    mission_runs = [
        {'mission_id': 'mission-aaa', 'objective': 'External review',
         'run_id': 'mrun-1', 'status': 'completed',
         'created_at': '2026-03-03T10:00:00', 'updated_at': '2026-03-03T10:05:00'},
        {'mission_id': 'mission-bbb', 'objective': 'Portal audit',
         'run_id': 'mrun-2', 'status': 'failed',
         'created_at': '2026-03-03T11:00:00', 'updated_at': '2026-03-03T11:02:00'},
    ]

    events = timeline.build_events([], mission_runs=mission_runs)

    assert {e['section'] for e in events} == {'missions'}
    types = [e['type'] for e in events]
    assert types.count('mission_run_started') == 2
    assert 'mission_run_completed' in types and 'mission_run_failed' in types
    failed = next(e for e in events if e['type'] == 'mission_run_failed')
    assert failed['severity'] == 'medium'
    assert failed['at'] == '2026-03-03T11:02:00'
    assert 'Portal audit' in failed['title'] and 'mrun-2' in failed['title']


def test_build_timeline_includes_mission_run_events(tmp_path):
    from core import mission_runner, pentest_mission as pm
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore
    from core.mission_store import MissionStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    mission = pm.advance_mission_status(
        pm.create_mission(project.slug, 'External review',
                          allowed_actions=['headers_check']), 'ready')
    saved = MissionStore().save_mission(mission)
    FindingsStore().upsert(project.slug, Finding(
        category='vuln', rule_id='edge', title='Exposed map', severity='high',
        location='https://x.com/a.js.map').to_store(), scan_id='s1')
    mission_runner.run_mission(saved['payload'])

    tl = timeline.build_timeline(project)
    types = {e['type'] for e in tl['events'] if e['section'] == 'missions'}
    assert 'mission_run_started' in types
    assert 'mission_run_completed' in types


def test_tool_run_events_are_shaped():
    tool_runs = [
        {'tool': 'header_audit', 'scan_id': 'tool-header_audit-1700000000',
         'at': '2026-04-01T10:00:00', 'findings': 2, 'assets': 1},
    ]
    events = timeline.build_events([], tool_runs=tool_runs)
    assert len(events) == 1
    ev = events[0]
    assert ev['type'] == 'tool_run' and ev['section'] == 'tools'
    assert ev['scan_id'] == 'tool-header_audit-1700000000'
    assert ev['severity'] == 'info'
    assert ('header_audit' in ev['title'] and '2 finding' in ev['title']
            and '1 asset' in ev['title'])


def test_derive_tool_runs_groups_created_events_by_scan_id():
    fe = [
        {'type': 'CREATED', 'scan_id': 'tool-header_audit-1700000000',
         'at': '2026-04-01T10:00:01'},
        {'type': 'CREATED', 'scan_id': 'tool-header_audit-1700000000',
         'at': '2026-04-01T10:00:00'},                       # earlier 'at'
        {'type': 'CREATED', 'scan_id': 's1', 'at': '2026-04-01T09:00:00'},  # real scan
        {'type': 'SEEN', 'scan_id': 'tool-header_audit-1700000000', 'at': 'x'},  # not CREATED
    ]
    ae = [{'type': 'CREATED', 'scan_id': 'tool-safe_active_prober-1700000005',
           'at': '2026-04-01T10:01:00'}]
    by_id = {r['scan_id']: r for r in timeline._derive_tool_runs(fe, ae)}
    assert 's1' not in by_id                                 # non-tool scan id excluded
    hdr = by_id['tool-header_audit-1700000000']
    assert hdr['tool'] == 'header_audit' and hdr['findings'] == 2
    assert hdr['at'] == '2026-04-01T10:00:00'                # earliest kept
    assert by_id['tool-safe_active_prober-1700000005']['assets'] == 1


def test_build_timeline_includes_tool_run_event(tmp_path):
    from core import pentest_mission as pm
    from core.mission_store import MissionStore
    from core.project import ProjectStore
    from core.tool_runner import run_tool_for_mission, tool_scan_id

    project = ProjectStore(tmp_path).get_or_create('https://shop.io')
    mission = pm.create_mission(
        project.slug, 'External review',
        roe={'allowed_domains': [project.slug], 'active_scan_enabled': True,
             'passive_only': False, 'authorized_by': 'client'},
        allowed_actions=['headers_check'])
    MissionStore().save_mission(mission)
    sid = tool_scan_id('header_audit')
    out = run_tool_for_mission(
        mission, 'header_audit',
        {'url': f'https://{project.slug}', 'headers': {}}, scan_id=sid)
    assert out['ingest']['written']

    tl = timeline.build_timeline(project)
    tool_events = [e for e in tl['events'] if e['type'] == 'tool_run']
    assert len(tool_events) == 1
    assert tool_events[0]['scan_id'] == sid
    assert 'header_audit' in tool_events[0]['title']
    # structured rows are also returned for CSV/export (one per tool run)
    assert [r['scan_id'] for r in tl['tool_runs']] == [sid]
    assert tl['tool_runs'][0]['tool'] == 'header_audit'
    assert tl['tool_runs'][0]['findings'] >= 1


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


def test_build_timeline_includes_audit_run_events(tmp_path):
    from core.audit_store import AuditRunStore
    from core.audit_workflow import advance_audit_phase, create_audit_run
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    run = create_audit_run(project.slug, phases=['validation'], run_id='audit-x')
    store = AuditRunStore()
    store.save_run(run, now='2026-03-01T10:00:00')
    store.record_event(
        'audit-x',
        'quality_gate_passed',
        phase='risk_business_impact',
        at='2026-03-01T10:01:00',
    )
    run = advance_audit_phase(run, 'validation', {'validated_findings': []})
    store.save_run(run, now='2026-03-01T10:05:00')

    tl = timeline.build_timeline(project)

    audit_events = [e for e in tl['events'] if e['section'] == 'audit_runs']
    assert [e['type'] for e in audit_events] == [
        'audit_run_started',
        'audit_quality_gate_passed',
        'audit_run_completed',
    ]


def test_build_timeline_includes_mission_events(tmp_path):
    from core import pentest_mission as pm
    from core.mission_store import MissionStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    mission = pm.create_mission(project.slug, 'External review',
                               allowed_actions=['headers_check'])
    mission = pm.advance_mission_status(mission, 'ready')
    MissionStore().save_mission(mission, now='2026-03-02T09:00:00')

    tl = timeline.build_timeline(project)

    mission_events = [e for e in tl['events'] if e['section'] == 'missions']
    assert {e['type'] for e in mission_events} == {'mission_created', 'mission_ready'}


def test_engagement_events_are_folded_into_timeline():
    engagements = [
        {  # draft → only a created event
            'id': 'eng-aaa', 'status': 'draft',
            'created_at': '2026-04-01T09:00:00', 'updated_at': '2026-04-01T09:00:00',
            'payload': {'client': 'Acme Corp'},
        },
        {  # advanced → created + a status event
            'id': 'eng-bbb', 'status': 'authorized',
            'created_at': '2026-04-01T08:00:00', 'updated_at': '2026-04-01T10:00:00',
            'payload': {'client': 'Beta LLC'},
        },
    ]
    events = timeline.build_events([], engagements=engagements)
    assert {e['section'] for e in events} == {'engagements'}
    types = [e['type'] for e in events]
    assert types.count('engagement_created') == 2
    assert 'engagement_authorized' in types
    assert 'engagement_draft' not in types
    auth = next(e for e in events if e['type'] == 'engagement_authorized')
    assert auth['at'] == '2026-04-01T10:00:00' and 'Beta LLC' in auth['title']


def test_build_timeline_includes_engagement_events(tmp_path):
    from core import engagement as eng
    from core.engagement_store import EngagementStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    e = eng.create_engagement('Acme Corp', project.slug,
                              authorization={'accepted': True})
    e = eng.advance_engagement_status(e, 'authorized')
    EngagementStore().save_engagement(e, now='2026-04-01T09:00:00')

    tl = timeline.build_timeline(project)
    eng_events = [ev for ev in tl['events'] if ev['section'] == 'engagements']
    assert {ev['type'] for ev in eng_events} == {'engagement_created',
                                                 'engagement_authorized'}


def test_retest_run_events_are_shaped():
    retest_runs = [
        {'retest_run_id': 'rt-ok', 'engagement_id': 'eng-1',
         'status': 'completed', 'created_at': '2026-07-01T10:00:00Z',
         'summary': {'total': 3, 'fixed': 1, 'open': 2, 'accepted': 0,
                     'missing': 0}},
        {'retest_run_id': 'rt-bad', 'engagement_id': 'eng-1',
         'status': 'failed', 'created_at': '2026-07-02T10:00:00Z',
         'summary': {}},
    ]
    events = timeline.build_events([], retest_runs=retest_runs)
    assert {e['section'] for e in events} == {'engagements'}
    assert [e['type'] for e in events] == ['retest_run', 'retest_run']
    ok = next(e for e in events if 'rt-ok' in e['title'])
    assert 'fixed 1/3' in ok['title'] and ok['severity'] == 'info'
    bad = next(e for e in events if 'rt-bad' in e['title'])
    assert bad['severity'] == 'medium'


def test_build_timeline_includes_retest_run_events(tmp_path):
    from core import engagement as eng
    from core.engagement_store import EngagementStore
    from core.findings_adapter import Finding
    from core.findings_store import FindingsStore
    from core.project import ProjectStore
    from core.retest_runner import run_retest

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    fid = FindingsStore().upsert(project.slug, Finding(
        category='vuln', rule_id='r', title='t', severity='high',
        location='https://x.com/a').to_store(), scan_id='s1')['finding']['id']
    e = eng.link_finding(eng.create_engagement('Acme', project.slug), fid)
    EngagementStore().save_engagement(e, now='2026-07-01T09:00:00')
    run_retest(e, now='2026-07-01T10:00:00Z')

    tl = timeline.build_timeline(project)
    assert len(tl['retest_runs']) == 1
    rt_events = [ev for ev in tl['events'] if ev['type'] == 'retest_run']
    assert len(rt_events) == 1 and rt_events[0]['section'] == 'engagements'


def test_build_timeline_tightens_sla_breach_on_kev(tmp_path):
    """A KEV finding surfaces an sla_breach on its tightened deadline even though
    it is on-track on the plain severity window — the timeline threat-annotates
    active findings from the offline cache before deriving SLA breaches."""
    from datetime import datetime, timedelta

    from core.cve_store import CVEStore
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    cve = 'CVE-2021-44228'
    CVEStore().put_cve_threat(cve, {'kev': True})   # isolated per-test (conftest)
    # 15 days old: on-track on the 30d high window, breached on the KEV 8d window.
    seen = (datetime.now() - timedelta(days=15)).isoformat(timespec='seconds')
    store = FindingsStore()
    kev = {'id': fingerprint('vuln', cve, 'https://x.com/'), 'category': 'vuln',
           'rule_id': cve, 'title': 'Log4Shell', 'severity': 'high', 'evidence': None}
    plain = {'id': fingerprint('vuln', 'https', 'https://x.com/'), 'category': 'vuln',
             'rule_id': 'https', 'title': 'Plain HTTP', 'severity': 'high',
             'evidence': None}
    store.upsert(project.slug, kev, now=seen)
    store.upsert(project.slug, plain, now=seen)

    tl = timeline.build_timeline(project)
    breaches = [e for e in tl['events'] if e['type'] == 'sla_breach']
    assert len(breaches) == 1                       # only the KEV finding breaches
    assert 'Log4Shell' in breaches[0]['title']


def test_build_timeline_emits_new_kev_event(tmp_path):
    """A finding whose CVE is KEV-listed surfaces a new_kev timeline event,
    derived from the offline threat cache (a plain finding produces none)."""
    from datetime import datetime, timedelta

    from core.cve_store import CVEStore
    from core.finding_fingerprint import fingerprint
    from core.findings_store import FindingsStore
    from core.project import ProjectStore

    project = ProjectStore(tmp_path).get_or_create('https://x.com')
    cve = 'CVE-2021-44228'
    CVEStore().put_cve_threat(cve, {'kev': True})   # isolated per-test (conftest)
    seen = (datetime.now() - timedelta(days=3)).isoformat(timespec='seconds')
    store = FindingsStore()
    kev = {'id': fingerprint('vuln', cve, 'https://x.com/'), 'category': 'vuln',
           'rule_id': cve, 'title': 'Log4Shell', 'severity': 'medium', 'evidence': None}
    plain = {'id': fingerprint('vuln', 'https', 'https://x.com/'), 'category': 'vuln',
             'rule_id': 'https', 'title': 'Plain HTTP', 'severity': 'high',
             'evidence': None}
    store.upsert(project.slug, kev, now=seen)
    store.upsert(project.slug, plain, now=seen)

    tl = timeline.build_timeline(project)
    kevs = [e for e in tl['events'] if e['type'] == 'new_kev']
    assert len(kevs) == 1
    assert kevs[0]['severity'] == 'high'
    assert 'Log4Shell' in kevs[0]['title'] and 'KEV' in kevs[0]['title']
