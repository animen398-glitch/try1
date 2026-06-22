"""Back-compat key contracts (EPIC NEXT F0.T2).

These regression tests lock the *current* key sets of the structures that several
surfaces read across the platform: ``report.json``, ``metadata.json`` (project +
scan entry), findings (DTO + stored row + events), assets (DTO + stored row +
events), the executive summary, and the timeline.

Invariant §4.7 (CLAUDE.md): NEXT features may ADD keys, but must not drop or
rename these — so the assertions are **subset** checks (``required <= produced``).
A removal/rename fails loudly here before it can break the GUI / web / export /
scan-diff consumers. Each ``_KEYS`` constant doubles as living documentation of
the contract. Pure/offline; the one end-to-end case stubs the network phases.
"""

import json

from core.asset_adapter import Asset
from core.asset_store import (EVENT_TYPES as ASSET_EVENT_TYPES,
                              STATUSES as ASSET_STATUSES, AssetStore)
from core.collection_runner import CollectionRunner
from core.executive_summary import build_summary
from core.findings_adapter import Finding
from core.findings_store import (EVENT_TYPES as FINDING_EVENT_TYPES,
                                 STATUSES as FINDING_STATUSES, FindingsStore)
from core.project import Project, ProjectStore
from core.timeline import build_events, build_series


def _missing(required, actual):
    """Contract keys absent from the produced structure (empty == OK)."""
    return set(required) - set(actual)


# ── metadata.json ────────────────────────────────────────────────────────────

PROJECT_METADATA_KEYS = {
    'slug', 'url', 'created_at', 'updated_at', 'scan_count', 'latest_scan',
    'scans', 'scope',
}

SCAN_ENTRY_KEYS = {
    'id', 'dir', 'url', 'started_at', 'finished_at', 'status', 'risk_level',
    'risk_score', 'attack_surface_score', 'secrets', 'high', 'medium',
    'source_map_leaks', 'weak_cookies', 'graphql', 'graphql_introspection',
    'warning_count', 'warning_summary', 'report_html', 'report_json',
}


def test_project_metadata_contract(tmp_path):
    meta = Project(tmp_path / 'site.com', url='https://site.com').ensure().load_metadata()
    assert not _missing(PROJECT_METADATA_KEYS, meta)


def test_scan_entry_contract(tmp_path):
    project = Project(tmp_path / 'site.com', url='https://site.com').ensure()
    scan_dir = project.start_scan('20260101_000000')
    report = {
        'url': 'https://site.com', 'started_at': 'a', 'finished_at': 'b',
        'status': 'Success', 'executive_summary': {'risk_level': 'Low',
        'risk_score': 1, 'metrics': {'attack_surface_score': 2, 'secrets': 0,
        'high': 0, 'medium': 0, 'source_map_leaks': 0, 'weak_cookies': 0,
        'graphql': 0, 'graphql_introspection': 0}}, 'warnings': [],
        'report_html': 'x.html', 'report_json': 'x.json',
    }
    entry = project._scan_entry(scan_dir, report)
    assert not _missing(SCAN_ENTRY_KEYS, entry)


# ── executive summary (drives the scan entry + portfolio + report card) ────────

SUMMARY_KEYS = {
    'risk_level', 'risk_score', 'risk_100', 'metrics', 'risk_factors',
    'key_findings', 'top_findings', 'recommendations',
}
# The metric keys the scan entry / trend series denormalize for cross-scan use.
SUMMARY_METRIC_KEYS = {
    'high', 'medium', 'info', 'secrets', 'weak_cookies', 'source_map_leaks',
    'graphql', 'graphql_introspection', 'attack_surface_score',
}


def test_executive_summary_contract():
    summary = build_summary({'phases': {}})    # empty report → Clean verdict
    assert not _missing(SUMMARY_KEYS, summary)
    assert not _missing(SUMMARY_METRIC_KEYS, summary['metrics'])


# ── findings (DTO → store row → events) ────────────────────────────────────────

FINDING_DTO_KEYS = {'id', 'category', 'rule_id', 'title', 'severity', 'evidence'}
FINDING_ROW_KEYS = {
    'id', 'project', 'category', 'rule_id', 'title', 'severity', 'status',
    'evidence', 'first_seen_at', 'last_seen_at', 'updated_at', 'status_source',
}
FINDING_EVENT_KEYS = {
    'finding_id', 'scan_id', 'type', 'from_status', 'to_status', 'note', 'at',
    'title', 'severity', 'category',
}
FINDINGS_PROJECTS_KEYS = {'project', 'total', 'active'}
FINDINGS_SUMMARY_KEYS = {'total', 'active', 'by_status'}


def test_finding_dto_contract():
    dto = Finding(category='vuln', rule_id='x', title='X', severity='high',
                  location='https://h/p').to_store()
    assert not _missing(FINDING_DTO_KEYS, dto)


def test_finding_store_row_and_events_contract(tmp_path):
    store = FindingsStore(tmp_path / 'findings.db')
    dto = Finding(category='vuln', rule_id='x', title='X', severity='high',
                  location='https://h/p').to_store()
    store.upsert('site.com', dto, scan_id='s1')
    rows = store.list_findings('site.com')
    assert rows and not _missing(FINDING_ROW_KEYS, rows[0])

    events = store.project_events('site.com')
    assert events and not _missing(FINDING_EVENT_KEYS, events[0])

    assert not _missing(FINDINGS_SUMMARY_KEYS, store.summary('site.com'))
    projects = store.projects()
    assert projects and not _missing(FINDINGS_PROJECTS_KEYS, projects[0])
    # Lifecycle vocab is part of the contract (web/GUI status filters bind to it).
    assert {'OPEN', 'FIXED', 'IGNORED', 'FALSE_POSITIVE'} <= set(FINDING_STATUSES)
    assert {'CREATED', 'SEEN', 'STATUS_CHANGED', 'REOPENED'} <= set(FINDING_EVENT_TYPES)


# ── assets (DTO → store row → events) ──────────────────────────────────────────

ASSET_DTO_KEYS = {'id', 'type', 'value', 'label', 'attrs'}
ASSET_ROW_KEYS = {
    'id', 'project', 'type', 'value', 'label', 'attrs', 'status',
    'first_seen_at', 'last_seen_at', 'updated_at',
}
ASSET_EVENT_KEYS = {'asset_id', 'scan_id', 'type', 'at', 'asset_type', 'value',
                    'label'}
ASSETS_PROJECTS_KEYS = {'project', 'total', 'active', 'updated_at'}
ASSETS_SUMMARY_KEYS = {'total', 'active', 'by_type'}


def test_asset_dto_contract():
    dto = Asset(type='subdomain', value='a.site.com').to_store()
    assert not _missing(ASSET_DTO_KEYS, dto)


def test_asset_store_row_and_events_contract(tmp_path):
    store = AssetStore(tmp_path / 'assets.db')
    dto = Asset(type='subdomain', value='a.site.com').to_store()
    store.upsert('site.com', dto, scan_id='s1')
    rows = store.list_assets('site.com')
    assert rows and not _missing(ASSET_ROW_KEYS, rows[0])

    events = store.project_events('site.com')
    assert events and not _missing(ASSET_EVENT_KEYS, events[0])

    assert not _missing(ASSETS_SUMMARY_KEYS, store.summary('site.com'))
    projects = store.projects()
    assert projects and not _missing(ASSETS_PROJECTS_KEYS, projects[0])
    assert {'ACTIVE', 'GONE'} <= set(ASSET_STATUSES)
    assert {'CREATED', 'SEEN', 'GONE', 'REAPPEARED'} <= set(ASSET_EVENT_TYPES)


# ── timeline (series points + change events) ───────────────────────────────────

TIMELINE_KEYS = {'project', 'series', 'events'}
SERIES_POINT_KEYS = {
    'scan_id', 'at', 'risk_score', 'risk_level', 'attack_surface', 'secrets',
    'high', 'medium', 'source_map_leaks', 'weak_cookies', 'graphql',
    'graphql_introspection',
}
TIMELINE_EVENT_KEYS = {'scan_id', 'at', 'type', 'title', 'severity', 'section'}


def test_timeline_series_contract():
    entry = {'id': 's1', 'finished_at': 't', 'risk_score': 1, 'risk_level': 'Low',
             'attack_surface_score': 2, 'secrets': 0, 'high': 0, 'medium': 0,
             'source_map_leaks': 0, 'weak_cookies': 0, 'graphql': 0,
             'graphql_introspection': 0}
    point = build_series([entry])[0]
    assert not _missing(SERIES_POINT_KEYS, point)


def test_timeline_event_contract():
    # An asset CREATED event flows through build_events with the contract shape.
    asset_events = [{'asset_id': 'a', 'scan_id': 's1', 'type': 'CREATED',
                     'at': 't', 'asset_type': 'subdomain', 'value': 'a.site.com',
                     'label': 'a.site.com'}]
    events = build_events([], asset_events=asset_events)
    assert events and not _missing(TIMELINE_EVENT_KEYS, events[0])


# ── report.json (end-to-end, network phases stubbed) ───────────────────────────

REPORT_KEYS = {
    'url', 'domain', 'scan_id', 'started_at', 'finished_at', 'scope',
    'scope_guard', 'phases', 'executive_summary', 'trends', 'status',
    'report_json', 'report_html',
}
SCOPE_GUARD_KEYS = {'rate_limit', 'skipped_active_phases'}

_NETWORK_PHASES = ('_phase_recon', '_phase_api', '_phase_capture', '_phase_clone',
                   '_phase_images', '_phase_cookies', '_phase_vulns')


def test_report_json_contract(tmp_path, monkeypatch):
    """A full collection (network phases stubbed) writes a report.json whose
    top-level keys honour the contract every consumer reads."""
    for name in _NETWORK_PHASES:
        monkeypatch.setattr(CollectionRunner, name,
                            lambda self, *a, **k: {'status': 'ok', 'data': {}})

    report = CollectionRunner().run('https://site.com', str(tmp_path))
    assert not _missing(REPORT_KEYS, report)
    assert not _missing(SCOPE_GUARD_KEYS, report['scope_guard'])

    # The on-disk report.json must carry the same contract (it is what scan_diff /
    # timeline / load_scan_report read back).
    on_disk = json.loads(open(report['report_json'], encoding='utf-8').read())
    assert not _missing(REPORT_KEYS, on_disk)

    # End-to-end: the recorded metadata scan entry honours its contract too.
    entry = ProjectStore(str(tmp_path)).get_or_create('https://site.com').latest_scan()
    assert entry and not _missing(SCAN_ENTRY_KEYS, entry)
