"""Project workspace — slug, store, scan indexing and history (offline)."""

import json

from core.project import ProjectStore, project_slug


# ── project_slug ────────────────────────────────────────────────────────────

def test_project_slug_normalizes():
    assert project_slug('https://www.Example.com/path') == 'Example.com'
    assert project_slug('http://sub.example.org:8080') == 'sub.example.org_8080'
    assert project_slug('not a url') == 'not_a_url'


def test_collection_domain_slug_delegates_to_project():
    # The collection runner alias must stay in lock-step (single source).
    from core.collection_runner import _domain_slug
    assert _domain_slug('https://www.Example.com/x') == project_slug(
        'https://www.Example.com/x')


# ── ProjectStore.get_or_create ──────────────────────────────────────────────

def test_get_or_create_builds_skeleton(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create('https://example.com')
    assert p.root == tmp_path / 'Projects' / 'example.com'
    for sub in ('scans', 'reports', 'screenshots', 'exports', 'history'):
        assert (p.root / sub).is_dir()
    meta = p.load_metadata()
    assert meta['slug'] == 'example.com'
    assert meta['url'] == 'https://example.com'
    assert meta['scan_count'] == 0


def test_get_or_create_is_idempotent_and_keeps_scans(tmp_path):
    store = ProjectStore(tmp_path)
    p = store.get_or_create('https://example.com')
    scan_dir = p.start_scan('20260613_120000')
    p.record_scan(scan_dir, {'url': 'https://example.com', 'status': 'Success',
                             'executive_summary': {'risk_level': 'Low',
                                                   'risk_score': 3}})
    # Re-opening the same project must not wipe its metadata.
    p2 = store.get_or_create('https://example.com')
    assert p2.load_metadata()['scan_count'] == 1


# ── scan indexing ───────────────────────────────────────────────────────────

def _report(url='https://example.com', level='High', score=12, metrics=None):
    return {
        'url': url, 'status': 'Success',
        'started_at': '2026-06-13T12:00:00', 'finished_at': '2026-06-13T12:01:00',
        'report_html': '/x/report.html', 'report_json': '/x/report.json',
        'executive_summary': {'risk_level': level, 'risk_score': score,
                              'metrics': metrics or {'secrets': 1, 'high': 2,
                                                     'medium': 3,
                                                     'attack_surface_score': 16}},
    }


def test_record_scan_updates_metadata_and_history(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://example.com')
    scan_dir = p.start_scan('20260613_120000')
    entry = p.record_scan(scan_dir, _report())

    assert entry['id'] == '20260613_120000'
    assert entry['dir'] == 'scans/20260613_120000'
    assert entry['risk_level'] == 'High'
    assert entry['attack_surface_score'] == 16

    meta = p.load_metadata()
    assert meta['scan_count'] == 1
    assert meta['latest_scan']['id'] == '20260613_120000'

    # A per-scan history snapshot is written.
    hist = json.loads((p.root / 'history' / '20260613_120000.json')
                      .read_text(encoding='utf-8'))
    assert hist['risk_score'] == 12


def test_record_scan_is_idempotent_on_same_id(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://example.com')
    scan_dir = p.start_scan('20260613_120000')
    p.record_scan(scan_dir, _report(level='Low', score=1))
    p.record_scan(scan_dir, _report(level='High', score=12))   # re-run, same id
    meta = p.load_metadata()
    assert meta['scan_count'] == 1                 # not duplicated
    assert meta['latest_scan']['risk_level'] == 'High'   # latest wins


def test_multiple_scans_sorted_and_latest_tracked(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://example.com')
    for stamp in ('20260613_090000', '20260613_120000', '20260613_100000'):
        p.record_scan(p.start_scan(stamp), _report())
    meta = p.load_metadata()
    ids = [s['id'] for s in meta['scans']]
    assert ids == sorted(ids)                      # chronological
    assert meta['latest_scan']['id'] == '20260613_120000'  # newest id
    assert meta['scan_count'] == 3


# ── ProjectStore listing ────────────────────────────────────────────────────

def test_list_projects_and_get(tmp_path):
    store = ProjectStore(tmp_path)
    store.get_or_create('https://a.com')
    store.get_or_create('https://b.com')
    slugs = {m['slug'] for m in store.list_projects()}
    assert slugs == {'a.com', 'b.com'}
    assert store.get('a.com') is not None
    assert store.get('nope.com') is None


def test_load_metadata_tolerates_corruption(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://example.com')
    p.metadata_path.write_text('{ broken', encoding='utf-8')
    meta = p.load_metadata()        # falls back to a fresh metadata dict
    assert meta['scan_count'] == 0
