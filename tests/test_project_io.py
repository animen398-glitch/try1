"""core/project_io.py — project export/import bundle round-trip (offline).

Seeds a project (tree + findings/assets lifecycle slice), exports it to a zip,
imports into a *separate* workspace + fresh DBs, and asserts both the tree and
the lifecycle (ids/status/remediation/events) survive faithfully — proving an
imported project is self-sufficient. Also covers skip/replace, the zip-slip
guard and bundle_info. Explicit db_paths keep it off the global stores.
"""
import json
import zipfile

import pytest

from core import project_io
from core.asset_adapter import Asset
from core.asset_store import AssetStore
from core.audit_store import AuditRunStore
from core.audit_workflow import advance_audit_phase, create_audit_run
from core.findings_store import FindingsStore
from core.project import ProjectStore
from core.remediation import set_task


def _seed(base, fdb, adb, audit_db=None, slug_url='https://shop.io'):
    store = ProjectStore(str(base))
    proj = store.get_or_create(slug_url)
    slug = proj.slug
    scan_dir = proj.start_scan('20260101_000000')
    report = {'scan_id': '20260101_000000', 'finished_at': '20260101_000000',
              'executive_summary': {'risk_level': 'High', 'risk_score': 70,
                                    'risk_100': 70, 'metrics': {'risk_100': 70}}}
    (scan_dir / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    proj.record_scan(scan_dir, report)

    fs = FindingsStore(db_path=fdb)
    fs.sync(slug, 's1', [
        {'category': 'vuln', 'rule_id': 'idor', 'title': 'IDOR', 'severity': 'high',
         'location': 'https://shop.io/cart'},
        {'category': 'headers', 'rule_id': 'hsts', 'title': 'No HSTS',
         'severity': 'medium', 'location': 'https://shop.io'},
    ])
    fid = fs.list_findings(slug)[0]['id']
    # find the idor finding id deterministically
    fid = [r['id'] for r in fs.list_findings(slug) if r['rule_id'] == 'idor'][0]
    set_task(fs, fid, status='in_progress', owner='alice', due='2026-02-01')

    AssetStore(db_path=adb).sync(slug, 's1',
                                 [Asset('domain', 'shop.io'),
                                  Asset('ip', '198.51.100.5')])
    if audit_db:
        run = create_audit_run(slug, phases=['validation'], run_id='audit-shop')
        run = advance_audit_phase(run, 'validation', {'validated_findings': []})
        audits = AuditRunStore(db_path=audit_db)
        audits.save_run(run, now='2026-01-01T10:00:00')
        audits.record_event(
            'audit-shop',
            'quality_gate_passed',
            phase='risk_business_impact',
            finding_id=fid,
            at='2026-01-01T10:01:00',
        )
    return slug, fid


# ── round-trip ──────────────────────────────────────────────────────────────

def test_export_then_import_restores_tree_and_lifecycle(tmp_path):
    src = tmp_path / 'src'
    src_f, src_a = src / 'findings.db', src / 'assets.db'
    src_audit = src / 'audit_runs.db'
    slug, fid = _seed(src, src_f, src_a, src_audit)

    bundle = tmp_path / 'shop.io.zip'
    out = project_io.export_project(src, slug, bundle,
                                    findings_db=src_f, assets_db=src_a,
                                    audit_db=src_audit)
    assert bundle.exists()
    assert out['findings'] == 2 and out['assets'] == 2 and out['scans'] == 1
    assert out['audit_runs'] == 1 and out['audit_events'] == 1

    # fresh, empty destination
    dst = tmp_path / 'dst'
    dst_f, dst_a = dst / 'findings.db', dst / 'assets.db'
    dst_audit = dst / 'audit_runs.db'
    res = project_io.import_project(bundle, dst,
                                    findings_db=dst_f, assets_db=dst_a,
                                    audit_db=dst_audit)
    assert res['skipped'] is False
    assert res['findings'] == 2 and res['assets'] == 2
    assert res['audit_runs'] == 1 and res['audit_events'] == 1

    # tree restored
    proj = ProjectStore(str(dst)).get(slug)
    assert proj is not None
    report = json.loads((proj.root / 'scans' / '20260101_000000'
                         / 'report.json').read_text('utf-8'))
    assert report['executive_summary']['risk_score'] == 70

    # findings lifecycle faithful: same id + status, remediation preserved
    rows = {r['id']: r for r in FindingsStore(db_path=dst_f).list_findings(slug)}
    assert fid in rows
    assert FindingsStore(db_path=dst_f).get_remediation(fid)['owner'] == 'alice'
    # assets restored
    assert len(AssetStore(db_path=dst_a).list_assets(slug)) == 2
    # audit runs restored
    audits = AuditRunStore(db_path=dst_audit)
    assert audits.get_run('audit-shop')['project'] == slug
    assert audits.events('audit-shop')[0]['finding_id'] == fid


def test_import_preserves_status_and_timestamps(tmp_path):
    src = tmp_path / 'src'
    src_f, src_a = src / 'findings.db', src / 'assets.db'
    slug, fid = _seed(src, src_f, src_a)
    before = [r for r in FindingsStore(db_path=src_f).list_findings(slug)
              if r['id'] == fid][0]

    bundle = tmp_path / 'b.zip'
    project_io.export_project(src, slug, bundle, findings_db=src_f, assets_db=src_a)
    dst = tmp_path / 'dst'
    dst_f = dst / 'findings.db'
    project_io.import_project(bundle, dst, findings_db=dst_f, assets_db=dst / 'a.db')

    dst_store = FindingsStore(db_path=dst_f)
    after = [r for r in dst_store.list_findings(slug) if r['id'] == fid][0]
    # lifecycle status + timestamps copied verbatim (status is the finding's own
    # OPEN — the remediation task status lives separately and is checked below).
    assert after['status'] == before['status']
    assert after['first_seen_at'] == before['first_seen_at']
    assert after['updated_at'] == before['updated_at']
    # the remediation task (a REMEDIATION event) travelled with the slice.
    assert dst_store.get_remediation(fid)['status'] == 'in_progress'


def test_export_import_restores_missions(tmp_path):
    from core import pentest_mission as pm
    from core.mission_store import MissionStore

    src = tmp_path / 'src'
    src_f, src_a, src_m = src / 'findings.db', src / 'assets.db', src / 'missions.db'
    slug, _fid = _seed(src, src_f, src_a)
    mission = pm.create_mission(slug, 'Authorized external review',
                                allowed_actions=['headers_check'])
    MissionStore(src_m).save_mission(mission, now='2026-01-01T09:00:00')

    bundle = tmp_path / 'b.zip'
    out = project_io.export_project(src, slug, bundle, findings_db=src_f,
                                    assets_db=src_a, missions_db=src_m)
    assert out['missions'] == 1

    dst = tmp_path / 'dst'
    dst_m = dst / 'missions.db'
    res = project_io.import_project(bundle, dst, findings_db=dst / 'f.db',
                                    assets_db=dst / 'a.db', missions_db=dst_m)
    assert res['missions'] == 1
    restored = MissionStore(dst_m).get_mission(mission['mission_id'])
    assert restored is not None
    assert restored['payload'] == mission                 # canonical, verbatim
    assert restored['created_at'] == '2026-01-01T09:00:00'


def test_import_tolerates_bundle_without_missions(tmp_path):
    """An older bundle (predating missions.json) imports cleanly with 0 missions."""
    import zipfile

    src = tmp_path / 'src'
    slug, _fid = _seed(src, src / 'f.db', src / 'a.db')
    bundle = tmp_path / 'b.zip'
    project_io.export_project(src, slug, bundle, findings_db=src / 'f.db',
                              assets_db=src / 'a.db')

    legacy = tmp_path / 'legacy.zip'
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(legacy, 'w') as zout:
        for item in zin.namelist():
            if item != 'missions.json':                   # strip the new member
                zout.writestr(item, zin.read(item))

    dst = tmp_path / 'dst'
    res = project_io.import_project(legacy, dst, findings_db=dst / 'f.db',
                                    assets_db=dst / 'a.db', missions_db=dst / 'm.db')
    assert res['skipped'] is False
    assert res['missions'] == 0                           # absent section → empty


# ── skip / replace ────────────────────────────────────────────────────────────

def test_import_skips_existing_without_replace(tmp_path):
    src = tmp_path / 'src'
    src_f, src_a = src / 'findings.db', src / 'assets.db'
    slug, _ = _seed(src, src_f, src_a)
    bundle = tmp_path / 'b.zip'
    project_io.export_project(src, slug, bundle, findings_db=src_f, assets_db=src_a)

    dst = tmp_path / 'dst'
    dst_f, dst_a = dst / 'findings.db', dst / 'assets.db'
    project_io.import_project(bundle, dst, findings_db=dst_f, assets_db=dst_a)
    again = project_io.import_project(bundle, dst, findings_db=dst_f, assets_db=dst_a)
    assert again['skipped'] is True and again['reason'] == 'project exists'


def test_import_replace_overwrites(tmp_path):
    src = tmp_path / 'src'
    src_f, src_a = src / 'findings.db', src / 'assets.db'
    slug, _ = _seed(src, src_f, src_a)
    bundle = tmp_path / 'b.zip'
    project_io.export_project(src, slug, bundle, findings_db=src_f, assets_db=src_a)

    dst = tmp_path / 'dst'
    dst_f, dst_a = dst / 'findings.db', dst / 'assets.db'
    project_io.import_project(bundle, dst, findings_db=dst_f, assets_db=dst_a)
    res = project_io.import_project(bundle, dst, findings_db=dst_f, assets_db=dst_a,
                                    replace=True)
    assert res['skipped'] is False and res['findings'] == 2
    # no duplication after replace
    assert len(FindingsStore(db_path=dst_f).list_findings(slug)) == 2


# ── safety / errors ─────────────────────────────────────────────────────────────

def test_export_unknown_project_raises(tmp_path):
    with pytest.raises(KeyError):
        project_io.export_project(tmp_path, 'ghost.io', tmp_path / 'x.zip')


def test_import_rejects_zip_slip(tmp_path):
    bad = tmp_path / 'evil.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(
            {'format_version': 1, 'slug': 'evil.io'}))
        zf.writestr('project/../../escape.txt', 'pwned')
    with pytest.raises(ValueError):
        project_io.import_project(bad, tmp_path / 'dst')


@pytest.mark.parametrize('slug', ['../escape', '/tmp/escape', r'C:\escape'])
def test_import_rejects_unsafe_manifest_slug(tmp_path, slug):
    bad = tmp_path / 'evil-slug.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(
            {'format_version': 1, 'slug': slug}))
        zf.writestr('project/metadata.json', '{}')
    with pytest.raises(ValueError):
        project_io.import_project(bad, tmp_path / 'dst')


def test_import_rejects_non_object_manifest(tmp_path):
    bad = tmp_path / 'list-manifest.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(['not', 'an', 'object']))
    with pytest.raises(ValueError):
        project_io.import_project(bad, tmp_path / 'dst')


def test_import_rejects_missing_manifest_slug(tmp_path):
    bad = tmp_path / 'missing-slug.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps({'format_version': 1}))
    with pytest.raises(ValueError):
        project_io.import_project(bad, tmp_path / 'dst')


def test_import_rejects_wrong_format(tmp_path):
    bad = tmp_path / 'old.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(
            {'format_version': 99, 'slug': 'x.io'}))
    with pytest.raises(ValueError):
        project_io.import_project(bad, tmp_path / 'dst')


def test_bundle_info_reads_manifest(tmp_path):
    src = tmp_path / 'src'
    src_f, src_a = src / 'findings.db', src / 'assets.db'
    slug, _ = _seed(src, src_f, src_a)
    bundle = tmp_path / 'b.zip'
    project_io.export_project(src, slug, bundle, findings_db=src_f, assets_db=src_a)
    info = project_io.bundle_info(bundle)
    assert info['slug'] == slug and info['format_version'] == 1
    assert project_io.bundle_info(tmp_path / 'nope.zip') is None


def test_bundle_info_rejects_unsafe_preview_manifest(tmp_path):
    bad = tmp_path / 'evil-preview.zip'
    with zipfile.ZipFile(bad, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(
            {'format_version': 1, 'slug': '../escape'}))
    assert project_io.bundle_info(bad) is None
