"""F1 closing tests (roadmap T1.7) — Findings lifecycle *through CollectionRunner*.

The pure store lifecycle (sync/upsert/sticky/auto-fix scope) is covered in
test_findings_store.py; fingerprint stability in test_finding_fingerprint.py.
This file pins the integration the others can't: the ``_sync_findings`` wiring in
CollectionRunner — auto-FIX gated by *which phase actually ran this scan*, the
nuclei source special-case, and the full triage→stamp→risk-exclusion chain that
makes GUI/web triage (T1.5/T1.6) feed back into the executive summary.

The findings DB is the per-test temp file from conftest's autouse
``_isolate_findings_db`` fixture; everything is offline.
"""

from core.collection_runner import CollectionRunner
from core.executive_summary import build_summary
from core.finding_fingerprint import scoped_id
from core.findings_adapter import from_raw
from core.findings_store import FindingsStore
from core.project import ProjectStore


def _stored_id(project, raw):
    """Scoped store id of a raw finding for ``project`` (rows are keyed by it)."""
    return scoped_id(project.slug, from_raw(raw).id)


def _vulns(findings, status='Success', **summary):
    phase = {'status': status, 'findings': findings}
    if summary:
        phase['summary'] = summary
    return phase


# ── auto-FIX is gated by the source phase succeeding this scan ─────────────────
# (Each branch is its own test with a fresh store: the fingerprint is
# project-agnostic, so a location-less finding shares one id across projects —
# contrasting two projects in one store would collide, not isolate, the cases.)

def _dns():
    return {'title': 'No SPF record', 'severity': 'Medium', 'source': 'dns'}


def test_sync_auto_fixes_absent_finding_when_source_phase_ran(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://a.com')
    r = CollectionRunner()
    fid = _stored_id(p, _dns())
    r._sync_findings({'phases': {'vulns': _vulns([_dns()]),
                                 'dns': {'status': 'Success'}}}, p, 's1')
    # Gone, and the DNS phase ran again → absence is real → auto-FIXED.
    r._sync_findings({'phases': {'vulns': _vulns([]),
                                 'dns': {'status': 'Success'}}}, p, 's2')
    assert FindingsStore().get(fid)['status'] == 'FIXED'


def test_sync_keeps_absent_finding_open_when_source_phase_skipped(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://a.com')
    r = CollectionRunner()
    fid = _stored_id(p, _dns())
    r._sync_findings({'phases': {'vulns': _vulns([_dns()]),
                                 'dns': {'status': 'Success'}}}, p, 's1')
    # Gone, but the DNS phase did NOT run → can't claim it's fixed → stays OPEN.
    r._sync_findings({'phases': {'vulns': _vulns([])}}, p, 's2')
    assert FindingsStore().get(fid)['status'] == 'OPEN'


def _nuclei():
    return {'title': 'CVE-2021-1234 exposed', 'severity': 'High', 'source': 'nuclei'}


def test_sync_auto_fixes_nuclei_finding_when_nuclei_enabled(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://a.com')
    r = CollectionRunner(nuclei=True)
    fid = _stored_id(p, _nuclei())
    r._sync_findings({'phases': {'vulns': _vulns([_nuclei()])}}, p, 's1')
    r._sync_findings({'phases': {'vulns': _vulns([])}}, p, 's2')
    assert FindingsStore().get(fid)['status'] == 'FIXED'


def test_sync_keeps_nuclei_finding_open_when_nuclei_disabled(tmp_path):
    # vulns succeeds, but nuclei didn't run this scan → its findings can't be
    # auto-FIXED just because they're absent from a scan that didn't look.
    p = ProjectStore(tmp_path).get_or_create('https://a.com')
    fid = _stored_id(p, _nuclei())
    CollectionRunner(nuclei=True)._sync_findings(
        {'phases': {'vulns': _vulns([_nuclei()])}}, p, 's1')
    CollectionRunner(nuclei=False)._sync_findings(
        {'phases': {'vulns': _vulns([])}}, p, 's2')
    assert FindingsStore().get(fid)['status'] == 'OPEN'


# ── triage → stamp → risk exclusion (the point of F1) ─────────────────────────

def test_user_triage_stamps_next_scan_and_drops_from_risk(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://x.com')
    raw = {'title': 'Weak Content-Security-Policy', 'severity': 'Medium'}
    r = CollectionRunner()
    r._sync_findings(
        {'phases': {'vulns': _vulns([dict(raw)], high=0, medium=1, info=0,
                                    risk_score=4)}}, p, 's1')

    # User marks it IGNORED (exactly what the GUI tab / POST /findings/{id}/status do).
    fid = _stored_id(p, raw)
    FindingsStore().set_status(fid, 'IGNORED', source='user')

    # Next scan: the issue is still present → _sync_findings stamps the stored
    # status onto the report's finding (sticky: not reopened).
    report2 = {'phases': {'vulns': _vulns([dict(raw)], high=0, medium=1, info=0,
                                          risk_score=4)}}
    r._sync_findings(report2, p, 's2')
    stamped = report2['phases']['vulns']['findings'][0]
    assert stamped['status'] == 'IGNORED'
    assert FindingsStore().get(fid)['status'] == 'IGNORED'   # stayed sticky

    # The risk engine reads that stamp and drops the finding.
    summary = build_summary(report2)
    assert summary['metrics']['medium'] == 0


# ── reopen flows back into the report stamp ────────────────────────────────────

def test_reopened_finding_is_stamped_open_in_report(tmp_path):
    p = ProjectStore(tmp_path).get_or_create('https://x.com')
    raw = {'title': 'Site served over plain HTTP', 'severity': 'High'}
    r = CollectionRunner()
    fid = _stored_id(p, raw)

    r._sync_findings({'phases': {'vulns': _vulns([dict(raw)])}}, p, 's1')
    r._sync_findings({'phases': {'vulns': _vulns([])}}, p, 's2')    # gone → FIXED
    assert FindingsStore().get(fid)['status'] == 'FIXED'

    report3 = {'phases': {'vulns': _vulns([dict(raw)])}}            # reappears
    r._sync_findings(report3, p, 's3')
    assert FindingsStore().get(fid)['status'] == 'OPEN'            # REOPENED
    assert report3['phases']['vulns']['findings'][0]['status'] == 'OPEN'
