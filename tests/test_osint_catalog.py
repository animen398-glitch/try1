"""Offline tests for the AI-OSINT Workflow Catalog (EXT-OSINT F3 T3.2)."""

from core import osint_catalog as oc


def test_catalog_returns_copy_with_required_fields():
    cat = oc.catalog()
    assert len(cat) == len(oc.WORKFLOWS) >= 10
    for wf in cat:
        for key in ('id', 'name', 'category', 'goal', 'engines', 'optional',
                    'produces', 'network'):
            assert key in wf
        assert wf['network'] in ('passive', 'active')
        assert wf['engines']                      # at least one required engine
    # mutating the copy does not touch the module constant
    cat[0]['name'] = 'mutated'
    assert oc.WORKFLOWS[0]['name'] != 'mutated'


def test_catalog_ids_unique():
    ids = [wf['id'] for wf in oc.WORKFLOWS]
    assert len(ids) == len(set(ids))


def test_every_engine_token_is_mapped():
    # No workflow may reference an engine token the resolver cannot interpret.
    for wf in oc.WORKFLOWS:
        for eng in wf['engines'] + wf['optional']:
            assert eng in oc._ENGINE_PHASE, eng


def test_assess_covered_partial_not_run():
    # infrastructure-recon needs recon/subdomains/ct/asn_intel/infrastructure.
    report = {'phases': {
        'recon': {'status': 'Success'},
        'subdomains': {'status': 'Success'},
        'ct': {'status': 'Success'},
        'asn_intel': {'status': 'Success'},
    }}
    by_id = {wf['id']: wf for wf in oc.assess(report)}
    infra = by_id['infrastructure-recon']
    # 'infrastructure' resolves to the recon phase → covered when recon ran
    assert infra['status'] == 'covered' and infra['missing'] == []
    # email-people-surface had no phases run → not_run
    assert by_id['email-people-surface']['status'] == 'not_run'


def test_assess_partial_when_some_engines_run():
    report = {'phases': {'subdomains': {'status': 'Success'}}}  # ct/dns absent
    sub = next(w for w in oc.assess(report)
               if w['id'] == 'subdomain-takeover-surface')
    assert sub['status'] == 'partial'
    assert 'subdomains' in sub['ran'] and 'ct' in sub['missing']


def test_assess_platform_capability_always_present():
    # continuous-monitoring's engines (monitor/timeline/scan_diff) map to None
    # (platform capabilities) → always covered, even with an empty report.
    mon = next(w for w in oc.assess({}) if w['id'] == 'continuous-monitoring')
    assert mon['status'] == 'covered' and mon['missing'] == []


def test_assess_optional_ran_tracked():
    report = {'phases': {'recon': {'status': 'Success'},
                         'subdomains': {'status': 'Success'},
                         'ct': {'status': 'Success'},
                         'asn_intel': {'status': 'Success'},
                         'bbot': {'status': 'Success'}}}
    infra = next(w for w in oc.assess(report)
                 if w['id'] == 'infrastructure-recon')
    assert 'bbot' in infra['optional_ran']


def test_assess_ignores_failed_phase():
    report = {'phases': {'documents': {'status': 'Error'}}}
    doc = next(w for w in oc.assess(report) if w['id'] == 'document-intelligence')
    assert doc['status'] == 'not_run'


def test_available_uses_injected_detectors():
    avail = oc.available(detectors={'bbot': lambda: True, 'lift': lambda: False,
                                    'pdf-text': lambda: True, 'ocr': lambda: False})
    assert avail == {'bbot': True, 'lift': False, 'pdf-text': True, 'ocr': False}


def test_summary_counts():
    report = {'phases': {'recon': {'status': 'Success'},
                         'subdomains': {'status': 'Success'},
                         'ct': {'status': 'Success'},
                         'asn_intel': {'status': 'Success'}}}
    s = oc.summary(report)
    assert s['total'] == len(oc.WORKFLOWS)
    assert s['covered'] + s['partial'] + s['not_run'] == s['total']
    # no report → catalog size only, zero coverage
    empty = oc.summary()
    assert empty['total'] == len(oc.WORKFLOWS) and empty['covered'] == 0
