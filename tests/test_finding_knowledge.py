"""Finding knowledge catalog (core/finding_knowledge.py, Epic F-O1) — offline."""

from core.finding_knowledge import FIELDS, annotate, describe


def test_describe_per_category_defaults():
    info = describe('cookie')
    assert set(info) == set(FIELDS)
    assert 'Secure' in info['remediation']
    assert all(info[f] for f in FIELDS)        # no empty field


def test_describe_unknown_category_falls_back_to_generic():
    info = describe('totally-unknown')
    assert 'лучшим практикам' in info['remediation']


def test_rule_specific_overrides_category_default():
    # HSTS specific refines the header category's remediation.
    info = describe('header', rule_id='hsts', title='HSTS missing')
    assert 'Strict-Transport-Security' in info['remediation']
    # Other fields still come from the header category default.
    assert info['impact'] == describe('header')['impact']


def test_explicit_evidence_wins_over_catalog():
    info = describe('vuln', rule_id='x', title='y',
                    evidence={'remediation': 'Upgrade to 2.0'})
    assert info['remediation'] == 'Upgrade to 2.0'   # producer text wins
    assert info['description']                        # other fields still filled


def test_explicit_blank_is_ignored():
    info = describe('cookie', evidence={'remediation': '   '})
    assert info['remediation'] == describe('cookie')['remediation']


def test_annotate_injects_fields_in_place():
    rows = [{'category': 'secret', 'rule_id': 'aws', 'title': 'AWS key'},
            'not-a-dict']
    out = annotate(rows)
    assert out is rows
    assert all(f in rows[0] for f in FIELDS)
    assert 'ротируйте' in rows[0]['remediation']
