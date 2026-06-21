"""Tests for the findings adapter (core/findings_adapter.py, F1 T1.3).

Maps the pipeline's flat scanner findings to the unified Finding DTO with a
stable fingerprint. Pure / offline.
"""

from core import findings_adapter as fa
from core.finding_fingerprint import fingerprint


# ── severity normalization ────────────────────────────────────────────────────

def test_normalize_severity():
    assert fa.normalize_severity('High') == 'high'
    assert fa.normalize_severity('Informational') == 'info'
    assert fa.normalize_severity('warning') == 'medium'
    assert fa.normalize_severity('CRITICAL') == 'critical'
    assert fa.normalize_severity('weird') == 'info'      # unknown → info


# ── category classification ───────────────────────────────────────────────────

def test_category_from_source_map():
    assert fa.from_raw({'title': 't', 'source': 'dns'}).category == 'dns'
    assert fa.from_raw({'title': 't', 'source': 'dependency-audit'}).category \
        == 'dependency'
    assert fa.from_raw({'title': 't', 'source': 'nuclei'}).category == 'vuln'


def test_category_from_title_keyword_and_default():
    assert fa.from_raw({'title': "Weakly protected cookie: sid"}).category \
        == 'cookie'
    assert fa.from_raw({'title': 'Missing security headers (3)'}).category \
        == 'header'
    assert fa.from_raw({'title': 'Something unrecognised'}).category == 'vuln'


def test_explicit_fields_win():
    f = fa.from_raw({'title': 'x', 'source': 'dns', 'category': 'custom',
                     'rule_id': 'my-rule', 'location': 'https://h/p',
                     'discriminator': 'd'})
    assert f.category == 'custom' and f.rule_id == 'my-rule'
    assert f.location == 'h/p' and f.discriminator == 'd'


def test_knowledge_fields_carried_into_evidence():
    # F-O2: producer-supplied description/impact/remediation persist in evidence.
    f = fa.from_raw({'title': 'x', 'severity': 'high', 'category': 'vuln',
                     'description': 'A flaw', 'remediation': 'Patch'})
    assert f.description == 'A flaw' and f.remediation == 'Patch'
    ev = f.to_store()['evidence']
    assert ev['description'] == 'A flaw' and ev['remediation'] == 'Patch'
    assert 'impact' not in ev                 # empty fields dropped by to_store


def test_knowledge_fields_absent_by_default():
    ev = fa.from_raw({'title': 'x', 'severity': 'low'}).to_store()['evidence']
    assert not any(k in ev for k in ('description', 'impact', 'remediation'))


def test_cwe_carried_into_evidence_and_normalized():
    # A producer's explicit CWE(s) persist in evidence, normalized to CWE-NNN and
    # de-duplicated; non-CWE junk is dropped.
    f = fa.from_raw({'title': 'x', 'severity': 'high', 'source': 'nuclei',
                     'cwe': ['cwe-79', 'CWE-79', 'NVD-CWE-noinfo', '']})
    assert f.cwe == ['CWE-79']
    assert f.to_store()['evidence']['cwe'] == ['CWE-79']
    # A single string is tolerated too.
    assert fa.from_raw({'title': 'x', 'cwe': 'CWE-89'}).cwe == ['CWE-89']


def test_cwe_absent_by_default():
    ev = fa.from_raw({'title': 'x', 'severity': 'low'}).to_store()['evidence']
    assert 'cwe' not in ev


# ── rule_id stability (the identity property) ────────────────────────────────

def test_evidence_refs_carried_into_store_evidence_safely():
    raw = {
        'title': 'Leaked secret',
        'severity': 'High',
        'source': 'secret',
        'evidence_refs': [
            {'artifact_id': 'sha256:abc', 'path': 'api/api_keys.json',
             'phase': 'api', 'extra': {'nested': 'drop'}},
            {'artifact_id': '', 'path': 'bad.json', 'phase': 'api'},
            'not-a-ref',
        ],
    }

    ev = fa.from_raw(raw).to_store()['evidence']

    assert ev['evidence_refs'] == [{
        'artifact_id': 'sha256:abc',
        'path': 'api/api_keys.json',
        'phase': 'api',
    }]


def test_volatile_counts_do_not_fork_identity():
    a = fa.from_raw({'severity': 'Medium', 'title': 'Missing security headers (3)',
                     'detail': 'csp'})
    b = fa.from_raw({'severity': 'Medium', 'title': 'Missing security headers (5)',
                     'detail': 'hsts'})
    assert a.rule_id == b.rule_id == 'missing-security-headers'
    assert a.id == b.id                                   # same finding


def test_distinct_titles_get_distinct_ids():
    a = fa.from_raw({'title': 'Weak Content-Security-Policy'})
    b = fa.from_raw({'title': 'HSTS max-age too short'})
    assert a.id != b.id


# ── location extraction (host/scheme stable) ─────────────────────────────────

def test_location_extracted_and_normalized():
    f = fa.from_raw({'title': 'Sensitive path pattern detected: /admin',
                     'detail': 'https://X.com/admin/panel?x=1'})
    assert f.location == 'x.com/admin/panel'              # scheme/query dropped


def test_no_location_is_host_level():
    assert fa.from_raw({'title': 'No SPF record', 'source': 'dns'}).location == ''


# ── secrets: distinct keys stay distinct, no plaintext leaks ─────────────────

def _secret(key, preview, url='https://x.com/api'):
    return {'severity': 'High',
            'title': 'Secret exposed in API response [JWT]',
            'detail': f"key='{key}'  =>  '{preview}'  |  {url}"}


def test_secret_discriminator_distinguishes_keys():
    a = fa.from_raw(_secret('token', 'eyJabc…120'))
    b = fa.from_raw(_secret('other', 'eyJzzz…99'))
    same = fa.from_raw(_secret('token', 'eyJabc…120'))
    assert a.category == 'secret'
    assert a.discriminator == 'token:eyJabc…120'
    assert a.id != b.id                                   # different key → distinct
    assert a.id == same.id                                # identical → same


def test_secret_without_parseable_detail_falls_back():
    f = fa.from_raw({'title': 'Secret exposed in API response [JWT]',
                     'severity': 'High', 'detail': 'opaque'})
    assert f.category == 'secret' and f.discriminator == ''   # graceful


# ── DTO contract ──────────────────────────────────────────────────────────────

def test_id_matches_fingerprint_of_components():
    f = fa.from_raw({'title': 'Weak Content-Security-Policy', 'detail': 'x'})
    assert f.id == fingerprint(f.category, f.rule_id, f.location, f.discriminator)


def test_to_store_shape_and_masked_evidence():
    store = fa.from_raw(_secret('tok', 'eyJ…120')).to_store()
    assert set(store) == {'id', 'category', 'rule_id', 'title', 'severity',
                          'evidence'}
    assert store['severity'] == 'high'
    assert store['evidence']['location'] == 'x.com/api'


# ── normalize() dedups by identity ───────────────────────────────────────────

def test_normalize_dedups_by_fingerprint():
    out = fa.normalize([
        {'title': 'Missing security headers (3)', 'severity': 'Medium'},
        {'title': 'Missing security headers (9)', 'severity': 'Medium'},  # same id
        {'title': 'Weak Content-Security-Policy', 'severity': 'Medium'},
    ])
    assert len(out) == 2
    assert {f.rule_id for f in out} == {'missing-security-headers',
                                        'weak-content-security-policy'}
