"""Stability tests for the finding fingerprint (core/finding_fingerprint.py).

T1.1 of roadmap F1: the fingerprint is the epic's foundation, so these tests
pin down exactly the properties everything downstream relies on — same issue →
same id across scans, genuinely different issue → different id, and no plaintext
secret ever entering the id. All pure, offline.
"""

import hashlib

from core import finding_fingerprint as ff


# ── the core stability property: same issue, noisy scan → same fingerprint ────

def test_location_is_scheme_query_fragment_slash_stable():
    # The "same resource" seen across scans with transport/query/fragment noise.
    variants = [
        'https://x.com/api/v1/users',
        'http://x.com/api/v1/users',          # http vs https
        'https://x.com/api/v1/users/',        # trailing slash
        'https://x.com/api/v1/users?page=2',  # query string
        'https://X.COM/api/v1/users#section',  # host case + fragment
    ]
    fps = {ff.fingerprint('endpoint', location=v) for v in variants}
    assert len(fps) == 1                      # all collapse to one identity


def test_volatile_fields_do_not_affect_identity():
    # Counts / timestamps / titles are never passed in, so the SAME identity
    # components always yield the SAME fingerprint regardless of them.
    a = ff.fingerprint('header', 'missing-security-headers', 'https://x.com/')
    b = ff.fingerprint('header', 'missing-security-headers', 'https://x.com/')
    assert a == b


def test_distinct_issues_get_distinct_fingerprints():
    base = dict(category='secret', rule_id='aws access key',
                location='https://x.com/app.js', discriminator='aws:AKIA…20')
    fp = ff.fingerprint(**base)
    assert fp != ff.fingerprint(**{**base, 'category': 'sourcemap'})
    assert fp != ff.fingerprint(**{**base, 'rule_id': 'google api key'})
    assert fp != ff.fingerprint(**{**base, 'location': 'https://x.com/other.js'})
    assert fp != ff.fingerprint(**{**base, 'discriminator': 'aws:BKIA…20'})


def test_case_normalization_of_category_and_rule():
    assert ff.fingerprint('SECRET', 'AWS Access Key', 'https://x.com/a') == \
           ff.fingerprint('secret', 'aws access key', 'https://x.com/a')


# ── separator can't be gamed (no concatenation collisions) ───────────────────

def test_field_separator_prevents_collision():
    # ("ab", "c") must not collide with ("a", "bc"): the \x1f separator makes
    # the joined byte-strings distinct.
    assert ff.fingerprint('ab', 'c') != ff.fingerprint('a', 'bc')


# ── secrets: identity without leaking the value ──────────────────────────────

def test_secret_discriminator_never_leaks_plaintext():
    value = 'AKIAIOSFODNN7EXAMPLE'
    disc = ff.secret_discriminator('AWS', value)
    assert value not in disc                  # full value never present
    assert disc.startswith('aws:')            # vendor lower-cased
    assert str(len(value)) in disc            # length encoded


def test_secret_same_value_same_fp_different_value_different_fp():
    loc = 'https://x.com/bundle.js'
    same_a = ff.fingerprint('secret', 'aws access key', loc,
                            ff.secret_discriminator('aws', 'AKIAIOSFODNN7EXAMPLE'))
    same_b = ff.fingerprint('secret', 'aws access key', loc,
                            ff.secret_discriminator('aws', 'AKIAIOSFODNN7EXAMPLE'))
    diff = ff.fingerprint('secret', 'aws access key', loc,
                          ff.secret_discriminator('aws', 'AKIAXXXXXXXXXXXXXXXX'))
    assert same_a == same_b and same_a != diff


def test_mask_value_keeps_only_short_prefix_and_length():
    m = ff.mask_value('0123456789abcdef', keep=6)
    assert m == '012345…16' and '6789abcdef' not in m


# ── determinism / format lock ─────────────────────────────────────────────────

def test_fingerprint_is_40_hex_and_deterministic():
    fp = ff.fingerprint('endpoint', location='https://x.com/a')
    assert len(fp) == 40 and all(c in '0123456789abcdef' for c in fp)


def test_fingerprint_matches_documented_formula():
    # Independently reconstruct the digest from the spec (category|rule lowered,
    # location normalized, fields joined by \x1f) — locks the algorithm so an
    # accidental change to separator/casing/order is caught.
    cat, rule, loc, disc = 'secret', 'AWS Access Key', 'https://x.com/a.js', 'aws:AKIA…20'
    expected = hashlib.sha1('\x1f'.join((
        cat.lower(), rule.lower(), ff.normalize_location(loc), disc,
    )).encode('utf-8')).hexdigest()
    assert ff.fingerprint(cat, rule, loc, disc) == expected


def test_golden_fingerprint_is_stable_across_runs():
    # A hard-coded golden value: this exact issue must keep this exact id forever
    # (a change here means findings would lose their history — intentional only).
    golden = '34dd86e8e47146c7f806c17ee183995a668e6342'
    assert ff.fingerprint(
        'secret', 'AWS Access Key', 'https://X.com/app.js?v=2#frag',
        ff.secret_discriminator('aws', 'AKIAIOSFODNN7EXAMPLE')) == golden


# ── scoped_id: project-scoped storage key (B fix) ──────────────────────────────

def test_scoped_id_is_40_hex_and_deterministic():
    fp = ff.fingerprint('dns', 'spf')
    sid = ff.scoped_id('a.com', fp)
    assert len(sid) == 40 and all(c in '0123456789abcdef' for c in sid)
    assert sid == ff.scoped_id('a.com', fp)        # deterministic


def test_scoped_id_separates_projects_but_keeps_fingerprint_agnostic():
    fp = ff.fingerprint('dns', 'spf')              # location-less → shared fp
    assert ff.scoped_id('a.com', fp) != ff.scoped_id('b.com', fp)
    # The content fingerprint itself stays project-agnostic (unchanged by B).
    assert fp == ff.fingerprint('dns', 'spf')


def test_scoped_id_separator_prevents_collision():
    # ("ab","c") must not collide with ("a","bc") via naive concatenation.
    assert ff.scoped_id('ab', 'c') != ff.scoped_id('a', 'bc')
