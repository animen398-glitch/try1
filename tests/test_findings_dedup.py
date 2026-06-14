"""Tests for cross-scanner CVE dedup in core/findings_adapter.py (Phase B)."""

from core import findings_adapter as fa


def test_extract_cve_from_various_fields():
    assert fa.extract_cve({'cve': 'CVE-2020-11022'}) == 'CVE-2020-11022'
    assert fa.extract_cve({'cve': ['CVE-2021-23337', 'GHSA-x']}) == 'CVE-2021-23337'
    assert fa.extract_cve({'discriminator': 'CVE-2019-11358'}) == 'CVE-2019-11358'
    assert fa.extract_cve({'title': 'Vuln lib jQuery (cve-2020-11023)'}) == 'CVE-2020-11023'
    assert fa.extract_cve({'detail': 'template CVE-2021-26855 at /x'}) == 'CVE-2021-26855'
    # GHSA-only advisory has no CVE → not merged.
    assert fa.extract_cve({'discriminator': 'GHSA-gxr4-xjj5-5px2'}) is None
    assert fa.extract_cve({'title': 'Missing HSTS header'}) is None


def test_same_cve_different_scanners_share_identity():
    nuclei = {'severity': 'High', 'title': 'CVE-2020-11022', 'source': 'nuclei',
              'detail': 'CVE-2020-11022 at https://x.com'}
    osv = {'severity': 'Medium', 'title': 'Уязвимая библиотека: jQuery 3.4.1 (CVE-2020-11022)',
           'source': 'dependency-audit', 'discriminator': 'CVE-2020-11022',
           'detail': 'OSV/GHSA-.. at https://x.com'}
    a, b = fa.from_raw(nuclei), fa.from_raw(osv)
    assert a.category == 'vuln' and a.rule_id == 'cve-2020-11022'
    assert a.id == b.id                      # same CVE + location → one identity


def test_different_location_distinct():
    one = {'title': 'CVE-2020-11022', 'detail': 'https://a.com/app.js'}
    two = {'title': 'CVE-2020-11022', 'detail': 'https://b.com/app.js'}
    assert fa.from_raw(one).id != fa.from_raw(two).id


def test_non_cve_identity_unchanged():
    # A header finding must keep its existing (non-CVE) identity — regression guard.
    raw = {'title': 'Missing security headers', 'source': 'vuln',
           'detail': 'https://x.com'}
    f = fa.from_raw(raw)
    assert f.category == 'header'
    assert f.rule_id == 'missing-security-headers'


def test_normalize_accumulates_sources():
    raws = [
        {'title': 'CVE-2020-11022', 'source': 'nuclei', 'detail': 'https://x.com'},
        {'title': 'jQuery CVE-2020-11022', 'source': 'dependency-audit',
         'detail': 'https://x.com'},
    ]
    out = fa.normalize(raws)
    assert len(out) == 1                     # collapsed to one
    assert set(out[0].sources) == {'nuclei', 'dependency-audit'}
    store = out[0].to_store()
    assert set(store['evidence']['sources']) == {'nuclei', 'dependency-audit'}


def test_dedup_findings_collapses_and_keeps_first_display():
    raws = [
        {'title': 'CVE-2020-11022 (nuclei wording)', 'severity': 'High',
         'source': 'nuclei', 'detail': 'https://x.com'},
        {'title': 'CVE-2020-11022 (osv wording)', 'severity': 'Medium',
         'source': 'dependency-audit', 'detail': 'https://x.com'},
        {'title': 'Missing HSTS', 'source': 'vuln', 'detail': 'https://x.com'},
    ]
    out = fa.dedup_findings(raws)
    assert len(out) == 2                      # 2 CVE dupes → 1, + the HSTS one
    cve = [f for f in out if 'CVE' in f['title']][0]
    assert cve['title'] == 'CVE-2020-11022 (nuclei wording)'   # first wins
    assert set(cve['sources']) == {'nuclei', 'dependency-audit'}


def test_dedup_findings_noop_when_unique():
    raws = [{'title': 'A', 'source': 'x', 'detail': 'https://x.com'},
            {'title': 'B', 'source': 'y', 'detail': 'https://x.com'}]
    assert len(fa.dedup_findings(raws)) == 2
