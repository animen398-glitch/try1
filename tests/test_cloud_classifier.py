"""core/cloud_classifier.py — pure, offline cloud classification."""

from core.cloud_classifier import classify_cloud


# ── provider / ASN-name keyword ────────────────────────────────────────────────

def test_classify_by_provider_keyword():
    out = classify_cloud(provider='Amazon.com, Inc.', asn_name='Amazon')
    assert out['cloud'] == 'AWS' and out['confidence'] == 80
    assert 'provider' in out['evidence']


def test_classify_cloudflare_provider():
    out = classify_cloud(provider='Cloudflare, Inc.')
    assert out['cloud'] == 'Cloudflare'


# ── exact ASN number outranks a keyword ────────────────────────────────────────

def test_classify_by_asn_number_is_highest_confidence():
    out = classify_cloud(asn='AS16509')
    assert out['cloud'] == 'AWS' and out['confidence'] == 90
    assert out['evidence'] == 'ASN AS16509'


def test_asn_case_insensitive():
    assert classify_cloud(asn='as15169')['cloud'] == 'Google Cloud'


# ── CDN technology signal ──────────────────────────────────────────────────────

def test_classify_by_cdn_technology():
    out = classify_cloud(technologies=[{'name': 'Amazon CloudFront',
                                        'category': 'CDN'}])
    assert out['cloud'] == 'AWS' and out['confidence'] == 75


def test_classify_by_plain_technology_string():
    out = classify_cloud(technologies=['Cloudflare'])
    assert out['cloud'] == 'Cloudflare'


# ── CNAME signal (per-subdomain) ───────────────────────────────────────────────

def test_classify_by_cname():
    out = classify_cloud(cname='myapp.azurewebsites.net')
    assert out['cloud'] == 'Microsoft Azure' and out['confidence'] == 70


def test_classify_by_s3_cname():
    assert classify_cloud(cname='bucket.s3.amazonaws.com')['cloud'] == 'AWS'


# ── unknown stays unknown (no guessing) ────────────────────────────────────────

def test_no_signal_returns_empty():
    assert classify_cloud() == {}
    assert classify_cloud(provider='Some Tiny ISP Ltd') == {}
    assert classify_cloud(asn='AS99999') == {}


# ── strongest signal wins ──────────────────────────────────────────────────────

def test_asn_beats_keyword_when_both_present():
    # An AWS ASN with a misleading provider string still resolves via the ASN.
    out = classify_cloud(provider='Amazon', asn='AS16509')
    assert out['confidence'] == 90 and out['cloud'] == 'AWS'


def test_tolerates_none_and_bad_types():
    assert classify_cloud(provider=None, asn_name=None, technologies=None) == {}
    assert classify_cloud(technologies=[None, {'no_name': 1}]) == {}
