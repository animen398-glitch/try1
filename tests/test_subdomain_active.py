"""Tests for the active subdomain takeover classifier (network-free)."""

from core.subdomain_active import TAKEOVER_SIGNATURES, classify


def test_takeover_flagged_when_cname_and_fingerprint_match():
    v = classify(
        ["user.github.io"],
        "<html><body>There isn't a GitHub Pages site here.</body></html>",
    )
    assert v["takeover"] is True
    assert v["service"] == "GitHub Pages"
    assert v["cname_matched"] is True
    assert v["fingerprint_matched"]


def test_cname_match_without_fingerprint_is_not_takeover():
    # CNAME points at GitHub Pages but the site is actually served — not vuln.
    v = classify(["user.github.io"], "<html><title>My real blog</title></html>")
    assert v["service"] == "GitHub Pages"
    assert v["cname_matched"] is True
    assert v["takeover"] is False
    assert v["fingerprint_matched"] is None


def test_no_known_cname_is_clean():
    v = classify(["something.internal.example.com"], "No such app")
    assert v["service"] is None
    assert v["cname_matched"] is False
    assert v["takeover"] is False


def test_heroku_no_such_app():
    v = classify(["app.herokudns.com"], "<h1>No such app</h1>")
    assert v["service"] == "Heroku"
    assert v["takeover"] is True


def test_s3_nosuchbucket():
    v = classify(
        ["bucket.s3.amazonaws.com"],
        "<Error><Code>NoSuchBucket</Code></Error>",
    )
    assert v["service"] == "AWS S3"
    assert v["takeover"] is True


def test_empty_inputs():
    v = classify([], "")
    assert v == {"service": None, "cname_matched": False,
                 "fingerprint_matched": None, "takeover": False}


def test_signature_table_shape():
    for sig in TAKEOVER_SIGNATURES:
        assert sig["service"] and sig["cnames"] and sig["fingerprints"]
        assert all(isinstance(c, str) for c in sig["cnames"])
