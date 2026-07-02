"""Tests for core.secret_scanner — the shared credential detector."""

from core.secret_scanner import SecretScanner, scan_text


def _types(findings):
    return {f["type"] for f in findings}


def test_detects_known_vendor_formats():
    text = (
        "const a='AKIA1234567890ABCD56';"
        "var g='AIzaSyA1234567890abcdefghijklmnopqrstuv';"
        "stripe='sk_live_abcdefghijklmnopqrstuvwx';"
        "gh='ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';"
    )
    types = _types(scan_text(text))
    assert "AWS Access Key" in types
    assert "Google API Key" in types
    assert "Stripe Secret" in types
    assert "GitHub Token" in types


def test_jwt_and_private_key_block():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123_-signaturepart"
    pem = "-----BEGIN RSA PRIVATE KEY-----"
    types = _types(scan_text(f"token={jwt}\n{pem}"))
    assert "JWT" in types
    assert "Private Key Block" in types


def test_contextual_assignment_captures_only_value():
    findings = scan_text('api_key = "AbCdEf0123456789ghij"')
    assert len(findings) == 1
    assert findings[0]["type"] == "Generic API Key"
    assert findings[0]["match"] == "AbCdEf0123456789ghij"  # value, not the whole line


def test_dedups_repeated_value_and_attaches_source():
    key = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    findings = scan_text(f"{key} {key} {key}", source="app.js")
    assert len(findings) == 1
    assert findings[0]["source"] == "app.js"


def test_preview_is_truncated_for_long_values():
    key = "ghp_" + "b" * 60
    f = scan_text(key)[0]
    assert "…" in f["preview"]
    assert key not in f["preview"]            # the secret body is never exposed
    assert f["preview"].startswith("ghp_b")   # short vendor/prefix only
    assert f["preview"].endswith(str(len(key)))  # length suffix keeps identity entropy
    assert len(f["preview"]) <= 12            # short mask, not a long slice


def test_detects_harvested_secretfinder_formats():
    text = (
        "g='ya29.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';"
        "stripe='rk_live_abcdefghijklmnopqrstuvwx';"
        "sq='sq0csp-" + "a" * 43 + "';"
        "pb='access_token$production$0123456789abcdef$0123456789abcdef0123456789abcdef';"
        "tw='AC0123456789abcdef0123456789abcdef';"
        "gh='https://user:p4ssword@github.com/x';"
    )
    types = _types(scan_text(text))
    assert "Google OAuth Token" in types
    assert "Stripe Restricted Key" in types
    assert "Square OAuth Secret" in types
    assert "PayPal/Braintree Token" in types
    assert "Twilio Account SID" in types
    assert "GitHub URL Credentials" in types


def test_detects_modern_provider_keys():
    openai = "sk-" + "A1b2C3d4E5f6G7h8I9j0"          # 20 body chars
    gitlab = "glpat-" + "aB3dE5gH7jK9mN1pQ3sT"
    hf = "hf_" + "a" * 34
    text = f"o='{openai}';g='{gitlab}';h='{hf}';"
    types = _types(scan_text(text))
    assert {"OpenAI API Key", "GitLab PAT", "Hugging Face Token"} <= types


def test_anthropic_prefix_wins_over_openai():
    # ``sk-ant-…`` must be reported as the more specific Anthropic type, not
    # swallowed by the broader OpenAI ``sk-`` rule (order + value-dedup).
    key = "sk-ant-api03-" + "Z9y8X7w6V5u4T3s2R1q0"
    findings = scan_text(key)
    assert len(findings) == 1
    assert findings[0]["type"] == "Anthropic API Key"
    assert findings[0]["match"] == key


def test_stripe_underscore_not_matched_by_openai_rule():
    # OpenAI uses ``sk-`` (hyphen); Stripe uses ``sk_live_`` (underscore) — the
    # OpenAI rule must not claim a Stripe key.
    types = _types(scan_text("sk_live_" + "a" * 24))
    assert "OpenAI API Key" not in types
    assert "Stripe Secret" in types


def test_clean_text_yields_nothing():
    assert scan_text("just some perfectly ordinary prose, nothing secret here") == []
    assert SecretScanner().scan_text("") == []


def test_non_str_input_degrades_not_raises():
    # The SSOT entry point is fed corpus by several engines; a non-str blob
    # (bytes from a fetch, a JSON number/object) must yield [] rather than crash
    # re.finditer (F-SR1 degrade-not-raise).
    for bad in (b"AKIA1234567890ABCD56", 12345, {"a": 1}, [1, 2], 3.14):
        assert scan_text(bad) == []
    # scan_many tolerates a non-str text element while still scanning the rest.
    out = SecretScanner().scan_many([
        (b"AKIA1234567890ABCD56", "bytes.js"),
        ("AKIA1234567890ABCD56", "good.js"),
    ])
    assert len(out) == 1 and out[0]["source"] == "good.js"


def test_scan_many_flattens_and_keeps_sources():
    scanner = SecretScanner()
    out = scanner.scan_many([
        ("AKIA1234567890ABCD56", "a.js"),
        ("nothing here", "b.js"),
    ])
    assert len(out) == 1 and out[0]["source"] == "a.js"
