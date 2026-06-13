"""Offline structural secret validation — format only, never any network."""

from core.secret_validator import (
    INVALID, UNVERIFIABLE, VALID, summarize, validate,
)


# ── exact-format types ──────────────────────────────────────────────────────

def test_aws_key_exact_format():
    assert validate('AWS Access Key', 'AKIAIOSFODNN7EXAMPLE')['status'] == VALID
    # Wrong length / lowercase → invalid.
    assert validate('AWS Access Key', 'AKIAshort')['status'] == INVALID
    assert validate('AWS Access Key', 'AKIAiosfodnn7example')['status'] == INVALID


def test_twilio_sid_hex_only():
    assert validate('Twilio Account SID',
                    'AC' + 'a' * 32)['status'] == VALID
    assert validate('Twilio Account SID',
                    'AC' + 'Z' * 32)['status'] == INVALID   # non-hex


def test_stripe_prefix_and_length():
    assert validate('Stripe Secret', 'sk_live_' + 'a' * 24)['status'] == VALID
    assert validate('Stripe Secret', 'sk_live_short')['status'] == INVALID


# ── JWT: real base64url + JSON header decode ────────────────────────────────

def test_jwt_valid_header_decodes_to_json_with_alg():
    # header {"alg":"HS256","typ":"JWT"} base64url, dummy payload+sig.
    jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
           'eyJzdWIiOiIxIn0.c2ln')
    out = validate('JWT', jwt)
    assert out['status'] == VALID
    assert 'HS256' in out['reason']


def test_jwt_invalid_when_header_not_json():
    # 'eyJ' prefix but the header segment isn't valid JSON.
    bad = 'eyJabcdefgh.payload.sig'
    assert validate('JWT', bad)['status'] == INVALID


def test_jwt_invalid_segment_count():
    assert validate('JWT', 'eyJabc.def')['status'] == INVALID


# ── Authorization Basic: decode to user:pass ────────────────────────────────

def test_basic_decodes_to_user_pass():
    import base64
    token = base64.b64encode(b'admin:s3cr3t').decode()
    assert validate('Authorization Basic', f'Basic {token}')['status'] == VALID


def test_basic_invalid_without_colon():
    import base64
    token = base64.b64encode(b'noseparator').decode()
    assert validate('Authorization Basic', f'Basic {token}')['status'] == INVALID


# ── generic contextual keys: placeholder / entropy demotion ─────────────────

def test_generic_placeholder_is_invalid():
    assert validate('Generic API Key',
                    'your_api_key_here')['status'] == INVALID
    assert validate('Generic Secret', 'changeme123456789')['status'] == INVALID


def test_generic_low_diversity_is_invalid():
    assert validate('Generic API Key', 'aaaaaaaaaaaaaaaaaa')['status'] == INVALID


def test_generic_plausible_key_is_valid():
    # High-entropy, mixed-case+digits, no sequential run → plausible real key.
    out = validate('Generic API Key', 'k3Jx9mQ2pV7nLw8aZ4bR')
    assert out['status'] == VALID


# ── unknown types & robustness ──────────────────────────────────────────────

def test_unknown_type_is_unverifiable():
    assert validate('Private Key Block',
                    '-----BEGIN PRIVATE KEY-----')['status'] == UNVERIFIABLE


def test_validate_never_raises_on_garbage():
    for v in (None, '', '\x00\x01', '...'):
        out = validate('JWT', v)               # must return, not raise
        assert out['status'] in (VALID, INVALID, UNVERIFIABLE)


# ── summarize ───────────────────────────────────────────────────────────────

def test_summarize_counts_by_status():
    findings = [
        {'validation': {'status': VALID}},
        {'validation': {'status': VALID}},
        {'validation': {'status': INVALID}},
        {},                                     # missing → unverifiable
    ]
    s = summarize(findings)
    assert s[VALID] == 2 and s[INVALID] == 1 and s[UNVERIFIABLE] == 1


# ── integration: scan_text attaches validation ──────────────────────────────

def test_scan_text_attaches_validation():
    from core.secret_scanner import scan_text
    findings = scan_text('AKIAIOSFODNN7EXAMPLE')
    assert findings[0]['validation']['status'] == VALID

    placeholder = scan_text('api_key = "your_api_key_here00"')
    assert placeholder[0]['validation']['status'] == INVALID


# ── GUI: Security Audit table shows the Format column (headless) ─────────────

def test_security_tab_shows_format_column(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    assert "Format" in w.SECRET_COLUMNS
    w._populate_secret_table([
        {'type': 'AWS Access Key', 'preview': 'AKIA…', 'source': 'app.js',
         'validation': {'status': VALID, 'reason': 'ок'}},
        {'type': 'Generic API Key', 'preview': 'your…', 'source': 'app.js',
         'validation': {'status': INVALID, 'reason': 'плейсхолдер'}},
    ])
    fmt_col = w.SECRET_COLUMNS.index('Format')
    assert w.security_table.rowCount() == 2
    assert '✓' in w.security_table.item(0, fmt_col).text()
    assert '✗' in w.security_table.item(1, fmt_col).text()
