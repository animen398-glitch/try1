"""TLS certificate summary — pure parsing (no socket) + collection phase."""

from core.cert_info import summarize_cert


_PARSED = {
    'subject': ((('commonName', 'example.com'),),),
    'issuer': ((('organizationName', "Let's Encrypt"),),
               (('commonName', 'R3'),)),
    'notBefore': 'May  1 00:00:00 2026 GMT',
    'notAfter': 'Aug  1 00:00:00 2026 GMT',
    'serialNumber': 'AABBCC',
    'subjectAltName': (('DNS', 'example.com'), ('DNS', 'www.example.com')),
}


# ── summarize_cert (pure) ────────────────────────────────────────────────────

def test_summarize_extracts_fields():
    out = summarize_cert(_PARSED, der=b'\x30\x82')
    assert out['subject'] == 'example.com'
    assert out['issuer'] == 'R3 (Let\'s Encrypt)'
    assert out['not_before'].startswith('May')
    assert out['not_after'].startswith('Aug')
    assert out['serial'] == 'AABBCC'
    assert out['sans'] == 'example.com, www.example.com'
    # DER → a stable SHA-256 fingerprint.
    assert len(out['fingerprint_sha256']) == 64


def test_summarize_der_only_gives_fingerprint():
    out = summarize_cert({}, der=b'abc')
    assert set(out) == {'fingerprint_sha256'}


def test_summarize_empty_is_none():
    assert summarize_cert(None, None) is None
    assert summarize_cert({}, None) is None


def test_summarize_handles_missing_san():
    out = summarize_cert({'subject': ((('commonName', 'x'),),)})
    assert out['subject'] == 'x'
    assert 'sans' not in out


# ── collection phase ─────────────────────────────────────────────────────────

def test_phase_certificate_skipped_for_http(tmp_path):
    from core.collection_runner import CollectionRunner
    phase = CollectionRunner(certificate=True)._phase_certificate(
        'http://x.com', tmp_path)
    assert phase['status'] == 'Skipped'           # not https → no handshake


def test_phase_certificate_success_with_stubbed_fetch(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'fetch_certificate',
                        lambda host, port=443: {'subject': 'x.com',
                                                'issuer': 'CA',
                                                'fingerprint_sha256': 'f' * 64})
    phase = cr.CollectionRunner(certificate=True)._phase_certificate(
        'https://x.com', tmp_path)
    assert phase['status'] == 'Success'
    assert phase['data']['subject'] == 'x.com'
    assert (tmp_path / 'security' / 'certificate.json').exists()


def test_phase_certificate_error_when_no_cert(tmp_path, monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'fetch_certificate', lambda host, port=443: None)
    phase = cr.CollectionRunner(certificate=True)._phase_certificate(
        'https://x.com', tmp_path)
    assert phase['status'] == 'Error'


def test_default_collection_has_certificate_off():
    from core.collection_runner import CollectionRunner
    assert CollectionRunner().certificate is False
