"""core/cert_info.py
Fetch and summarise a host's served TLS certificate (stdlib ssl/socket only).

A single TLS handshake retrieves the certificate; parsing is pure. No external
service, no extra dependency (architectural invariant I1). The point is to
record *what certificate a host serves* so Scan Diff can show when it changes
between scans — a renewal (new validity window / serial / fingerprint), an
issuer change, or a different SAN set — which are meaningful security signals.

The network call (``fetch_certificate``) is isolated from the pure summariser
(``summarize_cert``) so the latter is unit-testable without a socket (I5).
"""

import hashlib
import socket
import ssl
from typing import Dict, Optional, Tuple


def _flatten_name(rdn_seq) -> Dict[str, str]:
    """Flatten getpeercert()'s nested subject/issuer RDN structure to a dict."""
    out: Dict[str, str] = {}
    for rdn in rdn_seq or ():
        for pair in rdn:
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                out[str(pair[0])] = str(pair[1])
    return out


def _name_str(rdn_seq) -> str:
    d = _flatten_name(rdn_seq)
    cn = d.get('commonName')
    org = d.get('organizationName')
    if cn and org and org != cn:
        return f'{cn} ({org})'
    return cn or org or '—'


def summarize_cert(parsed: Optional[Dict], der: Optional[bytes] = None) -> Optional[Dict]:
    """Build a flat, comparable cert summary from a parsed cert dict + DER bytes.

    Pure (no network). Returns ``None`` when there is nothing usable. Fields:
    ``subject, issuer, not_before, not_after, serial, sans, fingerprint_sha256``.
    """
    out: Dict[str, str] = {}
    if der:
        out['fingerprint_sha256'] = hashlib.sha256(der).hexdigest()
    if parsed:
        if parsed.get('subject'):
            out['subject'] = _name_str(parsed['subject'])
        if parsed.get('issuer'):
            out['issuer'] = _name_str(parsed['issuer'])
        if parsed.get('notBefore'):
            out['not_before'] = str(parsed['notBefore'])
        if parsed.get('notAfter'):
            out['not_after'] = str(parsed['notAfter'])
        if parsed.get('serialNumber'):
            out['serial'] = str(parsed['serialNumber'])
        sans = sorted(v for k, v in parsed.get('subjectAltName', ())
                      if k == 'DNS')
        if sans:
            out['sans'] = ', '.join(sans)
    return out or None


def _handshake(host: str, port: int, timeout: float,
               verify: bool) -> Tuple[Optional[Dict], Optional[bytes]]:
    """One TLS handshake → (parsed-cert-or-empty, DER-bytes). Raises on failure."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        # Report the served cert even when it wouldn't validate (self-signed,
        # expired, hostname mismatch) — we are inspecting, not trusting.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return (ssock.getpeercert() or {}), ssock.getpeercert(binary_form=True)


def fetch_certificate(host: str, port: int = 443,
                      timeout: float = 6.0) -> Optional[Dict]:
    """Retrieve and summarise ``host``'s TLS certificate, or ``None`` on failure.

    Tries a verifying handshake first (rich parsed fields); on any failure falls
    back to an unverified handshake to still capture the DER fingerprint of a
    self-signed/expired cert. Never raises — a transport failure yields ``None``.
    """
    parsed: Optional[Dict] = {}
    der: Optional[bytes] = None
    try:
        parsed, der = _handshake(host, port, timeout, verify=True)
    except Exception:
        try:
            parsed, der = _handshake(host, port, timeout, verify=False)
        except Exception:
            return None
    return summarize_cert(parsed, der)
