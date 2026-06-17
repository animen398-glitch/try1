"""Canonical HTTP security-header vocabulary — the single source of truth.

A tiny, dependency-free constant shared by the recon engine (which classifies a
response's security headers from this set) and Scan Diff (which surfaces a
dropped security header as a regression). Kept here, not in recon_engine, so the
pure/offline diff can read it without pulling recon's heavy import chain.

Names are lowercase to match how recon stores them (``security_headers`` keys are
lowercased), so membership checks need no further normalisation.
"""

SECURITY_HEADER_NAMES = frozenset({
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
})
