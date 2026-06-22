"""Canonical HTTP security-header vocabulary — the single source of truth.

A tiny, dependency-free constant shared by the recon engine (which classifies a
response's security headers from this set), Scan Diff (which surfaces a dropped
security header as a regression) and the vuln scanner (which flags the missing
ones). Kept here, not in recon_engine, so the pure/offline diff can read it
without pulling recon's heavy import chain.

Names are lowercase to match how recon stores them (``security_headers`` keys are
lowercased), so membership checks need no further normalisation.
"""

# Canonical order (used where order matters — e.g. the vuln scanner's "missing
# security headers: …" detail list). The frozenset below is derived from it, so
# there is exactly ONE list to maintain: adding a header here updates the recon /
# diff membership checks and the vuln scanner's expected-set together.
SECURITY_HEADERS = (
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
)

SECURITY_HEADER_NAMES = frozenset(SECURITY_HEADERS)
