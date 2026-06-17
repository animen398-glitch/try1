"""core/finding_fingerprint.py
Stable finding identity — Findings Management foundation (roadmap F1, task T1.1).

This is the single most important decision of the ASM 2.0 epic: a deterministic
fingerprint that is identical for "the same" issue across scans. Everything that
follows depends on it — findings deduplicate instead of piling up, their
lifecycle (OPEN → IN_PROGRESS → FIXED / IGNORED …) sticks to the right record,
and Timeline / Alerts can tell what is *genuinely new* rather than re-firing on
every scan.

    fingerprint = sha1( category ␟ rule_id ␟ normalized_location ␟ discriminator )

Design rules (why each field is shaped this way):
  * Host-stable — ``normalized_location`` runs through the existing
    ``utils.endpoint_index.EndpointIndex.normalize`` (drops fragment + query,
    lowercases scheme/host, trims a trailing slash). The same resource on
    http vs https, or with different query strings, is therefore ONE finding.
  * Count/time-stable — only identity-bearing fields enter. Volatile data
    (occurrence counts, timestamps, "(3 found)" suffixes) must never be passed
    in, so a finding keeps its identity when those wiggle between scans.
  * No plaintext secrets — a secret's discriminator is ``vendor + masked prefix
    + length``, never the value (the same non-leak rule Scan Diff / reports
    already follow). Two different keys of one vendor at one location still get
    distinct fingerprints via their masked prefix/length.
  * Collision-safe joining — fields are separated by an ASCII Unit Separator
    (``\\x1f``), which cannot appear in a normalized URL or a rule id, so
    ``("a", "b")`` can never collide with ``("a" , "b")`` joined naively.

Pure and stdlib-only (architectural invariants I1/I5): no network, no DB — the
``EndpointIndex.normalize`` reuse is a pure string transform.
"""

import hashlib
from typing import Optional
from urllib.parse import urlsplit

from utils.endpoint_index import EndpointIndex

# Canonical category vocabulary (the ``category`` component). Not a closed set —
# callers may pass another string — but these are the values the per-scanner
# adapters (T1.3) will emit, kept here as the single reference list.
CATEGORIES = (
    'secret', 'sourcemap', 'cookie', 'graphql', 'header', 'tech',
    'endpoint', 'dns', 'dependency', 'takeover', 'vuln',
)

# ASCII Unit Separator — a non-printing control char that never occurs in a
# normalized URL, rule id or our masked discriminators, so joined components
# are unambiguous.
_SEP = '\x1f'


def normalize_location(value: Optional[str]) -> str:
    """Canonical, host-stable location for a finding (URL or path), or ''.

    Delegates to ``EndpointIndex.normalize`` (drops query/fragment/trailing
    slash, lowercases scheme+host) and then drops the scheme to ``host/path`` so
    the same resource fingerprints identically on http vs https — finding
    identity is the resource, not the transport. Host-level findings (no
    specific resource) pass ``None``/``''`` → ``''``.
    """
    norm = EndpointIndex.normalize(value or '')
    parts = urlsplit(norm)
    if parts.scheme:
        return f'{parts.netloc}{parts.path}'
    return norm


def mask_value(value: str, keep: int = 6) -> str:
    """A non-leaking token for a secret: short prefix + length, never the full
    value (mirrors the masking used in Scan Diff / reports)."""
    s = str(value or '')
    return f'{s[:keep]}…{len(s)}'


def secret_discriminator(vendor: str, secret_value: str) -> str:
    """Discriminator for a secret finding: ``vendor:maskedprefix…len``.

    Distinguishes two different keys of the same vendor at the same location
    WITHOUT persisting the plaintext value anywhere in the fingerprint input."""
    return f'{str(vendor).strip().lower()}:{mask_value(secret_value)}'


def fingerprint(category: str, rule_id: str = '', location: str = '',
                discriminator: str = '') -> str:
    """Stable SHA-1 identity for a finding from its identity components.

    Only identity-bearing fields enter — never counts, timestamps or raw secret
    values. ``category``/``rule_id`` are lower-cased and stripped; ``location``
    is normalized; ``discriminator`` is passed through stripped (it may carry a
    case-significant masked prefix). Returns the full 40-char hex digest, used
    directly as the findings-table primary key.
    """
    parts = (
        str(category).strip().lower(),
        str(rule_id).strip().lower(),
        normalize_location(location),
        str(discriminator).strip(),
    )
    return hashlib.sha1(_SEP.join(parts).encode('utf-8')).hexdigest()


def scoped_id(project: str, fingerprint: str) -> str:
    """Project-scoped storage key for a finding row.

    The :func:`fingerprint` is *content* identity and is deliberately
    project-agnostic, so two projects can share one fingerprint for an issue
    that has no URL location (a DNS / host-level finding). The findings store,
    however, must keep those as distinct rows — its identity is the pair
    ``(project, fingerprint)``. This folds that pair into one stable 40-hex key
    (same format as ``fingerprint``), so the store's single-column ``id`` stays a
    drop-in primary key without changing any read/write signature.
    """
    return hashlib.sha1(
        f'{str(project)}{_SEP}{str(fingerprint)}'.encode('utf-8')).hexdigest()
