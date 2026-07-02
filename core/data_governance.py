"""Sensitive Data Governance for client-facing reports (Roadmap E9).

A render-time safety net that guarantees no raw secret or credential value
reaches a client-facing deliverable, even if an upstream field was populated
with plaintext. Findings are already masked at capture/store time
(:func:`core.finding_fingerprint.mask_value`, ``document_intelligence``,
``findings_store``); this layer is defense-in-depth *at the report boundary*.

Design
------
- Pure and offline. No new dependencies, no I/O, no network, no state.
- Reuses the single sources of truth instead of a second detector/masker:
  detection is :data:`core.secret_scanner.RULES`; masking is
  :func:`core.finding_fingerprint.mask_value` (``prefix…len`` — preserves the
  vendor/type prefix and length as context while dropping the secret body).
- Non-destructive: operates on copies and only rewrites string content. It does
  not change stored evidence, finding identities, counts, or severities.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.finding_fingerprint import mask_value
from core.secret_scanner import RULES


# Key-name markers whose *string* values are masked wholesale (mirrors the
# vocabulary scrubbed by ``core.crash_reporter._redact``). Non-string values
# (ints/bools) are never masked, so false friends like ``match_count`` or
# ``auth_context: true`` are unaffected.
_SENSITIVE_MARKERS = (
    "password", "passwd", "pwd", "secret", "token", "authorization",
    "api_key", "apikey", "private_key", "credential", "cookie", "match",
    "plaintext", "raw_value",
)
# Key names that contain a marker as a substring but are not sensitive.
_KEY_FALSE_FRIENDS = frozenset({"author", "authors", "tokens_total"})


def is_sensitive_key(key: Any) -> bool:
    """True when a mapping key's string value should be masked wholesale."""
    name = str(key).strip().lower()
    if name in _KEY_FALSE_FRIENDS:
        return False
    return any(marker in name for marker in _SENSITIVE_MARKERS)


def _mask_in_match(match, group: int) -> str:
    """Replace only the secret portion of a regex match, keeping context.

    Contextual rules (``Bearer <tok>``, ``api_key="<v>"``) capture the value in
    a group; we mask just that span so the surrounding label survives.
    """
    whole = match.group(0)
    value = match.group(group) if group else whole
    if not value:
        return whole
    masked = mask_value(value)
    if group:
        start = match.start(group) - match.start(0)
        end = match.end(group) - match.start(0)
        return whole[:start] + masked + whole[end:]
    return masked


def redact_text(text: Any) -> Any:
    """Mask any embedded secret in ``text`` using the shared rule set.

    Non-strings pass through unchanged. Rules run in sequence; a value masked by
    one rule (``prefix…len``) no longer matches later rules, so the pass is
    stable and idempotent.
    """
    if not isinstance(text, str) or not text:
        return text
    out = text
    for rule in RULES:
        out = rule.pattern.sub(lambda m, g=rule.group: _mask_in_match(m, g), out)
    return out


def redact_data(obj: Any) -> Any:
    """Recursively redact strings inside a nested dict/list structure.

    A string under a sensitive key is masked wholesale; every other string is
    scanned for embedded secrets. Structure, keys, numbers and booleans are
    preserved.
    """
    if isinstance(obj, dict):
        out: Dict[Any, Any] = {}
        for key, value in obj.items():
            if isinstance(value, str) and is_sensitive_key(key):
                out[key] = mask_value(value) if value else value
            else:
                out[key] = redact_data(value)
        return out
    if isinstance(obj, list):
        return [redact_data(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_data(item) for item in obj)
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def redact_finding(finding: Any) -> Any:
    """Governed copy of one finding dict (raw values masked, structure intact)."""
    if not isinstance(finding, dict):
        return finding
    return redact_data(finding)


def govern_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Governed copies of a list of finding rows, ready for client rendering."""
    return [redact_finding(row) for row in rows or []]
