"""core/secret_scanner.py

Native-Python secret/credential detection — the single source of truth for
"does this text contain an API key, token or private key". Replaces the two
regex sets that had drifted apart (``api_key_extractor.KEY_PATTERNS`` and
``dynamic_analyzer._SECRET_PATTERNS``) with one curated, precision-first list,
so every consumer (dynamic analysis, source-map inspection, the Security Audit
tab) flags the same things the same way.

Design notes:
  • Pure and dependency-free (just ``re``): safe to call from a background
    worker thread — no Qt, no network, no global state.
  • Precision over recall: patterns target *known* credential shapes (vendor
    prefixes, PEM blocks, JWTs) plus a couple of conservative contextual rules
    (``secret = "…"``). High-entropy guessing is deliberately avoided to keep
    false positives low on minified JS.
  • Findings are de-duplicated by matched value so a key repeated across a
    bundle is reported once per source.
"""

import re
from typing import Dict, List, NamedTuple, Pattern, Tuple

from core.secret_validator import validate as validate_secret


class SecretRule(NamedTuple):
    """One detection rule: a human label and a compiled pattern.

    ``group`` selects which capture group holds the secret value (0 = whole
    match). Contextual rules (``api_key = "<value>"``) capture the value in
    group 1 so the surrounding assignment is not reported as the secret.
    """
    name: str
    pattern: Pattern
    group: int = 0


# Curated, precision-first rule set. Order is irrelevant (all rules run); names
# are stable identifiers used by the UI and reports.
RULES: List[SecretRule] = [
    SecretRule('JWT',              re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    SecretRule('AWS Access Key',   re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    SecretRule('Google API Key',   re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    SecretRule('Stripe Secret',    re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')),
    SecretRule('Stripe Publishable', re.compile(r'\bpk_live_[0-9a-zA-Z]{24,}\b')),
    SecretRule('Stripe Test Key',  re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b')),
    SecretRule('GitHub Token',     re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b')),
    SecretRule('GitHub Fine-grained PAT', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,}\b')),
    SecretRule('Slack Token',      re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')),
    SecretRule('Slack Webhook',    re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]{40,}')),
    SecretRule('Twilio SID Key',   re.compile(r'\bSK[0-9a-fA-F]{32}\b')),
    SecretRule('Mailgun Key',      re.compile(r'\bkey-[0-9a-zA-Z]{32}\b')),
    SecretRule('SendGrid Key',     re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b')),
    SecretRule('npm Token',        re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    SecretRule('Stripe Restricted Key', re.compile(r'\brk_live_[0-9a-zA-Z]{24,}\b')),
    SecretRule('Google OAuth Token', re.compile(r'\bya29\.[0-9A-Za-z_\-]{20,}')),
    SecretRule('AWS MWS Token',    re.compile(
        r'\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')),
    SecretRule('PayPal/Braintree Token', re.compile(
        r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')),
    SecretRule('Square OAuth Secret', re.compile(r'\bsq0csp-[0-9A-Za-z_\-]{43}\b')),
    SecretRule('Square Access Token', re.compile(r'\bsqOatp-[0-9A-Za-z_\-]{22}\b')),
    SecretRule('Twilio Account SID', re.compile(r'\bAC[0-9a-f]{32}\b')),
    SecretRule('GitHub URL Credentials', re.compile(
        r'[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@github\.com')),
    SecretRule('Authorization Basic', re.compile(r'\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}')),
    SecretRule('Bearer Token',     re.compile(r'\bBearer\s+([A-Za-z0-9._~+/=\-]{20,})'), group=1),
    SecretRule('Private Key Block', re.compile(
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')),
    # Conservative contextual rules: an explicit key/secret assignment with a
    # quoted value long enough to be real. Group 1 is the value.
    SecretRule('Generic API Key', re.compile(
        r'(?i)\bapi[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'), group=1),
    SecretRule('Generic Secret', re.compile(
        r'(?i)\b(?:secret|client[_-]?secret|access[_-]?token|auth[_-]?token)'
        r'\s*[:=]\s*["\']([A-Za-z0-9_\-./+=]{16,})["\']'), group=1),
]


def _preview(value: str, keep: int = 6) -> str:
    """Short, non-leaking preview of a matched secret for display: at most the
    first ``keep`` characters (the vendor/prefix — enough to identify the key)
    plus an ellipsis, never the secret body. Mirrors the masking level of
    ``finding_fingerprint.mask_value`` (keep=6)."""
    return value[:keep] + '…' if len(value) > keep else value


class SecretScanner:
    """Scans arbitrary text (HTML, JS, JSON strings) for credentials.

    Stateless and thread-safe: a single instance can be shared across workers,
    or callers can use the module-level :func:`scan_text` convenience.
    """

    def __init__(self, rules: List[SecretRule] = RULES):
        self.rules = rules

    def scan_text(self, text: str, source: str = '') -> List[Dict]:
        """Return findings ``{type, match, preview, source}`` for ``text``.

        De-duplicates by matched value so the same key appearing many times in
        one blob is reported once. ``source`` (a URL or file path) is attached
        to every finding for drill-down.
        """
        # Degrade, never raise (F-SR1): this is the shared SSOT entry point, fed
        # corpus by several engines — a non-str blob (bytes from a fetch, a JSON
        # number) must yield no findings rather than crash re.finditer.
        if not isinstance(text, str) or not text:
            return []
        findings: List[Dict] = []
        seen: set = set()
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                value = m.group(rule.group) if rule.group else m.group(0)
                if not value or value in seen:
                    continue
                seen.add(value)
                findings.append({
                    'type': rule.name,
                    'match': value,
                    'preview': _preview(value),
                    'source': source,
                    # Offline structural format check (no network) — demotes
                    # placeholders/truncated values, confirms exact shapes.
                    'validation': validate_secret(rule.name, value),
                })
        return findings

    def scan_many(self, items: List[Tuple[str, str]]) -> List[Dict]:
        """Scan a list of ``(text, source)`` pairs and flatten the findings."""
        out: List[Dict] = []
        for text, source in items:
            out.extend(self.scan_text(text, source))
        return out


# Process-wide default scanner + convenience wrapper for one-off calls.
_default = SecretScanner()


def scan_text(text: str, source: str = '') -> List[Dict]:
    """Scan ``text`` with the default rule set. See :meth:`SecretScanner.scan_text`."""
    return _default.scan_text(text, source)
