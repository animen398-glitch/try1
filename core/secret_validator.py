"""core/secret_validator.py
Pure, OFFLINE structural validation of detected secrets — format only.

Given a detected secret (its rule type from ``secret_scanner`` + the matched
value), this checks the *shape*: length, charset, vendor prefix, base64/JSON
structure, decoded contents. It does this entirely offline — it NEVER contacts
a provider API, never sends the secret anywhere, nothing leaves the machine
(architectural invariants I1/I2; the "live validation" variant that would phone
a vendor is deliberately out of scope for privacy/dual-use reasons).

It therefore cannot tell you a key is *active* — only that it is well-formed.
That is still useful: it demotes obvious false positives (placeholders like
``your_api_key_here``, truncated or low-entropy values) and raises confidence on
structurally exact matches (a JWT whose header base64-decodes to real JSON, a
Basic credential that decodes to ``user:pass``).

Pure and dependency-free (``base64``/``json``/``re``), so it is trivially
unit-testable and deterministic (invariant I5).
"""

import base64
import json
import re
from typing import Callable, Dict, List, Optional, Tuple

VALID = 'valid_format'          # matches the exact structural spec for its type
INVALID = 'invalid_format'      # matched the broad regex but fails a strict check
UNVERIFIABLE = 'unverifiable'   # no structural spec beyond the detection regex

# Substrings that betray a placeholder/sample value rather than a real secret.
_PLACEHOLDER_TOKENS = (
    'your', 'example', 'placeholder', 'changeme', 'change_me', 'dummy',
    'sample', 'redacted', 'insert', 'replace', 'lorem', 'foobar', 'xxxx',
    'todo', 'yourkey', 'your_api', 'enter_', 'putyour', '0123456789',
    'abcdefghij',
)

_Result = Tuple[str, str]


# ── low-level helpers ────────────────────────────────────────────────────────

def _b64url_text(seg: str) -> Optional[str]:
    """Base64url-decode one JWT segment to text, or ``None`` if it isn't."""
    try:
        pad = '=' * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg + pad).decode('utf-8', 'replace')
    except Exception:
        return None


def _b64_bytes(token: str) -> Optional[bytes]:
    """Standard base64-decode, or ``None`` if it isn't valid base64."""
    try:
        return base64.b64decode(token + '=' * (-len(token) % 4))
    except Exception:
        return None


def _re_exact(pattern: str) -> Callable[[str], _Result]:
    """Validator that passes iff the value fully matches ``pattern``."""
    rx = re.compile(pattern)

    def check(value: str) -> _Result:
        if rx.fullmatch(value):
            return VALID, 'соответствует точному формату типа'
        return INVALID, 'не соответствует точному формату типа'
    return check


# ── structural validators with real decoding ────────────────────────────────

def _jwt(value: str) -> _Result:
    parts = value.split('.')
    if len(parts) != 3:
        return INVALID, 'JWT должен иметь 3 сегмента'
    header = _b64url_text(parts[0])
    if header is None:
        return INVALID, 'заголовок не декодируется как base64url'
    try:
        obj = json.loads(header)
    except Exception:
        return INVALID, 'заголовок не является JSON'
    if isinstance(obj, dict) and obj.get('alg'):
        return VALID, f'корректный JWT-заголовок (alg={obj["alg"]})'
    return INVALID, 'в заголовке JWT нет поля alg'


def _basic(value: str) -> _Result:
    m = re.search(r'Basic\s+([A-Za-z0-9+/=]+)', value)
    token = m.group(1) if m else value
    raw = _b64_bytes(token)
    if raw is None:
        return INVALID, 'не является base64'
    text = raw.decode('utf-8', 'replace')
    if ':' in text:
        return VALID, 'декодируется в пару user:pass'
    return INVALID, 'не содержит разделитель user:pass'


def _generic(value: str) -> _Result:
    """Low-confidence contextual keys: separate plausible secrets from
    placeholders by content, since the detection regex alone is weak."""
    low = value.lower()
    if any(tok in low for tok in _PLACEHOLDER_TOKENS):
        return INVALID, 'похоже на плейсхолдер/пример'
    uniq = len(set(value))
    if uniq < 6:
        return INVALID, f'слишком низкое разнообразие символов ({uniq})'
    classes = sum(bool(re.search(p, value)) for p in (r'[a-z]', r'[A-Z]', r'[0-9]'))
    if classes >= 2 and len(value) >= 16:
        return VALID, 'достаточная длина и разнообразие символов'
    return UNVERIFIABLE, 'структура неоднозначна'


def _bearer(value: str) -> _Result:
    # A Bearer value is often a JWT — validate it as one when it looks like it.
    if value.startswith('eyJ') and value.count('.') == 2:
        return _jwt(value)
    return UNVERIFIABLE, 'непрозрачный bearer-токен'


# Registry: secret_scanner rule name -> structural validator. Types absent here
# have no spec beyond their detection regex and report as ``unverifiable``.
_VALIDATORS: Dict[str, Callable[[str], _Result]] = {
    'JWT': _jwt,
    'Authorization Basic': _basic,
    'Bearer Token': _bearer,
    'Generic API Key': _generic,
    'Generic Secret': _generic,
    'AWS Access Key': _re_exact(r'AKIA[0-9A-Z]{16}'),
    'Google API Key': _re_exact(r'AIza[0-9A-Za-z_\-]{35}'),
    'Twilio Account SID': _re_exact(r'AC[0-9a-f]{32}'),
    'Twilio SID Key': _re_exact(r'SK[0-9a-f]{32}'),
    'npm Token': _re_exact(r'npm_[A-Za-z0-9]{36}'),
    'SendGrid Key': _re_exact(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
    'Stripe Secret': _re_exact(r'sk_live_[0-9a-zA-Z]{24,}'),
    'Stripe Publishable': _re_exact(r'pk_live_[0-9a-zA-Z]{24,}'),
    'Stripe Test Key': _re_exact(r'sk_test_[0-9a-zA-Z]{24,}'),
    'Stripe Restricted Key': _re_exact(r'rk_live_[0-9a-zA-Z]{24,}'),
    'GitHub Token': _re_exact(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    'GitHub Fine-grained PAT': _re_exact(r'github_pat_[A-Za-z0-9_]{22,}'),
    'Anthropic API Key': _re_exact(r'sk-ant-[A-Za-z0-9_-]{20,}'),
    'OpenAI API Key': _re_exact(r'sk-[A-Za-z0-9_-]{20,}'),
    'GitLab PAT': _re_exact(r'glpat-[A-Za-z0-9_-]{20,}'),
    'Hugging Face Token': _re_exact(r'hf_[A-Za-z0-9]{34,}'),
    'Slack Token': _re_exact(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    'Mailgun Key': _re_exact(r'key-[0-9a-zA-Z]{32}'),
}


def validate(secret_type: str, value: str) -> Dict:
    """Validate a secret's *format* offline. Returns ``{status, reason}``.

    ``status`` is one of ``valid_format`` / ``invalid_format`` /
    ``unverifiable``. Never raises, never touches the network.
    """
    fn = _VALIDATORS.get(secret_type)
    if fn is None:
        return {'status': UNVERIFIABLE,
                'reason': 'нет структурной спецификации для типа'}
    try:
        status, reason = fn(value or '')
    except Exception as e:   # noqa: BLE001 — a validator must never raise
        return {'status': UNVERIFIABLE, 'reason': f'ошибка валидации: {e}'}
    return {'status': status, 'reason': reason}


def summarize(findings: List[Dict]) -> Dict:
    """Count findings by validation status (for report/summary cards)."""
    out = {VALID: 0, INVALID: 0, UNVERIFIABLE: 0}
    for f in findings:
        status = (f.get('validation') or {}).get('status', UNVERIFIABLE)
        out[status] = out.get(status, 0) + 1
    return out
