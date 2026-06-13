"""core/llm_summary.py
Optional LLM narrative for the executive summary via a LOCAL Ollama instance.

Strictly opt-in and localhost-only — no cloud, no API key, nothing leaves the
machine. The deterministic executive summary (core/executive_summary) stays the
single authoritative source of the risk verdict and metrics; this module only
adds a natural-language *narrative* on top of numbers already computed. It never
recomputes the score or the level. If Ollama isn't running it degrades to
nothing (the deterministic summary is shown alone), so reports stay reproducible
and self-contained (architectural invariants I1/I2/I3).

The narrative is generated at scan time and baked into the report as static
text, so report.html remains offline (the only request is to localhost, not a
CDN). The single network seam — ``_post`` — is isolated so tests stub it; the
model's free text is never asserted on (invariant I5).
"""

import json
import urllib.request
from typing import Callable, Dict, Optional

DEFAULT_ENDPOINT = 'http://localhost:11434'
DEFAULT_MODEL = 'llama3'
_GENERATE_PATH = '/api/generate'
_TAGS_PATH = '/api/tags'


def available(endpoint: str = DEFAULT_ENDPOINT, timeout: float = 0.5) -> bool:
    """True if a local Ollama answers on ``endpoint``.

    Localhost only; any failure (connection refused / timeout / bad status)
    degrades to ``False`` so callers can disable or skip the feature cleanly.
    """
    try:
        req = urllib.request.Request(endpoint.rstrip('/') + _TAGS_PATH)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= getattr(resp, 'status', 200) < 300
    except Exception:   # noqa: BLE001 — any failure means "not available"
        return False


def build_prompt(summary: Dict) -> str:
    """Build a deterministic prompt from the already-computed executive summary.

    Pure (no model, no network) so it is unit-testable. The prompt feeds the
    model only the structured facts the deterministic summary produced and
    instructs it not to invent anything or change the verdict.
    """
    metrics = summary.get('metrics', {}) if isinstance(
        summary.get('metrics'), dict) else {}
    level = summary.get('risk_level', '—')
    score = summary.get('risk_100', metrics.get('risk_100', 0))
    findings = summary.get('key_findings', []) or []
    recs = summary.get('recommendations', []) or []

    lines = [
        'Ты — ассистент по кибербезопасности. На основе СТРУКТУРИРОВАННЫХ данных '
        'ниже напиши краткое (3–5 предложений) резюме рисков для отчёта. Не '
        'выдумывай фактов сверх данных и НЕ меняй вердикт риска. Отвечай по-русски.',
        f'Вердикт риска (авторитетный, не меняй): {level} ({score}/100).',
        f'Метрики: секретов={metrics.get("secrets", 0)}, '
        f'High={metrics.get("high", 0)}, Medium={metrics.get("medium", 0)}, '
        f'слабых cookie={metrics.get("weak_cookies", 0)}, '
        f'страниц={metrics.get("pages", 0)}.',
    ]
    if findings:
        lines.append('Находки: ' + '; '.join(str(f) for f in findings) + '.')
    if recs:
        lines.append('Рекомендации: ' + '; '.join(str(r) for r in recs) + '.')
    return '\n'.join(lines)


def _post(url: str, payload: Dict, timeout: float) -> Dict:
    """The single network seam: POST JSON to a localhost URL, return parsed
    JSON. Isolated so tests can stub the whole HTTP call (invariant I5)."""
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def generate_narrative(summary: Dict, endpoint: str = DEFAULT_ENDPOINT,
                       model: str = DEFAULT_MODEL, timeout: float = 30.0,
                       log: Optional[Callable] = None) -> Dict:
    """Ask a local Ollama to narrate the executive ``summary``.

    Returns ``{status, narrative, model, error?}`` where ``status`` is
    ``Unavailable`` (no local Ollama), ``Error`` (call failed / empty), or
    ``Success``. Never raises and never blocks the report: a missing or failing
    Ollama just yields no narrative, and the deterministic summary stands alone.
    """
    def _log(msg: str):
        if log:
            log(msg)

    if not available(endpoint, timeout=min(timeout, 0.5)):
        return {'status': 'Unavailable', 'narrative': None, 'model': model,
                'error': f'ollama not reachable on {endpoint}'}
    try:
        resp = _post(
            endpoint.rstrip('/') + _GENERATE_PATH,
            {'model': model, 'prompt': build_prompt(summary), 'stream': False},
            timeout)
        text = str(resp.get('response') or '').strip()
        if not text:
            return {'status': 'Error', 'narrative': None, 'model': model,
                    'error': 'empty response from ollama'}
        _log(f'  LLM narrative: {len(text)} chars ({model})')
        return {'status': 'Success', 'narrative': text, 'model': model}
    except Exception as e:   # noqa: BLE001 — a model failure is never fatal
        _log(f'  LLM narrative failed: {e}')
        return {'status': 'Error', 'narrative': None, 'model': model,
                'error': str(e)}
