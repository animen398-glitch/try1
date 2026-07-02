"""core/update_check.py

Opt-in, local-first update check (DEV_PLAN WS6). Nothing here runs unless the
user turns it on and configures an endpoint — the offline-first / privacy stance
is preserved (mirrors ``core.crash_reporter``: nothing egresses automatically).

The check is a single HTTPS GET to a user-configured endpoint that returns a
small JSON document ``{"version": "1.2.3", "url": "https://…/download"}``. We
compare that to the running :data:`core.config.APP_VERSION` and report whether a
newer version exists — we never download or install anything (no auto-update).

Pure and side-effect-light: the transport (``_fetch``) is injectable so the
comparison logic is unit-tested deterministically without network (invariant I5,
same pattern as ``utils.http_retry`` / ``core.crash_reporter``).
"""

import json
import re
import urllib.request
from typing import Callable, Dict, Optional

__all__ = ['parse_version', 'check_for_update', 'update_line']

_NUM = re.compile(r'\d+')


def parse_version(value: str) -> tuple:
    """A comparable tuple of the numeric components of a version string.

    ``"1.2.3"`` → ``(1, 2, 3)``; a leading ``v`` and any pre-release suffix are
    ignored (``"v1.4.0-rc1"`` → ``(1, 4, 0, 1)``). Non-numeric / empty input →
    ``(0,)`` so a malformed value never wins a comparison."""
    parts = tuple(int(n) for n in _NUM.findall(str(value or '')))
    return parts or (0,)


def _fetch(endpoint: str, timeout: float) -> Dict:
    """HTTPS-only GET returning the parsed JSON body (raises on any failure)."""
    if not str(endpoint).lower().startswith('https://'):
        raise ValueError('endpoint must be https://')
    req = urllib.request.Request(
        endpoint, headers={'Accept': 'application/json',
                           'User-Agent': 'AdvancedSiteAnalyzer-UpdateCheck'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https-only, checked above
        return json.loads(resp.read().decode('utf-8', 'replace'))


def check_for_update(*, current: Optional[str] = None,
                     endpoint: Optional[str] = None,
                     fetch: Optional[Callable[[str, float], Dict]] = None,
                     timeout: float = 10.0) -> Dict:
    """Check the configured endpoint for a newer version (opt-in, best-effort).

    Returns ``{status, current, latest?, url?, update_available?, error?}`` where
    ``status`` is one of ``disabled`` / ``update_available`` / ``up_to_date`` /
    ``error``. ``current`` defaults to :data:`core.config.APP_VERSION` and
    ``endpoint`` to the ``update_check`` setting; when the feature is off or no
    endpoint is set the result is ``disabled`` (no network). ``fetch`` is
    injectable for tests. Never raises — a network/parse failure yields
    ``error``, so a caller can surface it without a try/except."""
    from core.config import APP_VERSION, load_settings
    if current is None:
        current = APP_VERSION
    if endpoint is None:
        cfg = load_settings().get('update_check') or {}
        if not cfg.get('enabled'):
            return {'status': 'disabled', 'current': current}
        endpoint = str(cfg.get('endpoint') or '').strip()
    if not endpoint:
        return {'status': 'disabled', 'current': current}

    fetcher = fetch or _fetch
    try:
        data = fetcher(endpoint, timeout)
    except Exception as e:  # noqa: BLE001 — update check is best-effort
        return {'status': 'error', 'current': current, 'error': str(e)}

    latest = str((data or {}).get('version') or '').strip()
    url = str((data or {}).get('url') or '').strip()
    if not latest:
        return {'status': 'error', 'current': current,
                'error': 'response has no "version"'}
    available = parse_version(latest) > parse_version(current)
    return {
        'status': 'update_available' if available else 'up_to_date',
        'current': current, 'latest': latest, 'url': url,
        'update_available': available,
    }


def update_line(result: Dict) -> str:
    """One human-readable status line for the health screen (pure)."""
    status = result.get('status')
    if status == 'update_available':
        line = (f"Обновление: доступна версия {result.get('latest')} "
                f"(текущая {result.get('current')})")
        return line + (f" — {result['url']}" if result.get('url') else '')
    if status == 'up_to_date':
        return f"Обновление: установлена последняя версия ({result.get('current')})"
    if status == 'error':
        return f"Обновление: проверка не удалась ({result.get('error')})"
    return "Обновление: проверка отключена"
