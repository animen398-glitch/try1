"""core/openapi_discovery.py
OpenAPI / Swagger discovery — find a target's API spec and build a map of its
endpoints (roadmap #11).

Probes the conventional spec locations (``/openapi.json``, ``/swagger.json``,
``/v3/api-docs`` …), and when one is found, parses it into a flat endpoint map
(method + path + summary + tags). Supports OpenAPI 3.x and Swagger 2.0.

Invariants:
  * I1 — stdlib only. JSON specs are parsed with ``json``; YAML specs are out of
    scope (would need a third-party parser) and simply not matched.
  * I5 — the network probe (``_fetch_json``) is separated from the pure parser
    (``parse_spec``) and is injectable into ``discover`` so tests never hit the
    network.
"""

import html
import json
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text

# Conventional spec locations, probed in order at the target's root. JSON only.
SPEC_PATHS = (
    '/openapi.json', '/swagger.json', '/v3/api-docs', '/v2/api-docs',
    '/api-docs', '/swagger/v1/swagger.json', '/v2/swagger.json',
    '/v3/swagger.json', '/api/openapi.json', '/api/swagger.json',
    '/api/v1/openapi.json', '/.well-known/openapi.json',
)

_HTTP_METHODS = ('get', 'post', 'put', 'delete', 'patch', 'options', 'head',
                 'trace')

_FETCH_TIMEOUT = 8.0


# ── network (injectable; kept out of the pure parser) ─────────────────────────

def _fetch_json(url: str, timeout: float = _FETCH_TIMEOUT,
                profile: str = 'chrome_windows') -> Optional[Dict]:
    """GET ``url`` and parse a JSON object, or None on any failure.

    A single attempt (probing many paths, so a 404 should fail fast, not
    retry). Returns None for non-JSON / non-object bodies (e.g. an HTML 404)."""
    try:
        req = SessionBuilder(profile).make_request(url)
        text = urlopen_text(req, timeout, attempts=1)
    except Exception:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


# ── pure parsing ──────────────────────────────────────────────────────────────

def parse_spec(spec: Dict) -> Optional[Dict]:
    """Flatten an OpenAPI 3.x / Swagger 2.0 dict into an endpoint map (pure).

    Returns ``{version, title, servers, endpoints, counts}`` or None when the
    dict is not a recognizable spec (no version marker or no ``paths``)."""
    if not isinstance(spec, dict):
        return None
    version = spec.get('openapi') or spec.get('swagger')
    paths = spec.get('paths')
    if not version or not isinstance(paths, dict):
        return None

    info = spec.get('info') if isinstance(spec.get('info'), dict) else {}
    title = info.get('title') or ''

    endpoints: List[Dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            # Tolerate a malformed-but-object spec (degrade, never raise): a
            # method key need not be a string, and operation fields may be the
            # wrong type — coerce/skip rather than crash on untrusted input.
            if str(method).lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            tags = op.get('tags')
            params = op.get('parameters')
            endpoints.append({
                'path': str(path),
                'method': str(method).upper(),
                'summary': str(op.get('summary') or op.get('operationId') or ''),
                'tags': [str(t) for t in tags] if isinstance(tags, list) else [],
                'deprecated': bool(op.get('deprecated')),
                'params': len(params) if isinstance(params, list) else 0,
            })
    endpoints.sort(key=lambda e: (e['path'], e['method']))

    return {
        'version': str(version),
        'title': str(title),
        'servers': _servers(spec),
        'endpoints': endpoints,
        'counts': {'paths': len(paths), 'endpoints': len(endpoints)},
    }


def _servers(spec: Dict) -> List[str]:
    """Server/base URLs for either spec dialect."""
    # OpenAPI 3.x: a servers[] list of {url}.
    servers = spec.get('servers')
    if isinstance(servers, list):
        out = [s.get('url') for s in servers
               if isinstance(s, dict) and s.get('url')]
        if out:
            return [str(u) for u in out]
    # Swagger 2.0: host + basePath (+ first scheme).
    host = spec.get('host')
    base_path = spec.get('basePath') or ''
    if host:
        schemes = spec.get('schemes') or ['https']
        scheme = schemes[0] if isinstance(schemes, list) and schemes else 'https'
        return [f'{scheme}://{host}{base_path}']
    if base_path:
        return [str(base_path)]
    return []


# ── discovery (probe + parse) ─────────────────────────────────────────────────

def discover(base_url: str, timeout: float = _FETCH_TIMEOUT,
             profile: str = 'chrome_windows',
             paths=None, fetch: Optional[Callable] = None) -> Dict:
    """Probe ``base_url``'s root for a spec and return the parsed API map.

    ``fetch(url)`` overrides the default network getter (tests inject a fake).
    Returns a result with ``status`` 'Success' (spec found) or 'Not found'."""
    parts = urlparse(base_url if '://' in base_url else 'https://' + base_url)
    root = f'{parts.scheme}://{parts.netloc}'
    getter = fetch or (lambda u: _fetch_json(u, timeout, profile))

    for p in (paths or SPEC_PATHS):
        url = root + p
        spec = getter(url)
        if not isinstance(spec, dict):
            continue
        parsed = parse_spec(spec)
        if parsed is None:
            continue
        parsed['status'] = 'Success'
        parsed['spec_url'] = url
        return parsed

    return {'status': 'Not found', 'spec_url': None, 'version': None,
            'title': '', 'servers': [], 'endpoints': [],
            'counts': {'paths': 0, 'endpoints': 0}}


# ── offline HTML render (no JS / CDN) ─────────────────────────────────────────

def render_html(data: Dict) -> str:
    """Render the API map as an offline HTML fragment (table of endpoints)."""
    e = html.escape
    if not data or data.get('status') != 'Success':
        return ('<p style="font-size:13px;color:#999;">OpenAPI-спека не найдена</p>')

    counts = data.get('counts', {})
    head = (f'<p style="font-size:13px;">Спека: '
            f'<b>{e(str(data.get("spec_url", "")))}</b><br>'
            f'{e(str(data.get("title") or "—"))} · OpenAPI {e(str(data.get("version", "")))}'
            f' · эндпоинтов: <b>{e(str(counts.get("endpoints", 0)))}</b> '
            f'на {e(str(counts.get("paths", 0)))} путях</p>')

    servers = data.get('servers') or []
    if servers:
        head += ('<p style="font-size:12px;color:#666;">Серверы: '
                 + e(', '.join(servers)) + '</p>')

    rows = []
    for ep in (data.get('endpoints') or [])[:60]:
        dep = (' <span style="color:#c62828;">deprecated</span>'
               if ep.get('deprecated') else '')
        tags = e(', '.join(ep.get('tags') or []))
        rows.append(
            f'<tr><td style="padding:2px 10px 2px 0;font-weight:bold;'
            f'color:#1565c0;">{e(ep.get("method", ""))}</td>'
            f'<td style="padding:2px 10px 2px 0;font-family:monospace;">'
            f'{e(ep.get("path", ""))}{dep}</td>'
            f'<td style="padding:2px 10px 2px 0;color:#444;">'
            f'{e(ep.get("summary", ""))}</td>'
            f'<td style="color:#888;">{tags}</td></tr>')
    table = (f'<table style="font-size:12px;border-collapse:collapse;">'
             f'<tr style="color:#666;text-align:left;"><th>Метод</th><th>Путь</th>'
             f'<th>Описание</th><th>Теги</th></tr>{"".join(rows)}</table>'
             if rows else '')
    return head + table
