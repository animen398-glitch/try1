import asyncio
import concurrent.futures
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False


_AUTH_HEADER_NAMES = frozenset({
    'authorization', 'x-api-key', 'x-auth-token', 'x-access-token',
    'api-key', 'x-token', 'x-secret', 'x-client-id', 'x-csrf-token',
    'x-session-token', 'x-user-token', 'x-app-token',
})

# High-precision patterns for known secret formats
_SECRET_PATTERNS: List[tuple] = [
    ('JWT',         re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ('AWS Key ID',  re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('Google API',  re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
    ('Stripe sk',   re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')),
    ('Stripe pk',   re.compile(r'\bpk_live_[0-9a-zA-Z]{24,}\b')),
    ('GitHub PAT',  re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b')),
    ('Slack Token', re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')),
    ('Bearer',      re.compile(r'\bBearer\s+([A-Za-z0-9._~+/=\-]{20,})')),
    ('Firebase',    re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('Twilio',      re.compile(r'\bSK[0-9a-fA-F]{32}\b')),
    ('Mailgun',     re.compile(r'\bkey-[0-9a-zA-Z]{32}\b')),
    ('SendGrid',    re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b')),
]

# JSON key names that semantically indicate a credential
_SECRET_KEY_NAMES = frozenset({
    'token', 'access_token', 'refresh_token', 'id_token', 'auth_token',
    'api_key', 'apikey', 'api_secret', 'secret', 'secret_key',
    'authorization', 'bearer', 'jwt', 'session_token', 'x_api_key',
    'client_secret', 'private_key', 'auth', 'credential', 'credentials',
    'password', 'passwd', 'key', 'signing_key', 'symmetric_key',
})


def _looks_like_secret(value: str) -> bool:
    """Heuristic: long, no spaces, mixed alpha+digit — typical token shape."""
    return (
        len(value) > 20
        and ' ' not in value
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
    )


def _scan_json_for_secrets(body: object, source_url: str) -> List[Dict]:
    """
    Recursively walk a decoded JSON body looking for API keys and tokens.
    Returns a list of finding dicts:  {key, type, preview, source_url}
    """
    found: List[Dict] = []
    seen_values: set = set()

    def check(key: str, val: object, depth: int = 0):
        if depth > 4:
            return
        if isinstance(val, str):
            if val in seen_values or len(val) < 8:
                return
            # 1. Pattern-based (high precision)
            for pat_name, pattern in _SECRET_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched = m.group(0)
                    seen_values.add(val)
                    found.append({
                        'key': key,
                        'type': pat_name,
                        'preview': matched[:24] + '...' if len(matched) > 24 else matched,
                        'source_url': source_url,
                    })
                    return
            # 2. Semantic key name + secret-looking value (lower precision)
            key_norm = key.lower().replace('-', '_').replace(' ', '_')
            if key_norm in _SECRET_KEY_NAMES and _looks_like_secret(val):
                seen_values.add(val)
                found.append({
                    'key': key,
                    'type': 'token-field',
                    'preview': val[:24] + '...' if len(val) > 24 else val,
                    'source_url': source_url,
                })
        elif isinstance(val, dict):
            for k, v in val.items():
                check(k, v, depth + 1)
        elif isinstance(val, list):
            for item in val[:5]:
                if isinstance(item, dict):
                    for k, v in item.items():
                        check(k, v, depth + 1)

    if isinstance(body, dict):
        for k, v in body.items():
            check(k, v)
    elif isinstance(body, list):
        for item in body[:10]:
            if isinstance(item, dict):
                for k, v in item.items():
                    check(k, v)

    return found


class DynamicAnalyzer:
    """
    Headless Chromium traffic interceptor via Playwright.
    Captures all XHR/Fetch calls, extracts API endpoints,
    JSON response structures, and authentication headers.
    """

    def __init__(self):
        self.timeout_ms: int = 20000
        self.wait_ms: int = 3000
        self.max_responses: int = 200
        self.progress_callback: Optional[Callable] = None

    def configure(
        self,
        timeout_ms: int = 20000,
        wait_ms: int = 3000,
        max_responses: int = 200,
    ):
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.max_responses = max_responses

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    # ---------------------------------------------------------------- async

    async def _intercept_async(self, url: str) -> Dict:
        endpoints: List[Dict] = []
        auth_headers: List[Dict] = []
        json_structures: List[Dict] = []
        seen: set = set()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
            )
            ctx = await browser.new_context(
                user_agent=(
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/121.0.0.0 Safari/537.36'
                ),
                ignore_https_errors=True,
            )
            page = await ctx.new_page()

            async def on_response(response):
                if len(endpoints) >= self.max_responses:
                    return
                req = response.request
                if req.resource_type not in ('xhr', 'fetch'):
                    return
                req_url = req.url
                if req_url in seen:
                    return
                seen.add(req_url)

                parsed = urlparse(req_url)
                endpoints.append({
                    'url': req_url,
                    'method': req.method,
                    'status': response.status,
                    'host': parsed.netloc,
                    'path': parsed.path,
                    'query': parsed.query[:120] if parsed.query else '',
                })

                for key, val in req.headers.items():
                    if key.lower() in _AUTH_HEADER_NAMES and val:
                        auth_headers.append({
                            'header': key,
                            'preview': val[:16] + '...' if len(val) > 16 else val,
                            'url': req_url,
                        })

                ct = response.headers.get('content-type', '')
                if 'application/json' in ct or ('text/' in ct and req.resource_type == 'fetch'):
                    try:
                        body = await response.json()
                        secrets = _scan_json_for_secrets(body, req_url)
                        if isinstance(body, dict) and body:
                            json_structures.append({
                                'url': req_url,
                                'top_keys': sorted(body.keys())[:15],
                                'sample': {k: str(v)[:80]
                                           for k, v in list(body.items())[:5]},
                                'secrets_found': secrets,
                            })
                        elif isinstance(body, list) and body:
                            first = body[0] if isinstance(body[0], dict) else {}
                            json_structures.append({
                                'url': req_url,
                                'type': 'array',
                                'length': len(body),
                                'item_keys': sorted(first.keys())[:10],
                                'secrets_found': secrets,
                            })
                    except Exception:
                        pass

            page.on('response', on_response)

            try:
                await page.goto(url, timeout=self.timeout_ms, wait_until='networkidle')
            except Exception:
                try:
                    await page.goto(url, timeout=self.timeout_ms, wait_until='domcontentloaded')
                except Exception:
                    pass

            if self.wait_ms > 0:
                await page.wait_for_timeout(self.wait_ms)

            # Trigger lazy-loaded resources by scrolling
            try:
                await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                await page.wait_for_timeout(1200)
            except Exception:
                pass

            # Probe runtime globals to identify SPA frameworks
            runtime_globals: Dict = {}
            try:
                probe_result = await page.evaluate("""
                (function() {
                    var r = {};
                    try { r['Angular']  = !!(window.angular || window.getAllAngularRootElements); } catch(e){}
                    try { r['Zone.js']  = typeof window.Zone !== 'undefined'; } catch(e){}
                    try { r['React']    = !!(window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__); } catch(e){}
                    try { r['Vue.js']   = !!(window.Vue || window.__vue_app__); } catch(e){}
                    try { r['Lit']      = typeof window.LitElement !== 'undefined'; } catch(e){}
                    try { r['jQuery']   = !!(window.jQuery || typeof window.$ === 'function'); } catch(e){}
                    try { r['Quill']    = typeof window.Quill !== 'undefined'; } catch(e){}
                    try { r['Alpine.js']= typeof window.Alpine !== 'undefined'; } catch(e){}
                    try { r['HTMX']     = typeof window.htmx !== 'undefined'; } catch(e){}
                    try { r['Svelte']   = typeof window.__SVELTE__ !== 'undefined'; } catch(e){}
                    try { r['Next.js']  = typeof window.__NEXT_DATA__ !== 'undefined'; } catch(e){}
                    try { r['Nuxt.js']  = typeof window.__NUXT__ !== 'undefined'; } catch(e){}
                    try { r['Ember']    = typeof window.Ember !== 'undefined'; } catch(e){}
                    return r;
                })()
                """)
                runtime_globals = {k: True for k, v in probe_result.items() if v}
            except Exception:
                runtime_globals = {}

            await browser.close()

        all_secrets = [s for js in json_structures for s in js.get('secrets_found', [])]
        return {
            'status': 'Success',
            'url': url,
            'total_api_calls': len(endpoints),
            'unique_hosts': len({urlparse(e['url']).netloc for e in endpoints}),
            'endpoints': endpoints,
            'auth_headers': auth_headers,
            'json_structures': json_structures,
            'secrets_found': all_secrets,
            'runtime_globals': runtime_globals,
        }

    # ---------------------------------------------------------------- sync

    def _run_in_thread(self, url: str) -> Dict:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._intercept_async(url))
        finally:
            loop.close()

    def analyze_dynamic_traffic(self, url: str) -> Dict:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not _PLAYWRIGHT_OK:
            return {
                'status': 'Error',
                'error': (
                    'playwright not installed. '
                    'Run: pip install playwright && python -m playwright install chromium'
                ),
                'endpoints': [],
                'auth_headers': [],
                'json_structures': [],
            }

        self._log(f'[DynamicAnalyzer] Launching headless browser: {url}')
        timeout_s = self.timeout_ms / 1000 + 20

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self._run_in_thread, url)
                result = future.result(timeout=timeout_s)

            self._log(
                f'[DynamicAnalyzer] {result["total_api_calls"]} API calls, '
                f'{len(result["auth_headers"])} auth headers, '
                f'{len(result["json_structures"])} JSON structures'
            )
            return result

        except concurrent.futures.TimeoutError:
            return {
                'status': 'Error',
                'error': f'Timed out after {timeout_s:.0f}s',
                'endpoints': [], 'auth_headers': [], 'json_structures': [],
            }
        except Exception as e:
            return {
                'status': 'Error',
                'error': str(e),
                'endpoints': [], 'auth_headers': [], 'json_structures': [],
            }
