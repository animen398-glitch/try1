import asyncio
import concurrent.futures
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from core.secret_scanner import SecretScanner
from core.secret_validator import INVALID

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

# Credential detection is delegated to the shared scanner (core/secret_scanner)
# so JSON bodies, static JS and the Security Audit tab all use one rule set.
_SCANNER = SecretScanner()

# URL strings hiding inside JS bundles: absolute URLs, plus quoted root-relative
# paths that look like API endpoints (resolved against the page later).
_ABS_URL_RE = re.compile(r'''https?://[^\s"'`<>()\\]{4,}''')
_API_PATH_RE = re.compile(
    r'''["'`](/(?:api|v\d+|graphql|gql|rest|auth|oauth|internal)[A-Za-z0-9_\-/.]*)["'`]''')
# Trailing characters that regularly cling to a URL match but are not part of it.
_URL_TRAILING = '",\');:`>}]'


def extract_js_urls(text: str, base_url: str = '', limit: int = 200) -> List[str]:
    """Pull endpoint-looking URL strings out of a JS file body.

    Returns de-duplicated absolute URLs found verbatim plus API-shaped relative
    paths resolved against ``base_url``. Pure and bounded (``limit``) so it is
    cheap to run inline while intercepting traffic in a worker thread.
    """
    if not text:
        return []
    found: List[str] = []
    seen: set = set()

    def add(u: str):
        u = u.strip().rstrip(_URL_TRAILING)
        if u and u not in seen:
            seen.add(u)
            found.append(u)

    for m in _ABS_URL_RE.finditer(text):
        add(m.group(0))
        if len(found) >= limit:
            return found
    for m in _API_PATH_RE.finditer(text):
        path = m.group(1)
        add(urljoin(base_url, path) if base_url else path)
        if len(found) >= limit:
            break
    return found


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
            # 1. Pattern-based (high precision) — shared rule set. Drop hits the
            # structural validator flags as placeholders/examples (e.g. a docs key
            # in an API response), so they don't become a false High "secret exposed"
            # — the same filtering the api/document/audit secret folders apply.
            hits = [h for h in _SCANNER.scan_text(val)
                    if (h.get('validation') or {}).get('status') != INVALID]
            if hits:
                seen_values.add(val)
                found.append({
                    'key': key,
                    'type': hits[0]['type'],
                    'preview': hits[0]['preview'],
                    'source_url': source_url,
                })
                return
            # 2. Semantic key name + secret-looking value (lower precision). No
            # validator filter here: the value is an untyped 'token-field', for which
            # the structural validator is 'unverifiable' (it can't add signal).
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
        static_secrets: List[Dict] = []
        seen: set = set()
        js_seen: set = set()

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

            async def scan_js_body(response, js_url):
                """Mine a static JS bundle for endpoint URLs + leaked secrets."""
                if len(endpoints) >= self.max_responses:
                    return
                try:
                    text = await response.text()
                except Exception:
                    return
                for hit in _SCANNER.scan_text(text, js_url):
                    if (hit.get('validation') or {}).get('status') == INVALID:
                        continue   # placeholder/example in the bundle, not a secret
                    static_secrets.append({
                        'key': '(static-js)',
                        'type': hit['type'],
                        'preview': hit['preview'],
                        'source_url': js_url,
                    })
                for u in extract_js_urls(text, base_url=js_url):
                    if u in seen or len(endpoints) >= self.max_responses:
                        continue
                    seen.add(u)
                    parsed = urlparse(u)
                    endpoints.append({
                        'url': u,
                        'method': 'JS-REF',     # referenced in code, not requested
                        'status': None,
                        'host': parsed.netloc,
                        'path': parsed.path,
                        'query': parsed.query[:120] if parsed.query else '',
                        'source': 'static-js',
                        'found_in': js_url,
                    })

            async def on_response(response):
                req = response.request
                # Static JS bundles: mine the body for endpoint URLs and any
                # leaked secrets, then register the URLs as discovered endpoints.
                if req.resource_type == 'script' and req.url not in js_seen:
                    js_seen.add(req.url)
                    await scan_js_body(response, req.url)
                    return
                if len(endpoints) >= self.max_responses:
                    return
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
        all_secrets.extend(static_secrets)
        # JS-REF endpoints are discovered in code, not observed calls — count
        # them separately so total_api_calls stays "what the page actually hit".
        observed = [e for e in endpoints if e.get('method') != 'JS-REF']
        return {
            'status': 'Success',
            'url': url,
            'total_api_calls': len(observed),
            'discovered_endpoints': len(endpoints) - len(observed),
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
