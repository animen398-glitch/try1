import json
import re
import socket
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from utils.browser_utils import SessionBuilder
from utils.http_retry import decompress, urlopen_retry
from utils.scan_cache import TTLCache


_GEOIP_API = 'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as'

# GeoIP for a given IP is stable for a long time — cache it for an hour to
# avoid hammering ip-api.com when scanning the same host repeatedly.
_GEO_CACHE = TTLCache(ttl_seconds=3600)


def clear_geo_cache() -> int:
    """Drop all cached GeoIP lookups; returns the number of entries removed."""
    n = len(_GEO_CACHE)
    _GEO_CACHE.clear()
    return n

_SECURITY_HEADER_NAMES = frozenset({
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
})

_CMS_SIGNATURES: List[Tuple[str, List[str]]] = [
    ('WordPress',  ['wp-content/', 'wp-includes/', '/wp-json/', 'wp-embed.min.js']),
    ('Joomla',     ['/components/com_', '/media/jui/', 'Joomla!']),
    ('Drupal',     ['/sites/default/files/', 'Drupal.settings', '/misc/drupal.js']),
    ('Next.js',    ['__NEXT_DATA__', '/_next/static/', '__NEXT_LOADED_PAGES__']),
    ('Nuxt.js',    ['__NUXT__', '/_nuxt/', 'data-server-rendered']),
    ('Gatsby',     ['___gatsby', '/static/gatsby-', 'gatsby-chunk']),
    ('Tilda',      ['tildacdn.com', 'tilda-', 't-rec']),
    ('Wix',        ['wixstatic.com', 'X-Wix-Published-Version', 'wix-warmup-data']),
    ('Shopify',    ['cdn.shopify.com', 'Shopify.theme', 'myshopify.com']),
    ('Ghost',      ['content.ghost.io', '/ghost/', 'ghost-url']),
    ('Bitrix',     ['bitrix/js', 'bitrix/templates', 'BX.ready']),
    ('Hugo',       ['hugo-', 'generator.*Hugo']),
    ('React',      ['__reactFiber', '__reactContainer', 'react-root']),
    ('Vue.js',     ['__vue__', 'data-v-app', 'vue-router']),
    ('Angular',    ['ng-version=', '_nghost-', 'ng-app=']),
]

_SCRIPT_SIGNATURES: List[Tuple[str, List[str]]] = [
    ('Angular',   ['angular.min.js', 'angular.js', '/angular/', 'zone.js', '@angular/']),
    ('Zone.js',   ['zone.js', 'zone.min.js', 'zone-evergreen']),
    ('React',     ['react.development.js', 'react.production.min.js', 'react-dom']),
    ('Vue.js',    ['vue.global.js', 'vue.esm-browser', 'vue.min.js', '/vue@']),
    ('Quill',     ['quill.js', 'quill.min.js', '/quill@', '/quill/']),
    ('GTM',       ['gtm.js', 'googletagmanager.com/gtm']),
    ('jQuery',    ['jquery.min.js', 'jquery-3.', 'jquery-2.', '/jquery@']),
    ('Svelte',    ['svelte.js', '/svelte@', '/svelte/']),
    ('Alpine.js', ['alpine.js', 'alpinejs@']),
    ('HTMX',      ['htmx.min.js', 'htmx@']),
    ('Lit',       ['lit-element.js', '/lit@', 'lit-core']),
    ('Ember',     ['ember.min.js', '/ember@']),
    ('Next.js',   ['_next/static/', '__next']),
    ('Nuxt.js',   ['/_nuxt/', '__nuxt']),
]


def enrich_cms_with_dynamic(recon_result: Dict, dynamic_result: Dict) -> None:
    """Mutates recon_result['cms'] and recon_result['cms_details'] in-place.

    Builds a URL corpus from dynamic endpoint URLs, checks _SCRIPT_SIGNATURES,
    and merges runtime_globals from the Playwright JS probe.
    """
    if not recon_result or not dynamic_result:
        return

    # Build corpus of all endpoint URLs seen during dynamic tracing
    endpoints = dynamic_result.get('endpoints', [])
    url_corpus = '\n'.join(ep.get('url', '') for ep in endpoints)
    structs = dynamic_result.get('json_structures', [])
    url_corpus += '\n' + '\n'.join(js.get('url', '') for js in structs)

    cms: List[str] = recon_result.get('cms', [])
    cms_details: Dict[str, List[str]] = recon_result.get('cms_details', {})

    for name, patterns in _SCRIPT_SIGNATURES:
        if name in cms:
            continue
        matched = [p for p in patterns if re.search(re.escape(p), url_corpus, re.IGNORECASE)]
        if matched:
            cms.append(name)
            existing = cms_details.get(name, [])
            cms_details[name] = existing + [f'[script-url] {m}' for m in matched]

    # Merge runtime globals detected by the Playwright JS probe
    runtime_globals: Dict[str, bool] = dynamic_result.get('runtime_globals', {})
    for name, detected in runtime_globals.items():
        if detected and name not in cms:
            cms.append(name)
            cms_details[name] = cms_details.get(name, []) + ['[window-global]']

    recon_result['cms'] = cms
    recon_result['cms_details'] = cms_details


class ReconEngine:
    """
    Deep site reconnaissance:
    - IP resolution + geographic lookup (ip-api.com)
    - CMS / tech-stack fingerprinting from HTML patterns and response headers
    - Favicon discovery: root /favicon.ico, <link rel="icon">, apple-touch-icon
    - PWA manifest extraction: /manifest.json, /site.webmanifest, <link rel="manifest">
    """

    def __init__(self, data_registry=None):
        self._timeout: int = 10
        self._profile: str = 'chrome_windows'
        self._output_dir: Optional[Path] = None
        self._data_registry = data_registry

    def _record_discovery(self, source: str, data_type: str, content: str,
                          metadata: Optional[Dict] = None) -> None:
        """Сохранить найденный актив в DataRegistry (не ломая процесс разведки)."""
        try:
            if self._data_registry is None:
                from core.registry import DataRegistry
                self._data_registry = DataRegistry()
            self._data_registry.add_record(source, data_type, content, metadata)
        except Exception:
            pass

    def configure(
        self,
        output_dir: Optional[str] = None,
        timeout: int = 10,
        profile: str = 'chrome_windows',
    ):
        self._timeout = timeout
        self._profile = profile
        self._output_dir = Path(output_dir) if output_dir else None
        if self._output_dir:
            self._output_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- fetch

    def _fetch(self, url: str) -> Optional[bytes]:
        try:
            headers = SessionBuilder(self._profile).get_headers()
            req = urllib.request.Request(url, headers=headers)
            raw, resp_headers = urlopen_retry(req, self._timeout)
            return decompress(raw, resp_headers)
        except Exception:
            return None

    def _fetch_with_headers(self, url: str) -> Tuple[Optional[bytes], Dict[str, str]]:
        try:
            headers = SessionBuilder(self._profile).get_headers()
            req = urllib.request.Request(url, headers=headers)
            raw, resp_headers = urlopen_retry(req, self._timeout)
            return decompress(raw, resp_headers), dict(resp_headers)
        except Exception:
            return None, {}

    # ---------------------------------------------------------------- geo / ip

    def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _geoip(self, ip: str) -> Dict:
        cached = _GEO_CACHE.get(ip)
        if cached is not None:
            return cached
        try:
            raw = self._fetch(_GEOIP_API.format(ip=ip))
            if raw:
                data = json.loads(raw.decode('utf-8', errors='ignore'))
                if data.get('status') == 'success':
                    data.pop('status', None)
                    _GEO_CACHE.set(ip, data)   # cache only successful lookups
                    return data
        except Exception:
            pass
        return {}

    # ---------------------------------------------------------------- CMS

    def _detect_cms(
        self, html: str, headers: Dict[str, str]
    ) -> tuple:  # (List[str], Dict[str, List[str]])
        corpus = html + '\n' + '\n'.join(f'{k}: {v}' for k, v in headers.items())
        names: List[str] = []
        details: Dict[str, List[str]] = {}
        for name, patterns in _CMS_SIGNATURES:
            matched = [p for p in patterns if re.search(p, corpus, re.IGNORECASE)]
            if matched:
                names.append(name)
                details[name] = matched
        return names, details

    # ---------------------------------------------------------------- favicons

    def _extract_favicons(self, html: str, base_url: str) -> List[Dict]:
        icons: List[Dict] = []
        seen: set = set()

        def add(url: str, icon_type: str, sizes: Optional[str] = None):
            full = urljoin(base_url, url)
            if full not in seen:
                seen.add(full)
                icons.append({'url': full, 'type': icon_type, 'sizes': sizes})

        # <link rel="icon"> and <link rel="shortcut icon">
        for m in re.finditer(
            r'<link[^>]+rel=["\'][^"\']*\bicon\b[^"\']*["\'][^>]*>',
            html, re.IGNORECASE
        ):
            tag = m.group(0)
            href = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            sizes = re.search(r'sizes=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if href:
                add(href.group(1), 'link-icon', sizes.group(1) if sizes else None)

        # <link rel="apple-touch-icon">
        for m in re.finditer(
            r'<link[^>]+apple-touch-icon[^>]*>', html, re.IGNORECASE
        ):
            tag = m.group(0)
            href = re.search(r'href=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            sizes = re.search(r'sizes=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if href:
                add(href.group(1), 'apple-touch-icon', sizes.group(1) if sizes else None)

        # Root fallback
        parsed = urlparse(base_url)
        root_ico = f'{parsed.scheme}://{parsed.netloc}/favicon.ico'
        add(root_ico, 'root-fallback')

        return icons

    # ---------------------------------------------------------------- PWA manifest

    def _fetch_pwa_manifest(self, html: str, base_url: str) -> Dict:
        parsed = urlparse(base_url)
        origin = f'{parsed.scheme}://{parsed.netloc}'

        # Try standard manifest paths first
        for path in ('/manifest.json', '/site.webmanifest', '/manifest.webmanifest'):
            raw = self._fetch(origin + path)
            if raw:
                try:
                    data = json.loads(raw.decode('utf-8', errors='ignore'))
                    return {'url': origin + path, 'data': data}
                except Exception:
                    continue

        # Then check <link rel="manifest"> in HTML
        m = re.search(
            r'<link[^>]+rel=["\']manifest["\'][^>]+href=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if m:
            manifest_url = urljoin(base_url, m.group(1))
            raw = self._fetch(manifest_url)
            if raw:
                try:
                    return {
                        'url': manifest_url,
                        'data': json.loads(raw.decode('utf-8', errors='ignore')),
                    }
                except Exception:
                    pass

        return {}

    # ---------------------------------------------------------------- public

    def run_recon(self, url: str) -> Dict:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        parsed = urlparse(url)
        domain = parsed.netloc

        result: Dict = {
            'url': url,
            'domain': domain,
            'ip': None,
            'geo': {},
            'cms': [],
            'favicons': [],
            'pwa_manifest': {},
            'server_headers': {},
            'security_headers': {},
            'status': 'Failed',
        }

        # IP + geo
        ip = self._resolve_ip(domain)
        result['ip'] = ip
        if ip:
            result['geo'] = self._geoip(ip)

        # Persist discovered assets (host + resolved IP) to the DataRegistry
        if domain:
            self._record_discovery(
                source=url, data_type='subdomain', content=domain,
                metadata={'resolved_ip': ip},
            )
        if ip:
            self._record_discovery(
                source=url, data_type='ip_address', content=ip,
                metadata={'domain': domain, 'geo': result['geo']},
            )

        # Fetch main page
        raw, resp_headers = self._fetch_with_headers(url)
        if raw is None:
            result['error'] = 'Failed to fetch main page'
            return result

        html = raw.decode('utf-8', errors='ignore')

        # Keep only interesting server headers
        interesting = {
            'server', 'x-powered-by', 'x-generator', 'x-cms',
            'x-wix-published-version', 'x-drupal-cache', 'x-wordpress-url',
        }
        result['server_headers'] = {
            k: v for k, v in resp_headers.items()
            if k.lower() in interesting
        }
        result['security_headers'] = {
            k.lower(): v for k, v in resp_headers.items()
            if k.lower() in _SECURITY_HEADER_NAMES
        }

        cms, cms_details       = self._detect_cms(html, resp_headers)
        result['cms']          = cms
        result['cms_details']  = cms_details
        result['favicons']     = self._extract_favicons(html, url)
        result['pwa_manifest'] = self._fetch_pwa_manifest(html, url)
        result['status']       = 'Success'

        # Persist recon report if output_dir configured
        if self._output_dir:
            report = dict(result)
            report.pop('pwa_manifest', None)   # can be large
            out = self._output_dir / 'recon_report.json'
            out.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding='utf-8',
            )

        return result
