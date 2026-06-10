"""subdomain_active.py
Active follow-up checks for enumerated subdomains:

  • HTTP/HTTPS liveness  — is the host actually serving, and with what status?
  • Subdomain takeover   — does the host CNAME to a third-party service that is
                           returning an "unclaimed resource" fingerprint?

CNAME resolution uses the stdlib (``socket.gethostbyname_ex`` exposes the alias
chain), so no extra dependency is required. The fingerprint classification is a
pure function (``classify``) and is unit-tested independently of the network.
"""

import concurrent.futures
import re
import socket
import ssl
import threading
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional


# Each signature: a third-party service, the CNAME suffixes that point at it,
# and body fingerprints shown when the backing resource is unclaimed/dangling.
TAKEOVER_SIGNATURES: List[Dict] = [
    {'service': 'GitHub Pages', 'cnames': ['github.io'],
     'fingerprints': ["There isn't a GitHub Pages site here",
                      "For root URLs (like http://example.com/) you must provide an index.html file"]},
    {'service': 'Heroku', 'cnames': ['herokuapp.com', 'herokudns.com', 'herokussl.com'],
     'fingerprints': ['No such app', "There's nothing here, yet."]},
    {'service': 'AWS S3', 'cnames': ['s3.amazonaws.com', 's3-website', '.s3.'],
     'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist']},
    {'service': 'Azure', 'cnames': ['azurewebsites.net', 'cloudapp.net',
                                    'trafficmanager.net', 'azureedge.net', 'azure-api.net'],
     'fingerprints': ['404 Web Site not found']},
    {'service': 'Fastly', 'cnames': ['fastly.net'],
     'fingerprints': ['Fastly error: unknown domain']},
    {'service': 'Shopify', 'cnames': ['myshopify.com'],
     'fingerprints': ['Sorry, this shop is currently unavailable']},
    {'service': 'Surge.sh', 'cnames': ['surge.sh'],
     'fingerprints': ['project not found']},
    {'service': 'Tumblr', 'cnames': ['domains.tumblr.com'],
     'fingerprints': ["Whatever you were looking for doesn't currently exist at this address"]},
    {'service': 'WordPress', 'cnames': ['wordpress.com'],
     'fingerprints': ['Do you want to register']},
    {'service': 'Ghost', 'cnames': ['ghost.io'],
     'fingerprints': ['The thing you were looking for is no longer here']},
    {'service': 'Bitbucket', 'cnames': ['bitbucket.io'],
     'fingerprints': ['Repository not found']},
    {'service': 'Pantheon', 'cnames': ['pantheonsite.io'],
     'fingerprints': ['The gods are wise', '404 error unknown site']},
    {'service': 'Read the Docs', 'cnames': ['readthedocs.io'],
     'fingerprints': ['unknown to Read the Docs']},
    {'service': 'Zendesk', 'cnames': ['zendesk.com'],
     'fingerprints': ['Help Center Closed']},
]

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)


def classify(cname_chain: List[str], body: str) -> Dict:
    """Decide whether a host looks vulnerable to subdomain takeover.

    Pure function: given the resolved CNAME alias chain and the HTTP response
    body, returns ``{service, cname_matched, fingerprint_matched, takeover}``.

    A takeover is flagged only when BOTH a known service CNAME is present AND a
    matching unclaimed-resource fingerprint appears in the body — that pairing
    is what distinguishes a dangling resource from a normally-hosted one.
    """
    chain_l = [c.lower() for c in cname_chain]
    body_l = body or ''

    for sig in TAKEOVER_SIGNATURES:
        cname_hit = any(any(c in alias for alias in chain_l) for c in sig['cnames'])
        if not cname_hit:
            continue
        fp_hit = next((fp for fp in sig['fingerprints'] if fp in body_l), None)
        return {
            'service': sig['service'],
            'cname_matched': True,
            'fingerprint_matched': fp_hit,
            'takeover': fp_hit is not None,
        }
    return {'service': None, 'cname_matched': False,
            'fingerprint_matched': None, 'takeover': False}


class ActiveSubdomainChecker:
    """Runs liveness + takeover checks over a set of hostnames."""

    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self._cancel = threading.Event()

    def cancel(self):
        self._cancel.set()

    @staticmethod
    def _cname_chain(host: str) -> List[str]:
        try:
            _name, aliases, _ips = socket.gethostbyname_ex(host)
            return aliases or []
        except Exception:
            return []

    def _http_probe(self, host: str) -> Dict:
        """Try HTTPS then HTTP; return {alive, http_status, server, title, body}."""
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}'
            try:
                req = urllib.request.Request(
                    url, headers={'User-Agent': 'Mozilla/5.0'})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                    raw = r.read(65536)
                    body = raw.decode('utf-8', errors='ignore')
                    return {'alive': True, 'http_status': r.status,
                            'server': r.headers.get('Server', ''),
                            'title': self._title(body), 'body': body}
            except urllib.error.HTTPError as e:
                # A 4xx/5xx is still "alive" and its body matters for takeover.
                try:
                    body = e.read(65536).decode('utf-8', errors='ignore')
                except Exception:
                    body = ''
                return {'alive': True, 'http_status': e.code,
                        'server': e.headers.get('Server', '') if e.headers else '',
                        'title': self._title(body), 'body': body}
            except Exception:
                continue
        return {'alive': False, 'http_status': None, 'server': '',
                'title': '', 'body': ''}

    @staticmethod
    def _title(body: str) -> str:
        m = _TITLE_RE.search(body or '')
        return m.group(1).strip()[:120] if m else ''

    def check(self, host: str) -> Dict:
        """Full active check for one host: CNAME + liveness + takeover verdict."""
        cname_chain = self._cname_chain(host)
        probe = self._http_probe(host)
        verdict = classify(cname_chain, probe.get('body', ''))
        return {
            'host': host,
            'alive': probe['alive'],
            'http_status': probe['http_status'],
            'server': probe['server'],
            'title': probe['title'],
            'cname': cname_chain[-1] if cname_chain else '',
            'service': verdict['service'],
            'takeover': verdict['takeover'],
            'fingerprint': verdict['fingerprint_matched'],
        }

    def check_many(self, hosts: List[str],
                   on_result: Optional[Callable[[Dict], None]] = None,
                   on_progress: Optional[Callable[[int, int], None]] = None,
                   max_workers: int = 20) -> List[Dict]:
        """Check many hosts concurrently; returns the per-host result list."""
        self._cancel.clear()
        results: List[Dict] = []
        total = len(hosts)
        done = [0]
        lock = threading.Lock()

        def _one(host: str):
            if self._cancel.is_set():
                return None
            res = self.check(host)
            with lock:
                done[0] += 1
                if on_progress:
                    on_progress(done[0], total)
                if on_result:
                    on_result(res)
            return res

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for res in pool.map(_one, hosts):
                if res is not None:
                    results.append(res)
        return results
