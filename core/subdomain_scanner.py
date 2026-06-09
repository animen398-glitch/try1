"""
SubdomainScanner — passive enumeration (crt.sh, HackerTarget) +
active DNS brute-force with concurrent resolution.
"""
import concurrent.futures
import json
import socket
import threading
import time
import urllib.request
from typing import Callable, Dict, List, Optional


_CRTSH_URL        = 'https://crt.sh/?q=%.{domain}&output=json'
_HACKERTARGET_URL = 'https://api.hackertarget.com/hostsearch/?q={domain}'
_FETCH_TIMEOUT    = 10
_DNS_TIMEOUT      = 3

_WORDLIST: tuple = (
    'www', 'www2', 'www3', 'mail', 'mail1', 'mail2', 'smtp', 'smtp1', 'smtp2',
    'pop', 'pop3', 'imap', 'webmail', 'mx', 'mx1', 'mx2',
    'ftp', 'sftp', 'ns', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
    'admin', 'administrator', 'panel', 'dashboard', 'manage', 'cpanel',
    'whm', 'plesk', 'directadmin', 'webmin', 'phpmyadmin',
    'api', 'api1', 'api2', 'api3', 'api-v1', 'api-v2', 'graphql', 'rest',
    'app', 'app1', 'app2', 'mobile', 'wap', 'pwa',
    'dev', 'dev1', 'dev2', 'develop', 'development',
    'test', 'test1', 'test2', 'testing', 'qa', 'uat',
    'stage', 'staging', 'stg', 'sandbox', 'demo', 'beta', 'alpha', 'preview',
    'prod', 'production', 'live', 'release', 'rc',
    'web', 'web1', 'web2', 'site', 'portal', 'home',
    'static', 'assets', 'cdn', 'cdn1', 'cdn2', 'media', 'img', 'images',
    'video', 'videos', 'files', 'upload', 'uploads', 'download', 'downloads',
    'store', 'shop', 'cart', 'pay', 'payment', 'checkout', 'billing',
    'account', 'accounts', 'my', 'user', 'users', 'profile', 'members',
    'login', 'auth', 'sso', 'oauth', 'id', 'identity', 'iam', 'idp',
    'secure', 'ssl', 'vpn', 'remote', 'ssh', 'rdp', 'citrix',
    'git', 'gitlab', 'github', 'bitbucket', 'svn', 'cvs', 'repo',
    'jira', 'confluence', 'wiki', 'docs', 'help', 'support', 'kb', 'faq',
    'helpdesk', 'tickets', 'desk', 'service', 'crm', 'erp',
    'blog', 'news', 'press', 'events', 'calendar', 'newsletter', 'rss',
    'forum', 'community', 'chat', 'irc', 'slack',
    'jobs', 'careers', 'partners', 'affiliate', 'ads', 'adserver',
    'analytics', 'tracking', 'stats', 'metrics', 'reports', 'reporting',
    'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
    'elastic', 'es', 'solr', 'search', 'elastic1',
    'ci', 'cd', 'jenkins', 'build', 'builds', 'deploy', 'deployments',
    'k8s', 'kubernetes', 'docker', 'registry', 'harbor', 'nexus',
    'monitor', 'monitoring', 'grafana', 'kibana', 'prometheus',
    'alertmanager', 'sentry', 'nagios', 'zabbix', 'icinga',
    'logs', 'log', 'logging', 'logstash', 'splunk', 'fluentd',
    'socket', 'ws', 'wss', 'realtime', 'push', 'notify', 'webhook',
    'cloud', 's3', 'storage', 'backup', 'backups', 'archive',
    'office', 'intranet', 'extranet', 'internal', 'corp', 'corporate',
    'vpn1', 'vpn2', 'gateway', 'gw', 'proxy', 'lb', 'loadbalancer',
    'server', 'server1', 'server2', 'host', 'vps', 'node', 'node1',
    'eu', 'us', 'uk', 'de', 'fr', 'ru', 'cn', 'au', 'ca', 'jp', 'br',
    'east', 'west', 'north', 'south', 'nyc', 'lon', 'ams', 'fra', 'sin',
    'v1', 'v2', 'v3', 'new', 'old', 'legacy', 'classic', 'next',
    'status', 'uptime', 'health', 'ping',
    'mailer', 'sendgrid', 'mailgun', 'postfix', 'relay',
    'socket.io', 'push-server', 'notification',
    'translate', 'i18n', 'l10n',
    'share', 'fileserver', 'nfs', 'smb',
)


class SubdomainScanner:
    """
    Enumerates subdomains via:
    1. Passive:   crt.sh certificate transparency + HackerTarget
    2. Active:    DNS brute-force against a built-in wordlist
    """

    def __init__(self):
        self._cancel = threading.Event()

    def cancel(self):
        """Signal the scanner to stop at the next checkpoint."""
        self._cancel.set()

    def scan(
        self,
        domain: str,
        on_found: Optional[Callable[[Dict], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        passive: bool = True,
        brute: bool = True,
        max_workers: int = 40,
    ) -> Dict:
        """
        Run passive + brute-force enumeration.
        on_found(entry)           called for each new result
        on_progress(current, total) called during brute-force phase
        Returns summary dict: {status, domain, total, results, elapsed}
        """
        self._cancel.clear()
        domain = (
            domain.strip().lower()
            .replace('https://', '').replace('http://', '')
            .split('/')[0]
        )

        found: Dict[str, Dict] = {}
        t_start = time.time()

        def _record(subdomain: str, ip: str, source: str):
            if subdomain in found or not subdomain:
                return
            entry = {
                'subdomain': subdomain,
                'ip': ip or '',
                'status': 'Live' if ip else 'Unknown',
                'source': source,
            }
            found[subdomain] = entry
            if on_found:
                on_found(entry)

        def _resolve(hostname: str) -> Optional[str]:
            try:
                socket.setdefaulttimeout(_DNS_TIMEOUT)
                return socket.gethostbyname(hostname)
            except Exception:
                return None

        # ── Phase 1: crt.sh (certificate transparency) ───────────────────
        if passive and not self._cancel.is_set():
            if on_progress:
                on_progress(0, 0)  # indeterminate
            try:
                req = urllib.request.Request(
                    _CRTSH_URL.format(domain=domain),
                    headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'},
                )
                with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as r:
                    data = json.loads(r.read().decode('utf-8', errors='ignore'))
                raw_names: set = set()
                for entry in data:
                    for name in entry.get('name_value', '').splitlines():
                        name = name.strip().lstrip('*.').lower()
                        if name.endswith(f'.{domain}'):
                            raw_names.add(name)
                        elif name == domain:
                            raw_names.add(name)
                for name in sorted(raw_names):
                    if self._cancel.is_set():
                        break
                    ip = _resolve(name)
                    _record(name, ip or '', 'crt.sh')
            except Exception:
                pass

        # ── Phase 2: HackerTarget passive API ────────────────────────────
        if passive and not self._cancel.is_set():
            try:
                req = urllib.request.Request(
                    _HACKERTARGET_URL.format(domain=domain),
                    headers={'User-Agent': 'Mozilla/5.0'},
                )
                with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as r:
                    text = r.read().decode('utf-8', errors='ignore')
                for line in text.splitlines():
                    if self._cancel.is_set():
                        break
                    if ',' not in line or 'API count' in line:
                        continue
                    parts = line.split(',', 1)
                    sub, ip = parts[0].strip().lower(), parts[1].strip()
                    if sub.endswith(f'.{domain}') or sub == domain:
                        _record(sub, ip, 'hackertarget')
            except Exception:
                pass

        # ── Phase 3: DNS brute-force ──────────────────────────────────────
        if brute and not self._cancel.is_set():
            total = len(_WORDLIST)
            counter = [0]

            def _probe(word: str):
                if self._cancel.is_set():
                    return
                hostname = f'{word}.{domain}'
                ip = _resolve(hostname)
                counter[0] += 1
                if on_progress:
                    on_progress(counter[0], total)
                if ip:
                    _record(hostname, ip, 'brute')

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                list(pool.map(_probe, _WORDLIST))

        elapsed = round(time.time() - t_start, 2)
        results = list(found.values())
        return {
            'status': 'Cancelled' if self._cancel.is_set() else 'Success',
            'domain': domain,
            'total': len(results),
            'results': results,
            'elapsed': elapsed,
        }
