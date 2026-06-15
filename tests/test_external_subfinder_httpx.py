"""subfinder + httpx external-tool integration — offline (binaries stubbed)."""

import json

import core.external_tools as ext
from core.external_tools import (
    HttpxRunner, SubfinderRunner, parse_fqdn_lines, parse_httpx_jsonl,
)
from core.subdomain_scanner import SubdomainScanner


# ── shared FQDN parser (amass + subfinder) ───────────────────────────────────

def test_parse_fqdn_lines_keeps_in_scope():
    text = "\n".join([
        "api.ex.com", "WWW.EX.COM", "*.ex.com",      # in scope (case/wildcard)
        "ex.com", "other.org",                        # apex ok, out-of-scope drop
        "node 1 -> node 2", ""])                      # graph line / blank → drop
    out = parse_fqdn_lines(text, "ex.com")
    assert out == ["api.ex.com", "ex.com", "www.ex.com"]
    assert "other.org" not in out


def test_parse_amass_lines_alias_is_shared_impl():
    # Back-compat alias must still resolve to the shared parser.
    assert ext.parse_amass_lines is parse_fqdn_lines


# ── SubfinderRunner ──────────────────────────────────────────────────────────

def test_subfinder_unavailable(monkeypatch):
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: False))
    out = SubfinderRunner().enumerate('https://ex.com/path')
    assert out['status'] == 'Unavailable'
    assert out['domain'] == 'ex.com'                  # URL → bare domain
    assert out['subdomains'] == []


def test_subfinder_success(monkeypatch):
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 0, 'stdout': 'api.ex.com\ndev.ex.com',
                            'stderr': '', 'timed_out': False})
    out = SubfinderRunner().enumerate('ex.com')
    assert out['status'] == 'Success'
    assert out['subdomains'] == ['api.ex.com', 'dev.ex.com']


# ── httpx parsing ────────────────────────────────────────────────────────────

def test_parse_httpx_jsonl():
    text = "\n".join([
        json.dumps({"input": "api.ex.com", "url": "https://api.ex.com",
                    "status_code": 200, "title": "API", "webserver": "nginx",
                    "tech": ["nginx", "PHP"]}),
        json.dumps({"host": "dev.ex.com", "url": "https://dev.ex.com",
                    "status-code": 403}),               # hyphenated variant
        "{bad json", "",
    ])
    out = parse_httpx_jsonl(text)
    assert len(out) == 2
    assert out[0]['host'] == 'api.ex.com'
    assert out[0]['status_code'] == 200
    assert out[0]['tech'] == ['nginx', 'PHP']
    assert out[1]['host'] == 'dev.ex.com'
    assert out[1]['status_code'] == 403


# ── HttpxRunner ──────────────────────────────────────────────────────────────

def test_httpx_unavailable(monkeypatch):
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: False))
    out = HttpxRunner().probe(['api.ex.com'])
    assert out['status'] == 'Unavailable'
    assert out['results'] == []


def test_httpx_empty_hosts_short_circuits(monkeypatch):
    # No hosts → Success with no results and no subprocess call.
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError('run_command must not be called')))
    out = HttpxRunner().probe([])
    assert out['status'] == 'Success'
    assert out['results'] == []


def test_httpx_success_feeds_input_on_stdin(monkeypatch):
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: True))
    seen = {}

    def _fake_run(cmd, timeout, input_text=None):
        seen['input'] = input_text
        return {'rc': 0, 'timed_out': False, 'stderr': '',
                'stdout': json.dumps({"input": "api.ex.com",
                                      "url": "https://api.ex.com",
                                      "status_code": 200})}
    monkeypatch.setattr(ext, 'run_command', _fake_run)
    out = HttpxRunner().probe(['api.ex.com', 'dev.ex.com'])
    assert out['status'] == 'Success'
    assert out['results'][0]['host'] == 'api.ex.com'
    assert 'api.ex.com' in seen['input'] and 'dev.ex.com' in seen['input']


# ── SubdomainScanner integration ─────────────────────────────────────────────

def test_subdomain_scan_uses_subfinder_when_enabled(monkeypatch):
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        SubfinderRunner, 'enumerate',
        lambda self, domain: {'status': 'Success',
                              'subdomains': ['found.ex.com']})
    monkeypatch.setattr('socket.gethostbyname', lambda h: '1.2.3.4')

    scanner = SubdomainScanner(data_registry=_NullRegistry())
    res = scanner.scan('ex.com', passive=False, brute=False, subfinder=True)
    assert any(e['source'] == 'subfinder' and e['subdomain'] == 'found.ex.com'
               for e in res['results'])


def test_subdomain_scan_skips_subfinder_when_disabled(monkeypatch):
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(SubfinderRunner, 'enumerate',
                        lambda self, d: called.append(d) or {'subdomains': []})
    scanner = SubdomainScanner(data_registry=_NullRegistry())
    scanner.scan('ex.com', passive=False, brute=False, subfinder=False)
    assert called == []                               # opt-in: never invoked


def test_subdomain_scan_httpx_enriches_hosts(monkeypatch):
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        HttpxRunner, 'probe',
        lambda self, hosts: {'status': 'Success', 'results': [
            {'host': 'api.ex.com', 'url': 'https://api.ex.com',
             'status_code': 200, 'title': 'API', 'webserver': 'nginx',
             'tech': ['nginx']}]})
    # Seed one host via a stubbed subfinder so httpx has something to probe.
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        SubfinderRunner, 'enumerate',
        lambda self, d: {'status': 'Success', 'subdomains': ['api.ex.com']})
    monkeypatch.setattr('socket.gethostbyname', lambda h: '1.2.3.4')

    scanner = SubdomainScanner(data_registry=_NullRegistry())
    res = scanner.scan('ex.com', passive=False, brute=False,
                       subfinder=True, httpx=True)
    entry = next(e for e in res['results'] if e['subdomain'] == 'api.ex.com')
    assert entry['alive'] is True
    assert entry['http_status'] == 200
    assert entry['tech'] == ['nginx']
    assert entry['status'] == 'HTTP 200'
    assert res['live_count'] == 1                     # alive flag counted


def test_subdomain_scan_skips_httpx_when_disabled(monkeypatch):
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(HttpxRunner, 'probe',
                        lambda self, hosts: called.append(hosts) or {'results': []})
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        SubfinderRunner, 'enumerate',
        lambda self, d: {'status': 'Success', 'subdomains': ['api.ex.com']})
    monkeypatch.setattr('socket.gethostbyname', lambda h: '1.2.3.4')
    scanner = SubdomainScanner(data_registry=_NullRegistry())
    scanner.scan('ex.com', passive=False, brute=False, subfinder=True, httpx=False)
    assert called == []                               # opt-in: never invoked


class _NullRegistry:
    def add_record(self, *a, **k):
        return 0
