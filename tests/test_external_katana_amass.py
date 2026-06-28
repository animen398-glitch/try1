"""katana + amass external-tool integration — offline (binaries stubbed)."""

import json

import core.external_tools as ext
from core.attack_surface import build_surface
from core.collection_runner import CollectionRunner
from core.external_tools import (
    AmassRunner, HttpxRunner, KatanaRunner, SubfinderRunner,
    parse_amass_lines, parse_katana_lines,
)
from core.subdomain_scanner import SubdomainScanner


# ── katana parsing ──────────────────────────────────────────────────────────

def test_parse_katana_plain_urls_dedup_in_order():
    text = "\n".join([
        "https://ex.com/a", "https://ex.com/b", "https://ex.com/a",  # dup
        "not-a-url", "", "https://ex.com/c"])
    assert parse_katana_lines(text) == [
        "https://ex.com/a", "https://ex.com/b", "https://ex.com/c"]


def test_parse_katana_jsonl():
    text = "\n".join([
        json.dumps({"endpoint": "https://ex.com/x"}),
        json.dumps({"request": {"endpoint": "https://ex.com/y"}}),
        json.dumps({"url": "https://ex.com/z"}),
        "{bad json",
    ])
    assert parse_katana_lines(text) == [
        "https://ex.com/x", "https://ex.com/y", "https://ex.com/z"]


# ── amass parsing ───────────────────────────────────────────────────────────

def test_parse_amass_keeps_in_scope_fqdns():
    text = "\n".join([
        "api.ex.com", "WWW.EX.COM", "*.ex.com",     # in scope (case/wildcard)
        "ex.com", "other.org",                       # apex ok, out-of-scope drop
        "node 1 -> node 2", ""])                     # graph line / blank → drop
    out = parse_amass_lines(text, "ex.com")
    assert out == ["api.ex.com", "ex.com", "www.ex.com"]
    assert "other.org" not in out


# ── KatanaRunner ────────────────────────────────────────────────────────────

def test_katana_unavailable(monkeypatch):
    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: False))
    out = KatanaRunner().crawl('ex.com')
    assert out['status'] == 'Unavailable'
    assert out['endpoints'] == []
    assert out['url'] == 'https://ex.com'


def test_katana_success(monkeypatch):
    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 0, 'stdout': 'https://ex.com/a\nhttps://ex.com/b',
                            'stderr': '', 'timed_out': False})
    out = KatanaRunner().crawl('https://ex.com')
    assert out['status'] == 'Success'
    assert out['endpoints'] == ['https://ex.com/a', 'https://ex.com/b']


# ── AmassRunner ─────────────────────────────────────────────────────────────

def test_amass_unavailable(monkeypatch):
    monkeypatch.setattr(AmassRunner, 'available', staticmethod(lambda: False))
    out = AmassRunner().enumerate('https://ex.com/path')
    assert out['status'] == 'Unavailable'
    assert out['domain'] == 'ex.com'                 # URL → bare domain
    assert out['subdomains'] == []


def test_amass_success(monkeypatch):
    monkeypatch.setattr(AmassRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 0, 'stdout': 'api.ex.com\ndev.ex.com',
                            'stderr': '', 'timed_out': False})
    out = AmassRunner().enumerate('ex.com')
    assert out['status'] == 'Success'
    assert out['subdomains'] == ['api.ex.com', 'dev.ex.com']


# ── SubdomainScanner amass integration ──────────────────────────────────────

def test_subdomain_scan_uses_amass_when_enabled(monkeypatch):
    # Stub the external runner so no subprocess/network is touched.
    monkeypatch.setattr(AmassRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        AmassRunner, 'enumerate',
        lambda self, domain: {'status': 'Success',
                              'subdomains': ['amassed.ex.com']})
    # Keep DNS resolution offline.
    monkeypatch.setattr('socket.gethostbyname', lambda h: '1.2.3.4')

    scanner = SubdomainScanner(data_registry=_NullRegistry())
    res = scanner.scan('ex.com', passive=False, brute=False, amass=True)
    subs = [e['subdomain'] for e in res['results']]
    assert 'amassed.ex.com' in subs
    assert any(e['source'] == 'amass' for e in res['results'])


def test_subdomain_scan_skips_amass_when_disabled(monkeypatch):
    monkeypatch.setattr(AmassRunner, 'available', staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(AmassRunner, 'enumerate',
                        lambda self, d: called.append(d) or {'subdomains': []})
    scanner = SubdomainScanner(data_registry=_NullRegistry())
    scanner.scan('ex.com', passive=False, brute=False, amass=False)
    assert called == []                              # opt-in: never invoked


# ── CollectionRunner katana integration ─────────────────────────────────────

def test_collection_katana_phase_and_graph(monkeypatch):
    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(
        KatanaRunner, 'crawl',
        lambda self, url: {'status': 'Success',
                           'endpoints': ['https://ex.com/api/v1', 'https://ex.com/x']})
    runner = CollectionRunner(katana=True)
    phase = runner._phase_katana('https://ex.com')
    assert phase['status'] == 'Success'
    assert phase['data']['endpoints'][0] == 'https://ex.com/api/v1'

    # Endpoints feed the attack-surface graph as their own category.
    report = {'domain': 'ex.com', 'phases': {'katana': phase}}
    surface = build_surface(report)
    eps = next(c for c in surface['categories'] if c['name'] == 'Endpoints')
    assert eps['count'] == 2


def test_collection_katana_skipped_when_unavailable(monkeypatch):
    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: False))
    phase = CollectionRunner(katana=True)._phase_katana('https://ex.com')
    assert phase['status'] == 'Skipped'


def test_default_collection_has_no_katana():
    assert CollectionRunner().katana is False


class _NullRegistry:
    def add_record(self, *a, **k):
        return 0


def test_katana_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(KatanaRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 1, 'stdout': 'https://ex.com/partial',
                            'stderr': 'crawl failed', 'timed_out': False})
    out = KatanaRunner().crawl('https://ex.com')
    assert out['status'] == 'Error'
    assert out['endpoints'] == []
    assert 'crawl failed' in out['error']


def test_amass_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(AmassRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 1, 'stdout': '', 'stderr': 'config error',
                            'timed_out': False})
    out = AmassRunner().enumerate('ex.com')
    assert out['status'] == 'Error'
    assert out['subdomains'] == []
    assert 'config error' in out['error']


def test_subfinder_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(SubfinderRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 1, 'stdout': '', 'stderr': 'rate limited',
                            'timed_out': False})
    out = SubfinderRunner().enumerate('ex.com')
    assert out['status'] == 'Error'
    assert out['subdomains'] == []
    assert 'rate limited' in out['error']


def test_httpx_nonzero_exit_is_error(monkeypatch):
    monkeypatch.setattr(HttpxRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 1, 'stdout': '', 'stderr': 'bad input',
                            'timed_out': False})
    out = HttpxRunner().probe(['api.ex.com'])
    assert out['status'] == 'Error'
    assert out['results'] == []
    assert 'bad input' in out['error']
