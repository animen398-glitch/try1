"""tests/test_cancel_wiring.py

Prompt cancellation for the two long operations: Full Collection and the
subdomain scan thread their own cancel Event into the external-tool runners
(via ``set_cancel_event``), so pressing Stop kills a running child process tree
promptly instead of waiting for it to finish. Offline — runners are stubbed.
"""

from core import external_tools as ext
from core.subdomain_scanner import SubdomainScanner


class _Recorder:
    """External-tool runner stub that records the cancel token it was handed."""

    seen = None

    def __init__(self, *a, **k):
        pass

    @staticmethod
    def available():
        return True

    def set_progress_callback(self, cb):
        pass

    def set_cancel_event(self, ev):
        _Recorder.seen = ev

    # enumerator / crawler / prober / scanner surfaces used by the callers
    def enumerate(self, domain):
        return {'subdomains': []}

    def probe(self, hosts):
        return {'results': []}

    def crawl(self, url):
        return {'status': 'Success', 'endpoints': []}

    def scan(self, url):
        return {'status': 'Success', 'findings': []}


def _fresh_recorder():
    _Recorder.seen = None
    return _Recorder


# ── subdomain scan ────────────────────────────────────────────────────────────

def test_subdomain_amass_receives_scanner_cancel_event(monkeypatch):
    monkeypatch.setattr(ext, 'AmassRunner', _fresh_recorder())
    sc = SubdomainScanner()
    sc._passive_amass('example.com')
    assert _Recorder.seen is sc._cancel


def test_subdomain_subfinder_receives_scanner_cancel_event(monkeypatch):
    monkeypatch.setattr(ext, 'SubfinderRunner', _fresh_recorder())
    sc = SubdomainScanner()
    sc._passive_subfinder('example.com')
    assert _Recorder.seen is sc._cancel


def test_subdomain_httpx_receives_scanner_cancel_event(monkeypatch):
    monkeypatch.setattr(ext, 'HttpxRunner', _fresh_recorder())
    sc = SubdomainScanner()
    sc._enrich_httpx({'a.example.com': {}}, on_update=None)
    assert _Recorder.seen is sc._cancel


# ── Full Collection ───────────────────────────────────────────────────────────

def test_collection_nuclei_receives_runner_cancel_event(monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'NucleiRunner', _fresh_recorder())
    runner = cr.CollectionRunner(nuclei=True)
    runner._merge_nuclei('https://example.com', [])
    assert _Recorder.seen is runner._cancel


def test_collection_katana_receives_runner_cancel_event(monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'KatanaRunner', _fresh_recorder())
    runner = cr.CollectionRunner(katana=True)
    runner._phase_katana('https://example.com')
    assert _Recorder.seen is runner._cancel
