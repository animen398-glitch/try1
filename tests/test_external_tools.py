"""External tool integration (nuclei) — parsing, gating, collection merge.

Offline: the nuclei binary is never invoked; run_command/availability are
stubbed, matching how the scrapy subprocess is tested.
"""

import json
import subprocess

import core.external_tools as ext
from core.collection_runner import CollectionRunner
from core.external_tools import NucleiRunner, parse_nuclei_jsonl


_SAMPLE_JSONL = "\n".join(json.dumps(o) for o in [
    {'template-id': 'tech-detect', 'info': {'name': 'Tech', 'severity': 'info'},
     'host': 'https://ex.com', 'matched-at': 'https://ex.com'},
    {'template-id': 'CVE-2024-1', 'info': {'name': 'RCE', 'severity': 'critical'},
     'matched-at': 'https://ex.com/x'},
    {'template-id': 'weak-tls', 'info': {'name': 'Weak TLS', 'severity': 'medium'},
     'host': 'ex.com'},
])


# ── parse_nuclei_jsonl ──────────────────────────────────────────────────────

def test_parse_maps_severity_and_fields():
    findings = parse_nuclei_jsonl(_SAMPLE_JSONL)
    assert len(findings) == 3
    by_title = {f['title']: f for f in findings}
    assert by_title['RCE']['severity'] == 'High'       # critical → High
    assert by_title['Weak TLS']['severity'] == 'Medium'
    assert by_title['Tech']['severity'] == 'Info'      # info → Info
    # Each finding is tagged and carries template-id + location in detail.
    assert all(f['source'] == 'nuclei' for f in findings)
    assert 'CVE-2024-1' in by_title['RCE']['detail']


def test_parse_skips_blank_and_malformed_lines():
    text = '\n'.join(['', '{not json', json.dumps(
        {'info': {'name': 'OK', 'severity': 'low'}}), '   '])
    findings = parse_nuclei_jsonl(text)
    assert len(findings) == 1
    assert findings[0]['title'] == 'OK'
    assert findings[0]['severity'] == 'Info'           # low → Info


def test_parse_falls_back_to_template_id_for_title():
    text = json.dumps({'template-id': 'only-id', 'info': {'severity': 'high'}})
    findings = parse_nuclei_jsonl(text)
    assert findings[0]['title'] == 'only-id'


def test_parse_captures_template_knowledge():
    # F-O2: nuclei info.description/impact/remediation carried onto the finding.
    text = json.dumps({'template-id': 't', 'info': {
        'name': 'X', 'severity': 'high', 'description': 'A flaw',
        'impact': 'RCE possible', 'remediation': 'Patch it'}})
    f = parse_nuclei_jsonl(text)[0]
    assert f['description'] == 'A flaw'
    assert f['impact'] == 'RCE possible'
    assert f['remediation'] == 'Patch it'


# ── NucleiRunner ────────────────────────────────────────────────────────────

def test_scan_unavailable_when_binary_missing(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: False))
    out = NucleiRunner().scan('ex.com')
    assert out['status'] == 'Unavailable'
    assert 'nuclei' in out['error'].lower()
    assert out['findings'] == []
    assert out['url'] == 'https://ex.com'              # scheme normalised


def test_scan_success_parses_stub_output(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 0, 'stdout': _SAMPLE_JSONL, 'stderr': '',
                            'timed_out': False})
    out = NucleiRunner().scan('https://ex.com')
    assert out['status'] == 'Success'
    assert len(out['findings']) == 3
    assert out['truncated'] is False


def test_scan_reports_run_error(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': None, 'stdout': '', 'stderr': '',
                            'timed_out': False, 'error': 'binary not found on PATH'})
    out = NucleiRunner().scan('https://ex.com')
    assert out['status'] == 'Error'
    assert 'not found' in out['error']


def test_scan_reports_nonzero_exit(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 2, 'stdout': '', 'stderr': 'template parse failed',
                            'timed_out': False})
    out = NucleiRunner().scan('https://ex.com')
    assert out['status'] == 'Error'
    assert out['findings'] == []
    assert 'code 2' in out['error']
    assert 'template parse failed' in out['error']


def test_nonzero_exit_does_not_expose_stdout(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': 2, 'stdout': 'SECRET_OUTPUT', 'stderr': '',
                            'timed_out': False})
    out = NucleiRunner().scan('https://ex.com')
    assert out['status'] == 'Error'
    assert out['error'] == 'nuclei exited with code 2'
    assert 'SECRET_OUTPUT' not in repr(out)


def test_scan_timeout_returns_partial(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    monkeypatch.setattr(ext, 'run_command',
                        lambda cmd, timeout, input_text=None: {
                            'rc': None, 'stdout': _SAMPLE_JSONL, 'stderr': '',
                            'timed_out': True})
    out = NucleiRunner().scan('https://ex.com')
    assert out['status'] == 'Success'
    assert out['truncated'] is True
    assert len(out['findings']) == 3


# ── collection merge ────────────────────────────────────────────────────────

def test_collection_merges_nuclei_findings(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))

    def fake_scan(self, url):
        return {'status': 'Success', 'findings': [
            {'severity': 'High', 'title': 'RCE', 'detail': '', 'source': 'nuclei'}]}

    monkeypatch.setattr(NucleiRunner, 'scan', fake_scan)
    runner = CollectionRunner(nuclei=True)
    findings = [{'severity': 'Info', 'title': 'native', 'source': 'vuln'}]
    added = runner._merge_nuclei('https://ex.com', findings)
    assert added == 1
    assert any(f['source'] == 'nuclei' for f in findings)
    assert len(findings) == 2


def test_collection_skips_nuclei_when_disabled(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: True))
    runner = CollectionRunner(nuclei=False)          # opt-in: off
    findings = []
    assert runner._merge_nuclei('https://ex.com', findings) == 0
    assert findings == []


def test_collection_skips_nuclei_when_unavailable(monkeypatch):
    monkeypatch.setattr(NucleiRunner, 'available', staticmethod(lambda: False))
    runner = CollectionRunner(nuclei=True)
    assert runner._merge_nuclei('https://ex.com', []) == 0


def test_default_collection_has_no_nuclei():
    assert CollectionRunner().nuclei is False


# ── T11: run_command output cap / graceful degradation ──────────────────────


class _Proc:
    def __init__(self, stdout='', stderr='', rc=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rc


def test_run_command_caps_stdout(monkeypatch):
    monkeypatch.setattr(ext, 'run_hidden', lambda *a, **k: _Proc(stdout='x' * 100))
    out = ext.run_command(['tool'], timeout=1, max_output=10)
    assert out['truncated'] is True
    assert out['stdout'] == 'x' * 10
    assert out['timed_out'] is False


def test_run_command_no_truncation_under_cap(monkeypatch):
    monkeypatch.setattr(ext, 'run_hidden',
                        lambda *a, **k: _Proc(stdout='hi', stderr='e'))
    out = ext.run_command(['tool'], timeout=1, max_output=10)
    assert out['truncated'] is False
    assert out['stdout'] == 'hi'


def test_run_command_uses_default_cap(monkeypatch):
    monkeypatch.setattr(ext, 'MAX_OUTPUT', 5)
    monkeypatch.setattr(ext, 'run_hidden', lambda *a, **k: _Proc(stdout='abcdefgh'))
    out = ext.run_command(['tool'], timeout=1)  # no max_output → module default
    assert out['truncated'] is True
    assert out['stdout'] == 'abcde'


def test_run_command_timeout_caps_partial(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd='tool', timeout=1, output='y' * 100)

    monkeypatch.setattr(ext, 'run_hidden', boom)
    out = ext.run_command(['tool'], timeout=1, max_output=10)
    assert out['timed_out'] is True
    assert out['truncated'] is True
    assert out['stdout'] == 'y' * 10


def test_run_command_missing_binary_graceful(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(ext, 'run_hidden', boom)
    out = ext.run_command(['nope'], timeout=1)
    assert out.get('error')
    assert out['stdout'] == '' and out['truncated'] is False
