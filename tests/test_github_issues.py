"""GitHub Issues integration (core/github_issues.py, EPIC 16 wave 2) — offline.

The transport is stubbed (an injected fake client / patched _api_request), so
nothing touches the network. Covers: issue rendering from finding_knowledge, the
min-severity gate, idempotent create-only sync, and resilient error handling.
"""

from core import github_issues
from core.finding_fingerprint import fingerprint, scoped_id
from core.findings_store import FindingsStore


def _store(tmp_path):
    return FindingsStore(tmp_path / 'findings.db')


def _finding(title='SQL injection', category='vuln', rule_id='sqli',
             severity='high', location='https://x.com/a'):
    return {'id': fingerprint(category, rule_id, location), 'category': category,
            'rule_id': rule_id, 'title': title, 'severity': severity,
            'evidence': {'location': location}}


class _FakeClient:
    """Records create_issue calls and hands out sequential issue numbers."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail
        self._n = 100

    def create_issue(self, title, body, labels=None):
        if self.fail:
            raise RuntimeError('boom')
        self._n += 1
        self.calls.append({'title': title, 'body': body, 'labels': labels})
        return {'number': self._n, 'url': f'https://github.com/o/r/issues/{self._n}'}


# ── pure rendering ────────────────────────────────────────────────────────────

def test_issue_title_and_body_use_catalog():
    f = _finding()
    assert github_issues.issue_title(f) == '[high] SQL injection'
    body = github_issues.issue_body(f)
    assert '**Severity:** high' in body
    assert 'https://x.com/a' in body              # location surfaced
    assert f"finding:{f['id']}" in body           # mapping breadcrumb
    # finding_knowledge resolves a remediation section for a known category.
    assert 'Remediation' in body
    # OWASP/CWE class from the compliance SSOT (sqli → A03 / CWE-89).
    assert '**OWASP:** A03:2021' in body
    assert '**CWE:** CWE-89' in body


def test_issue_labels_add_severity():
    labels = github_issues.issue_labels(_finding(), ['site-analyzer'])
    assert labels[0] == 'site-analyzer' and 'high' in labels
    # de-dupes and drops blanks
    assert github_issues.issue_labels({'severity': 'high'}, ['high', '']) == ['high']


def test_meets_min_gate():
    assert github_issues._meets_min('critical', 'high') is True
    assert github_issues._meets_min('high', 'high') is True
    assert github_issues._meets_min('medium', 'high') is False


# ── build_client ──────────────────────────────────────────────────────────────

def test_build_client_requires_complete_config():
    assert github_issues.build_client({'enabled': False}) is None
    assert github_issues.build_client({'enabled': True, 'token': 't'}) is None
    c = github_issues.build_client({'enabled': True, 'token': 't',
                                    'owner': 'o', 'repo': 'r'})
    assert isinstance(c, github_issues.GitHubIssueClient)


# ── sync_findings (idempotent create-only) ────────────────────────────────────

def _cfg(**kw):
    base = {'enabled': True, 'token': 't', 'owner': 'o', 'repo': 'r'}
    base.update(kw)
    return base


def test_sync_disabled_noop(tmp_path):
    out = github_issues.sync_findings(_store(tmp_path), 'p', {'enabled': False})
    assert out['enabled'] is False and out['reason'] == 'disabled'


def test_sync_not_configured(tmp_path):
    out = github_issues.sync_findings(_store(tmp_path), 'p', {'enabled': True})
    assert out['reason'] == 'not configured' and out['created'] == []


def test_sync_creates_then_is_idempotent(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    s.upsert('p', f)
    client = _FakeClient()
    out = github_issues.sync_findings(s, 'p', _cfg(), client=client)
    assert out['total'] == 1 and len(out['created']) == 1 and out['skipped'] == 0
    assert out['created'][0]['number'] == 101
    assert len(client.calls) == 1
    # Re-run: the finding is now tracked → skipped, no second API call.
    out2 = github_issues.sync_findings(s, 'p', _cfg(), client=client)
    assert out2['created'] == [] and out2['skipped'] == 1
    assert len(client.calls) == 1


def test_sync_respects_min_severity(tmp_path):
    s = _store(tmp_path)
    s.upsert('p', _finding(severity='medium', rule_id='m', location='https://x/m'))
    s.upsert('p', _finding(severity='high', rule_id='h', location='https://x/h'))
    client = _FakeClient()
    out = github_issues.sync_findings(s, 'p', _cfg(min_severity='high'),
                                      client=client)
    # Only the high finding is pushed; the medium one is below the gate.
    assert out['total'] == 1 and len(out['created']) == 1


def test_sync_records_error_and_leaves_untracked(tmp_path):
    s = _store(tmp_path)
    f = _finding()
    sid = scoped_id('p', f['id'])
    s.upsert('p', f)
    out = github_issues.sync_findings(s, 'p', _cfg(), client=_FakeClient(fail=True))
    assert out['created'] == [] and len(out['errors']) == 1
    assert out['errors'][0]['id'] == sid
    # A failed create must not record a mapping → still untracked, retried next run.
    assert s.untracked_for_issue('p', [sid]) == [sid]


def test_create_issue_raises_on_non_2xx(tmp_path, monkeypatch):
    monkeypatch.setattr(github_issues, '_api_request',
                        lambda *a, **k: (422, {'message': 'Validation Failed'}))
    client = github_issues.GitHubIssueClient('t', 'o', 'r')
    try:
        client.create_issue('t', 'b')
    except RuntimeError as e:
        assert 'http 422' in str(e)
    else:
        raise AssertionError('expected RuntimeError on non-2xx')
