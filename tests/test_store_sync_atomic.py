"""T6: FindingsStore.sync / AssetStore.sync run the whole lifecycle reconcile in
one transaction, so a crash/cancel mid-sync rolls back entirely (no half-updated
lifecycle, no spurious diff/alerts). Offline, no network.
"""
import pytest

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from core.findings_store import FindingsStore


def _raw(title, severity='Medium', detail='x', source=''):
    return {'title': title, 'severity': severity, 'detail': detail,
            'source': source}


def _fail_on_second(monkeypatch, store):
    """Make the store's per-row _upsert raise on its 2nd call (mid-sync crash)."""
    orig = store._upsert
    calls = {'n': 0}

    def flaky(*a, **k):
        calls['n'] += 1
        if calls['n'] == 2:
            raise RuntimeError('boom mid-sync')
        return orig(*a, **k)

    monkeypatch.setattr(store, '_upsert', flaky)


def test_findings_sync_is_atomic(tmp_path, monkeypatch):
    store = FindingsStore(tmp_path / 'findings.db')
    store.sync('p', 's0', [_raw('Baseline')])           # committed baseline
    assert len(store.list_findings('p')) == 1

    _fail_on_second(monkeypatch, store)
    with pytest.raises(RuntimeError):
        store.sync('p', 's1', [_raw('New one'), _raw('Other')])

    # The failed sync rolled back entirely: the first row it inserted is gone and
    # the committed baseline is untouched.
    findings = store.list_findings('p')
    assert len(findings) == 1
    assert findings[0]['title'] == 'Baseline'
    titles = {f['title'] for f in findings}
    assert 'New one' not in titles and 'Other' not in titles
    # No orphan events leaked from the rolled-back transaction.
    ev_titles = ' '.join(e.get('title', '') for e in store.project_events('p'))
    assert 'New one' not in ev_titles and 'Other' not in ev_titles


def test_assets_sync_is_atomic(tmp_path, monkeypatch):
    store = AssetStore(db_path=tmp_path / 'assets.db')
    store.sync('p', 's0', [Asset('domain', 'example.com')])   # committed baseline
    assert len(store.list_assets('p')) == 1

    _fail_on_second(monkeypatch, store)
    with pytest.raises(RuntimeError):
        store.sync('p', 's1', [Asset('ip', '1.1.1.1'),
                               Asset('ip', '2.2.2.2')])

    assets = store.list_assets('p')
    assert len(assets) == 1
    assert assets[0]['value'] == 'example.com'
    values = {a['value'] for a in assets}
    assert '1.1.1.1' not in values and '2.2.2.2' not in values


def test_findings_sync_still_commits_normally(tmp_path):
    """Control: without a mid-sync failure the reconcile persists as before."""
    store = FindingsStore(tmp_path / 'findings.db')
    res = store.sync('p', 's1', [_raw('A'), _raw('B')])
    assert len(res['new']) == 2
    assert len(store.list_findings('p')) == 2
