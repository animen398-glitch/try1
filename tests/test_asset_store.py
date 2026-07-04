"""Asset Inventory persistence (core/asset_store.py) — offline SQLite."""

import pytest

from core.asset_adapter import Asset
from core.asset_store import AssetStore
from core.finding_fingerprint import scoped_id


def _store(tmp_path):
    return AssetStore(db_path=tmp_path / 'assets.db')


def _asset(atype, value, **attrs):
    return Asset(atype, value, attrs=attrs)


# ── schema / upsert ───────────────────────────────────────────────────────────

def test_schema_idempotent_and_versioned(tmp_path):
    s = _store(tmp_path)
    AssetStore(db_path=tmp_path / 'assets.db')          # re-init must not raise
    with s._connect() as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 1


def test_upsert_create_then_seen(tmp_path):
    s = _store(tmp_path)
    a = _asset('subdomain', 'api.x.com')
    r1 = s.upsert('p1', a.to_store(), scan_id='s1', now='2026-01-01T00:00:00')
    assert r1['created'] is True
    assert r1['asset']['status'] == 'ACTIVE'

    r2 = s.upsert('p1', a.to_store(), scan_id='s2', now='2026-02-01T00:00:00')
    assert r2['created'] is False
    assert r2['asset']['first_seen_at'] == '2026-01-01T00:00:00'   # preserved
    assert r2['asset']['last_seen_at'] == '2026-02-01T00:00:00'    # bumped
    types = [e['type'] for e in s.events(r1['asset']['id'])]
    assert types == ['CREATED', 'SEEN']


def test_same_asset_two_projects_are_distinct_rows(tmp_path):
    s = _store(tmp_path)
    a = _asset('ip', '1.2.3.4')
    s.upsert('p1', a.to_store())
    s.upsert('p2', a.to_store())
    assert len(s.list_assets('p1')) == 1
    assert len(s.list_assets('p2')) == 1
    assert s.list_assets('p1')[0]['id'] != s.list_assets('p2')[0]['id']


def test_set_status_validation_and_noop(tmp_path):
    s = _store(tmp_path)
    res = s.upsert('p1', _asset('ip', '1.1.1.1').to_store())
    aid = res['asset']['id']
    with pytest.raises(ValueError):
        s.set_status(aid, 'BOGUS', event_type='GONE')
    with pytest.raises(KeyError):
        s.set_status('nope', 'GONE', event_type='GONE')
    s.set_status(aid, 'ACTIVE', event_type='SEEN')      # unchanged → no event
    assert [e['type'] for e in s.events(aid)] == ['CREATED']


# ── sync lifecycle ────────────────────────────────────────────────────────────

def test_sync_new_recurring_gone_reappeared(tmp_path):
    s = _store(tmp_path)
    sub = _asset('subdomain', 'api.x.com')
    dom = _asset('domain', 'x.com')

    # Scan 1: both new.
    r1 = s.sync('p1', 's1', [dom, sub])
    assert len(r1['new']) == 2 and r1['summary']['active'] == 2

    # Scan 2: subdomain absent, its phase IN scope → GONE; domain recurring.
    r2 = s.sync('p1', 's2', [dom], in_scope=lambda t: True)
    assert [g['type'] for g in r2['gone']] == ['subdomain']
    assert len(r2['recurring']) == 1
    assert s.summary('p1')['active'] == 1

    # Scan 3: subdomain back → REAPPEARED → ACTIVE.
    r3 = s.sync('p1', 's3', [dom, sub], in_scope=lambda t: True)
    assert len(r3['reappeared']) == 1
    assert s.summary('p1')['active'] == 2


def test_sync_out_of_scope_type_not_marked_gone(tmp_path):
    s = _store(tmp_path)
    sub = _asset('subdomain', 'api.x.com')
    s.sync('p1', 's1', [sub])
    # Next scan didn't run the subdomain phase → must NOT mark it gone.
    r = s.sync('p1', 's2', [], in_scope=lambda t: t != 'subdomain')
    assert r['gone'] == []
    assert s.summary('p1')['active'] == 1


def test_sync_per_source_gating_does_not_flap_cert_only_subdomain(tmp_path):
    # A subdomain seen only in the TLS certificate (source='certificate').
    s = _store(tmp_path)
    cert_sub = _asset('subdomain', 'mail.x.com', source='certificate')
    s.sync('p1', 's1', [cert_sub])
    # Next scan ran the active subdomain phase but NOT the cert phase. Per-type
    # gating would flap it GONE (its type is in scope); per-source must not.
    ran = {'subdomains'}
    r = s.sync('p1', 's2', [], in_scope=lambda t: True,
               source_in_scope=lambda src: src in ran)
    assert r['gone'] == []
    assert s.summary('p1')['active'] == 1
    # When the cert phase DOES run and the name is absent → genuinely GONE.
    ran = {'subdomains', 'certificate'}
    r2 = s.sync('p1', 's3', [], in_scope=lambda t: True,
                source_in_scope=lambda src: src in ran)
    assert [g['type'] for g in r2['gone']] == ['subdomain']
    assert s.summary('p1')['active'] == 0


def test_sync_source_gating_falls_back_to_type_when_no_source(tmp_path):
    # A legacy row with no stored source → type gating still applies.
    s = _store(tmp_path)
    s.sync('p1', 's1', [_asset('subdomain', 'api.x.com')])   # no source attr
    r = s.sync('p1', 's2', [], in_scope=lambda t: t != 'subdomain',
               source_in_scope=lambda src: True)
    assert r['gone'] == []                                    # type gate wins
    assert s.summary('p1')['active'] == 1


# ── reads ─────────────────────────────────────────────────────────────────────

def test_list_filters_and_summary(tmp_path):
    s = _store(tmp_path)
    s.sync('p1', 's1', [_asset('subdomain', 'a.x.com'),
                        _asset('subdomain', 'b.x.com'),
                        _asset('ip', '1.2.3.4')])
    assert len(s.list_assets('p1', type='subdomain')) == 2
    assert len(s.list_assets('p1', type='ip')) == 1
    summ = s.summary('p1')
    assert summ['total'] == 3 and summ['active'] == 3
    assert summ['by_type'] == {'subdomain': 2, 'ip': 1}


def test_store_id_is_project_scoped(tmp_path):
    s = _store(tmp_path)
    a = _asset('asn', 'AS1')
    s.upsert('proj', a.to_store())
    assert s.list_assets('proj')[0]['id'] == scoped_id('proj', a.id)


def test_projects_lists_distinct_with_active_counts(tmp_path):
    s = _store(tmp_path)
    s.sync('p1', 's1', [_asset('subdomain', 'a.x.com'),
                        _asset('subdomain', 'b.x.com')])
    s.sync('p2', 's1', [_asset('ip', '1.2.3.4')])
    # b.x.com goes GONE in p1.
    s.sync('p1', 's2', [_asset('subdomain', 'a.x.com')], in_scope=lambda t: True)
    by_name = {p['project']: p for p in s.projects()}
    assert by_name['p1']['total'] == 2 and by_name['p1']['active'] == 1
    assert by_name['p2']['total'] == 1 and by_name['p2']['active'] == 1


def test_project_events_enriched_and_scoped(tmp_path):
    s = _store(tmp_path)
    s.sync('p1', 's1', [_asset('subdomain', 'api.x.com')])
    s.sync('p1', 's2', [], in_scope=lambda t: True)          # → GONE
    s.sync('p2', 's1', [_asset('ip', '9.9.9.9')])            # other project
    evs = s.project_events('p1')
    assert [e['type'] for e in evs] == ['CREATED', 'GONE']
    assert evs[0]['asset_type'] == 'subdomain'
    assert evs[0]['value'] == 'api.x.com'
    # Strictly scoped to the project.
    assert all(e['value'] == 'api.x.com' for e in evs)


def test_list_assets_query_matches_value_and_label(tmp_path):
    s = _store(tmp_path)
    s.sync('p', 's1', [Asset('subdomain', 'api.shop.com', label='API Gateway'),
                       Asset('ip', '10.0.0.5', label='DB host')])
    # value substring, case-insensitive
    assert [a['value'] for a in s.list_assets('p', query='api')] == ['api.shop.com']
    assert [a['value'] for a in s.list_assets('p', query='10.0')] == ['10.0.0.5']
    # label substring
    assert [a['value'] for a in s.list_assets('p', query='gateway')] == ['api.shop.com']
    # no match → empty; blank → all
    assert s.list_assets('p', query='zzz') == []
    assert len(s.list_assets('p', query='  ')) == 2
