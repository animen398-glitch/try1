"""CVE Intelligence persistent cache (core/cve_store.py) — offline foundation.

Round-trips for the two logical caches (library→advisories, cve→enrichment),
freshness age, refresh-on-conflict, and clear/stats. Isolated tmp DB (the
conftest fixture redirects CVE_CACHE_DB); no network.
"""

import sqlite3

from core.cve_store import CVEStore


def _store(tmp_path):
    return CVEStore(tmp_path / 'cve_cache.db')


def test_schema_is_versioned_and_idempotent(tmp_path):
    db = tmp_path / 'cve_cache.db'
    s1 = CVEStore(db)
    s1.put_lib_cves('npm', 'jquery', '1.11.0', [{'id': 'CVE-2020-11022'}])
    CVEStore(db)   # re-open must not wipe or error
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 1
    assert CVEStore(db).get_lib_cves('npm', 'jquery', '1.11.0') is not None


def test_lib_cves_round_trip_and_age(tmp_path):
    s = _store(tmp_path)
    assert s.get_lib_cves('npm', 'jquery', '1.11.0') is None   # miss
    vulns = [{'id': 'CVE-2020-11022', 'severity': 'Medium', 'summary': 'XSS'}]
    s.put_lib_cves('npm', 'jquery', '1.11.0', vulns)
    got = s.get_lib_cves('npm', 'jquery', '1.11.0')
    assert got['vulns'] == vulns
    assert got['age'] >= 0          # just-written → small, non-negative age
    # A stale write (old fetched_at) is still returned, with a large age.
    s.put_lib_cves('npm', 'jquery', '1.11.0', vulns, now='2000-01-01T00:00:00')
    assert s.get_lib_cves('npm', 'jquery', '1.11.0')['age'] > 1_000_000


def test_lib_cves_refresh_overwrites(tmp_path):
    s = _store(tmp_path)
    s.put_lib_cves('npm', 'lodash', '4.17.0', [{'id': 'A'}])
    s.put_lib_cves('npm', 'lodash', '4.17.0', [{'id': 'B'}, {'id': 'C'}])
    assert [v['id'] for v in s.get_lib_cves('npm', 'lodash', '4.17.0')['vulns']] \
        == ['B', 'C']


def test_cve_detail_round_trip(tmp_path):
    s = _store(tmp_path)
    assert s.get_cve_detail('CVE-2020-11022') is None
    s.put_cve_detail('CVE-2020-11022', {
        'cvss': 6.1, 'severity': 'Medium', 'published': '2020-04-29',
        'summary': 'jQuery XSS', 'source': 'nvd'})
    d = s.get_cve_detail('CVE-2020-11022')
    assert d['cvss'] == 6.1 and d['severity'] == 'Medium'
    assert d['published'] == '2020-04-29' and d['source'] == 'nvd'
    assert d['age'] >= 0


def test_clear_and_stats(tmp_path):
    s = _store(tmp_path)
    s.put_lib_cves('npm', 'vue', '2.0.0', [{'id': 'X'}])
    s.put_cve_detail('CVE-1', {'cvss': 5.0})
    assert s.stats() == {'lib_cves': 1, 'cve_details': 1}
    assert s.clear() == 2
    assert s.stats() == {'lib_cves': 0, 'cve_details': 0}


# ── T14: retention / prune ──────────────────────────────────────────────────


def test_prune_drops_stale_by_age(tmp_path):
    s = _store(tmp_path)
    s.put_lib_cves('PyPI', 'old', '1.0', [{'id': 'X'}], now='2000-01-01T00:00:00')
    s.put_lib_cves('PyPI', 'new', '1.0', [{'id': 'Y'}])  # fresh (now)
    assert s.prune(max_age_days=1) == 1
    assert s.get_lib_cves('PyPI', 'old', '1.0') is None
    assert s.get_lib_cves('PyPI', 'new', '1.0') is not None


def test_prune_caps_rows_by_recency(tmp_path):
    s = _store(tmp_path)
    for i in range(5):  # fetched_at 2020-01-01 .. 2020-01-05
        s.put_cve_detail(f'CVE-{i}', {'cvss': 1.0}, now=f'2020-01-0{i + 1}T00:00:00')
    # age cutoff far in the past so only the row cap applies; keep newest 2.
    assert s.prune(max_age_days=100000, max_rows=2) == 3
    assert s.stats()['cve_details'] == 2
    assert s.get_cve_detail('CVE-4') is not None   # newest kept
    assert s.get_cve_detail('CVE-0') is None        # oldest dropped


def test_prune_noop_within_bounds(tmp_path):
    s = _store(tmp_path)
    s.put_cve_detail('CVE-1', {'cvss': 9.8})
    assert s.prune(max_age_days=100000, max_rows=100) == 0
    assert s.stats()['cve_details'] == 1


def test_prune_totals_across_both_tables(tmp_path):
    s = _store(tmp_path)
    s.put_lib_cves('PyPI', 'a', '1', [{'id': 'X'}], now='2000-01-01T00:00:00')
    s.put_cve_detail('CVE-OLD', {'cvss': 1.0}, now='2000-01-01T00:00:00')
    assert s.prune(max_age_days=1) == 2  # one stale row from each table
