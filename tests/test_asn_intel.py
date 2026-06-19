"""Active ASN / netblock intelligence — offline (network seam stubbed).

Parsers are pure; the cached fetchers take an injected ``get_text`` so nothing
touches the network; the aggregator takes injected fetchers. No sockets.
"""

import json

from core import asn_intel as ai


# ── parsers ────────────────────────────────────────────────────────────────────

def test_parse_rdap_extracts_cidr_and_range():
    text = json.dumps({
        'handle': 'NET-104-16-0-0-1', 'name': 'CLOUDFLARENET',
        'startAddress': '104.16.0.0', 'endAddress': '104.31.255.255',
        'cidr0_cidrs': [{'v4prefix': '104.16.0.0', 'length': 12}],
    })
    out = ai._parse_rdap(text)
    assert out['cidr'] == '104.16.0.0/12'
    assert out['range'] == '104.16.0.0 – 104.31.255.255'
    assert out['name'] == 'CLOUDFLARENET'


def test_parse_rdap_garbage_is_empty():
    assert ai._parse_rdap('not json') == {}
    assert ai._parse_rdap('[]') == {}


def test_parse_ripe_prefixes():
    text = json.dumps({'data': {'prefixes': [
        {'prefix': '104.16.0.0/13'}, {'prefix': '104.24.0.0/14'}]}})
    out = ai._parse_ripe_prefixes(text)
    assert out['prefixes'] == ['104.16.0.0/13', '104.24.0.0/14']
    assert out['count'] == 2


def test_parse_ripe_prefixes_garbage():
    assert ai._parse_ripe_prefixes('x')['prefixes'] == []
    assert ai._parse_ripe_prefixes(json.dumps({'data': {}}))['count'] == 0


def test_parse_reverse_ip_hostlist():
    out = ai._parse_reverse_ip('example.com\nwww.example.com\nshop.example.com\n')
    assert out['neighbors'] == ['example.com', 'www.example.com', 'shop.example.com']
    assert out['count'] == 3


def test_parse_reverse_ip_dedups_and_filters_noise():
    out = ai._parse_reverse_ip('a.com\nA.COM\nnot a host line\nb.org')
    assert out['neighbors'] == ['a.com', 'b.org']


def test_parse_reverse_ip_rate_limited_degrades():
    assert ai._parse_reverse_ip('error API count exceeded')['neighbors'] == []
    assert ai._parse_reverse_ip('')['count'] == 0


# ── cached fetchers (injected get_text → no network) ──────────────────────────

def test_fetch_cidr_uses_injected_get_text():
    ai.clear_cache()
    payload = json.dumps({'cidr0_cidrs': [{'v4prefix': '1.2.0.0', 'length': 16}],
                          'name': 'NET'})
    out = ai.fetch_cidr('1.2.3.4', get_text=lambda url: payload)
    assert out['cidr'] == '1.2.0.0/16'


def test_fetch_empty_ip_or_asn_short_circuits():
    assert ai.fetch_cidr('', get_text=lambda url: 'x') == {}
    assert ai.fetch_asn_prefixes('', get_text=lambda url: 'x')['count'] == 0
    assert ai.fetch_reverse_ip('', get_text=lambda url: 'x')['count'] == 0


def test_fetch_caches_result():
    ai.clear_cache()
    calls = {'n': 0}

    def counting_get(url):
        calls['n'] += 1
        return json.dumps({'data': {'prefixes': [{'prefix': '9.9.9.0/24'}]}})

    ai.fetch_asn_prefixes('AS99', get_text=counting_get)
    ai.fetch_asn_prefixes('AS99', get_text=counting_get)
    assert calls['n'] == 1          # second call served from cache


# ── aggregator ────────────────────────────────────────────────────────────────

def test_build_asn_intel_composes_all_three():
    infra = {'ip': '1.2.3.4', 'asn': 'AS13335', 'asn_name': 'Cloudflare'}
    out = ai.build_asn_intel(
        infra,
        cidr_fetch=lambda ip: {'cidr': '1.2.0.0/16', 'range': 'r', 'name': 'NET'},
        prefixes_fetch=lambda asn: {'prefixes': ['1.2.0.0/16', '1.3.0.0/16'],
                                    'count': 2},
        reverse_fetch=lambda ip: {'neighbors': ['a.com', 'b.com'], 'count': 2},
    )
    assert out['status'] == 'Success'
    assert out['cidr'] == '1.2.0.0/16'
    assert out['prefix_count'] == 2 and out['neighbor_count'] == 2
    assert out['neighbors'] == ['a.com', 'b.com']


def test_build_asn_intel_caps_large_lists():
    infra = {'ip': '1.1.1.1', 'asn': 'AS1'}
    many = [f'10.{i}.0.0/24' for i in range(ai.PREFIX_CAP + 20)]
    hosts = [f'h{i}.com' for i in range(ai.NEIGHBOR_CAP + 30)]
    out = ai.build_asn_intel(
        infra,
        cidr_fetch=lambda ip: {},
        prefixes_fetch=lambda asn: {'prefixes': many, 'count': len(many)},
        reverse_fetch=lambda ip: {'neighbors': hosts, 'count': len(hosts)},
    )
    assert len(out['prefixes']) == ai.PREFIX_CAP
    assert out['prefix_count'] == len(many)            # full count preserved
    assert len(out['neighbors']) == ai.NEIGHBOR_CAP
    assert out['neighbor_count'] == len(hosts)


# ── related assets (co-hosted view) ───────────────────────────────────────────

def test_related_assets_filters_own_hosts():
    intel = {'ip': '1.2.3.4', 'neighbors': ['other.com', 'api.example.com',
                                            'example.com', 'foo.net'],
             'neighbor_count': 4}
    out = ai.related_assets(intel, own_hosts=['example.com', 'api.example.com'])
    hosts = [r['host'] for r in out['related']]
    assert hosts == ['foo.net', 'other.com']            # own excluded, sorted
    assert out['shared_ip'] == '1.2.3.4'
    assert out['count'] == 2 and out['total'] == 4
    assert all(r['shared_ip'] == '1.2.3.4' for r in out['related'])


def test_related_assets_dedups_and_normalizes():
    intel = {'ip': '9.9.9.9', 'neighbors': ['A.com', 'a.com.', 'b.com']}
    out = ai.related_assets(intel)
    assert [r['host'] for r in out['related']] == ['a.com', 'b.com']


def test_related_assets_empty_and_bad_input():
    assert ai.related_assets({})['related'] == []
    assert ai.related_assets(None)['count'] == 0


def test_related_assets_from_report_uses_subdomains_as_own():
    report = {'domain': 'example.com',
              'phases': {
                  'subdomains': {'status': 'Success', 'data': {'results': [
                      {'subdomain': 'api.example.com'}]}},
                  'asn_intel': {'status': 'Success', 'data': {
                      'ip': '1.2.3.4', 'neighbor_count': 3,
                      'neighbors': ['api.example.com', 'example.com',
                                    'stranger.org']}}}}
    out = ai.related_assets_from_report(report)
    assert [r['host'] for r in out['related']] == ['stranger.org']
    assert out['shared_ip'] == '1.2.3.4'


def test_related_assets_from_report_skips_when_phase_absent():
    assert ai.related_assets_from_report({'domain': 'x.com',
                                          'phases': {}})['count'] == 0


def test_build_asn_intel_skips_without_ip_or_asn():
    out = ai.build_asn_intel({'domain': 'x.com'})
    assert out['status'] == 'Skipped'
    assert out['prefixes'] == [] and out['neighbors'] == []


# ── render (offline) ──────────────────────────────────────────────────────────

def test_render_html_offline_and_caps_note():
    intel = {'status': 'Success', 'asn': 'AS1', 'cidr': '1.2.0.0/16',
             'range': 'a – b', 'netname': 'NET',
             'prefixes': ['1.2.0.0/16'], 'prefix_count': 5,
             'neighbors': ['a.com'], 'neighbor_count': 1}
    out = ai.render_html(intel)
    assert '<script' not in out.lower()
    assert 'http://' not in out and 'https://' not in out
    assert '1.2.0.0/16' in out
    assert 'ещё 4' in out               # prefix cap note (5 total, 1 shown)


def test_render_html_not_run_placeholder():
    assert 'не выполнялась' in ai.render_html(None)
    assert 'не выполнялась' in ai.render_html({'status': 'Skipped'})


# ── CollectionRunner wiring (opt-in phase, offline) ───────────────────────────

def test_collection_runner_asn_phase_runs(tmp_path, monkeypatch):
    from core.collection_runner import CollectionRunner
    # Stub the network-backed fetchers so the phase stays offline.
    monkeypatch.setattr(ai, 'fetch_cidr',
                        lambda ip: {'cidr': '1.2.0.0/16', 'range': 'r', 'name': 'N'})
    monkeypatch.setattr(ai, 'fetch_asn_prefixes',
                        lambda asn: {'prefixes': ['1.2.0.0/16'], 'count': 1})
    monkeypatch.setattr(ai, 'fetch_reverse_ip',
                        lambda ip: {'neighbors': ['a.com'], 'count': 1})

    runner = CollectionRunner(asn_intel=True)
    report = {'phases': {'recon': {'status': 'Success', 'data': {
        'infrastructure': {'ip': '1.2.3.4', 'asn': 'AS13335', 'asn_name': 'CF'}}}}}
    out = runner._phase_asn_intel(report, tmp_path)
    assert out['status'] == 'Success'
    assert out['data']['cidr'] == '1.2.0.0/16'
    assert out['data']['neighbor_count'] == 1
    assert (tmp_path / 'recon' / 'asn_intel.json').exists()


def test_collection_runner_asn_phase_skips_without_ip_asn(tmp_path):
    from core.collection_runner import CollectionRunner
    runner = CollectionRunner(asn_intel=True)
    report = {'phases': {'recon': {'status': 'Success',
                                   'data': {'infrastructure': {}}}}}
    out = runner._phase_asn_intel(report, tmp_path)
    assert out['status'] == 'Skipped'
