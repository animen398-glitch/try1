"""Captured-scan → tool-evidence bridge (core/tool_evidence.py).

Pure dict→dict mapping of a scan report.json to per-tool evidence; an additive
extractor registry. Verifies the verified extractors (source_map_finder,
safe_active_prober), the empty/unknown fallbacks, available_tools, and that the
output feeds straight into the matching tool_parsers parser (round-trip).
"""

import json

from core import tool_evidence as te
from core.tool_parsers import parse_tool_output


def _report():
    return {
        'url': 'https://shop.io',
        'phases': {
            'recon': {'status': 'Success', 'data': {
                'source_maps': [
                    {'url': 'https://shop.io/app.js.map', 'has_content': True},
                    {'url': 'https://shop.io/vendor.js.map'},
                    {'no_url': 1},                       # ignored
                ],
            }},
            'subdomains': {'status': 'Success', 'data': {
                'results': [{'subdomain': 'a.shop.io'}, {'subdomain': 'b.shop.io'}],
                'summary': {'takeover_candidates': [{'subdomain': 'c.shop.io'},
                                                    {'subdomain': 'a.shop.io'}]},
            }},
        },
    }


def test_source_map_evidence_shape():
    ev = te.evidence_from_report(_report(), 'source_map_finder')
    assert ev['url'] == 'https://shop.io'
    assert ev['urls'] == ['https://shop.io/app.js.map', 'https://shop.io/vendor.js.map']


def test_safe_active_prober_evidence_dedups():
    ev = te.evidence_from_report(_report(), 'safe_active_prober')
    # results + takeover candidates, deduped, order preserved
    assert ev['subdomains'] == ['a.shop.io', 'b.shop.io', 'c.shop.io']


def test_missing_data_yields_empty():
    assert te.evidence_from_report({'phases': {}}, 'source_map_finder') == {}
    assert te.evidence_from_report({}, 'safe_active_prober') == {}


def test_unknown_or_unbridged_tool_yields_empty():
    assert te.evidence_from_report(_report(), 'tls_audit') == {}      # no extractor
    assert te.evidence_from_report(_report(), 'nonsense') == {}
    assert te.evidence_from_report(_report(), '') == {}


def test_available_tools_lists_only_bridgeable():
    assert te.available_tools(_report()) == ['safe_active_prober',
                                             'source_map_finder']
    assert te.available_tools({'phases': {}}) == []


def test_bridge_output_feeds_the_parser():
    # the bridge's evidence must be exactly what tool_parsers expects
    sm = te.evidence_from_report(_report(), 'source_map_finder')
    out = parse_tool_output('source_map_finder', sm)
    assert any('.map' in f.get('location', '') for f in out['findings'])

    sp = te.evidence_from_report(_report(), 'safe_active_prober')
    out = parse_tool_output('safe_active_prober', sp)
    values = {a['value'] for a in out['assets']}
    assert {'a.shop.io', 'b.shop.io', 'c.shop.io'} <= values


# ── evidence_from_project_scan (thin loader over a real project) ────────────────

def _seed_project(base):
    from core.project import ProjectStore
    proj = ProjectStore(base).get_or_create('https://shop.io')
    sid = '20260101_000000'
    d = proj.start_scan(sid)
    report = {
        'url': 'https://shop.io', 'finished_at': sid,
        'phases': {'recon': {'status': 'Success', 'data': {
            'source_maps': [{'url': 'https://shop.io/a.js.map', 'has_content': True}]}}},
        'executive_summary': {'metrics': {}},
    }
    (d / 'report.json').write_text(json.dumps(report), encoding='utf-8')
    proj.record_scan(d, report)
    return proj


def test_evidence_from_project_scan_latest(tmp_path):
    _seed_project(str(tmp_path))
    ev = te.evidence_from_project_scan('shop.io', 'source_map_finder',
                                       base=str(tmp_path))
    assert ev['urls'] == ['https://shop.io/a.js.map']


def test_evidence_from_project_scan_explicit_scan(tmp_path):
    _seed_project(str(tmp_path))
    ev = te.evidence_from_project_scan('shop.io', 'source_map_finder',
                                       base=str(tmp_path), scan_id='20260101_000000')
    assert ev['urls'] == ['https://shop.io/a.js.map']


def test_evidence_from_project_scan_missing(tmp_path):
    assert te.evidence_from_project_scan('nope', 'source_map_finder',
                                         base=str(tmp_path)) == {}
    # known project, unknown explicit scan → {}
    _seed_project(str(tmp_path))
    assert te.evidence_from_project_scan('shop.io', 'source_map_finder',
                                         base=str(tmp_path), scan_id='zzz') == {}
