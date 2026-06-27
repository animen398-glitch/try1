"""T10: backward-compat — thin / partial / legacy / Error report.json dicts must
flow through every report consumer without raising (summary -> markdown -> diff ->
timeline). Pins the existing tolerance so future changes can't regress it.

This is a guard test, not a fix: the consumers are already defensive; this locks
that contract in. Offline, no network.
"""
import pytest

from core.executive_summary import build_summary
from core.report_export import report_markdown
from core.scan_diff import diff
from core.timeline import build_events, build_series

# Reports a consumer might be handed: empty, a thin Recon-only scan, an Error
# report (as written by CollectionRunner._persist_error_report on failure), and a
# legacy report whose phases use shapes from an older schema.
_THIN = {'url': 'http://x.com', 'domain': 'x.com', 'phases': {}}
_ERROR = {'url': 'http://x.com', 'project_dir': '/tmp/s', 'status': 'Error',
          'error': 'boom', 'phases': {}}
_LEGACY = {'url': 'http://x.com', 'phases': {'recon': {'status': 'Success'}}}
_REPORTS = [{}, _THIN, _ERROR, _LEGACY]


@pytest.mark.parametrize('report', _REPORTS)
def test_build_summary_tolerates(report):
    out = build_summary(report)
    assert isinstance(out, dict) and out  # coherent (low-signal) verdict, no raise


@pytest.mark.parametrize('report', _REPORTS)
def test_report_markdown_tolerates(report):
    md = report_markdown(report)
    assert isinstance(md, str)
    assert md.startswith('# ')  # at least a header


@pytest.mark.parametrize('report', _REPORTS)
def test_diff_against_self_tolerates(report):
    out = diff(report, report)
    assert isinstance(out, dict)
    # Missing/partial phases land in 'skipped', never as false added/removed noise.
    assert 'skipped' in out


def test_diff_across_mismatched_reports():
    assert isinstance(diff(_THIN, _LEGACY), dict)
    assert isinstance(diff(_LEGACY, _ERROR), dict)


def test_timeline_builders_tolerate_empty():
    assert build_events([], [], []) == []
    assert build_series([]) == []
