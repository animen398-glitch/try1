"""Dashboard registry aggregation — DataViewer.get_summary counts each type."""

from core.registry import DataRegistry
from utils.data_viewer import DataViewer


def _registry(tmp_path):
    return DataRegistry(db_path=str(tmp_path / 'registry.db'))


def test_get_summary_counts_new_types(tmp_path):
    reg = _registry(tmp_path)
    reg.add_record('s', 'subdomain', 'a.ex.com')
    reg.add_record('s', 'subdomain', 'b.ex.com')
    reg.add_record('s', 'takeover', 'c.ex.com', {'service': 'GitHub Pages'})
    reg.add_record('s', 'source_map', 'https://ex.com/app.js.map',
                   {'has_content': True})
    reg.add_record('s', 'source_map', 'https://ex.com/vendor.js.map')
    reg.add_record('s', 'api_endpoint', '/api/v1/me')

    summary = DataViewer(registry=reg).get_summary()
    assert summary['subdomains'] == 2
    assert summary['takeovers'] == 1
    assert summary['source_maps'] == 2
    assert summary['api_endpoints'] == 1
    assert summary['total'] == 6


def test_get_summary_zero_for_absent_types(tmp_path):
    summary = DataViewer(registry=_registry(tmp_path)).get_summary()
    assert summary['takeovers'] == 0
    assert summary['source_maps'] == 0
    assert summary['total'] == 0


def test_dashboard_stats_keys_exist_in_summary(tmp_path):
    # Every Dashboard card key must be a real summary key (no silent zeros).
    from gui.tab_dashboard import DashboardTabMixin
    summary = DataViewer(registry=_registry(tmp_path)).get_summary()
    for key, _label in DashboardTabMixin.DASHBOARD_STATS:
        assert key in summary, f'Dashboard card {key!r} has no summary source'


def test_registry_clear_removes_all_records(tmp_path):
    reg = _registry(tmp_path)
    reg.add_record('s', 'subdomain', 'a.ex.com')
    reg.add_record('s', 'source_map', 'https://ex.com/app.js.map')
    assert reg.count() == 2

    removed = reg.clear()
    assert removed == 2
    assert reg.count() == 0
    # Idempotent: clearing an empty registry removes nothing and doesn't error.
    assert reg.clear() == 0
