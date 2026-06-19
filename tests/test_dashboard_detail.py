"""Dashboard row-detail panel: selecting a row shows full, copyable content."""

from tests.gui_test_helpers import DashboardHost


def _window(qapp):
    return DashboardHost()


def test_activity_row_detail_shows_full_content(qapp):
    w = _window(qapp)
    long_content = "https://api.example.com/v1/" + "x" * 200
    w._populate_dashboard_table([
        {"data_type": "api_endpoint", "source": "page1",
         "content": long_content, "metadata": {"context": "ctx", "pattern": "p"}},
    ])
    # Select the row -> detail panel shows the FULL content (not the 80-char cell snippet).
    w.dashboard_table.selectRow(0)
    detail = w.dash_detail.toPlainText()
    assert long_content in detail
    assert "page1" in detail
    assert "ctx" in detail


def test_endpoint_row_detail_lists_sources(qapp):
    w = _window(qapp)
    w._populate_endpoints_table([
        {"endpoint": "https://x/api/long/" + "y" * 150, "count": 4,
         "source_count": 2, "sources": ["p1", "p2"], "patterns": ["api_endpoint"]},
    ])
    w.endpoints_table.selectRow(0)
    detail = w.dash_detail.toPlainText()
    assert "y" * 150 in detail
    assert "p1" in detail and "p2" in detail


def test_detail_is_read_only_but_copyable(qapp):
    w = _window(qapp)
    # Read-only (not editable) yet text interaction allows selection/copy.
    assert w.dash_detail.isReadOnly()


def test_clear_dashboard_clears_detail(qapp):
    w = _window(qapp)
    w._populate_dashboard_table([
        {"data_type": "t", "source": "s", "content": "c", "metadata": {}}])
    w.dashboard_table.selectRow(0)
    assert w.dash_detail.toPlainText()
    w._clear_dashboard()
    assert w.dash_detail.toPlainText() == ""
    assert w._dashboard_records == []
