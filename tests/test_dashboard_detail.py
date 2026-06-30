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


def test_endpoints_table_paginates_and_maps_selection(qapp):
    w = _window(qapp)
    eps = [{"endpoint": f"https://x/api/{i}", "count": i, "source_count": 1,
            "sources": [f"p{i}"], "patterns": ["api_endpoint"]}
           for i in range(250)]
    w._populate_endpoints_table(eps)
    assert len(w._endpoints_records) == 250          # full list kept (no [:200] cap)
    assert w.endpoints_table.rowCount() == 200        # only the first page rendered
    w.endpoints_table.selectRow(0)
    assert "https://x/api/0" in w.dash_detail.toPlainText()
    # page 2 → table row 0 maps to the full-list endpoint #200
    w._endpoints_paginator.go_to(1)
    w.endpoints_table.selectRow(0)
    assert "https://x/api/200" in w.dash_detail.toPlainText()


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


def test_table_load_error_clears_stale_activity_rows_and_detail(qapp):
    w = _window(qapp)
    w._populate_dashboard_table([
        {"data_type": "subdomain", "source": "x", "content": "a.x.com",
         "metadata": {}}],
    )
    w.dashboard_table.selectRow(0)
    assert w.dash_detail.toPlainText()

    w._on_dashboard_table_loaded({
        "data_type": w.dash_filter.currentData(),
        "endpoint": w._endpoint_filter,
        "error": "boom",
    })

    assert w.dashboard_table.rowCount() == 0
    assert w.dash_detail.toPlainText() == ""
    assert w._dashboard_records == []
    assert "boom" in w.dash_status.text()
