"""Dashboard tab 'Очистить' clears the view (tables + counters), keeps the DB."""


def _populated_window(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    w._populate_endpoints_table([
        {"endpoint": "https://x/api/a", "count": 3, "source_count": 2,
         "sources": ["p1", "p2"], "patterns": ["api_endpoint"]},
    ])
    w._populate_dashboard_table([
        {"data_type": "subdomain", "source": "x", "content": "a.x.com",
         "metadata": {}},
    ])
    w.dash_stats["subdomains"].setText("5")
    w.dash_status.setText("Всего записей: 12")
    return w


def test_clear_dashboard_resets_tables_and_counters(qapp):
    w = _populated_window(qapp)
    assert w.endpoints_table.rowCount() == 1
    assert w.dashboard_table.rowCount() == 1

    w._clear_dashboard()

    assert w.endpoints_table.rowCount() == 0
    assert w.dashboard_table.rowCount() == 0
    assert w.dash_stats["subdomains"].text() == "0"
    assert w._endpoint_filter is None
    assert "БД не затронута" in w.dash_status.text()


def test_clear_does_not_trigger_reload_on_tab_return(qapp):
    w = _populated_window(qapp)
    w._dashboard_loaded = True            # как после первой загрузки
    w._clear_dashboard()

    calls = []
    w._refresh_dashboard = lambda: calls.append(1)
    dash_index = next(i for i in range(w.tabs.count())
                      if w.tabs.widget(i) is w._dashboard_widget)
    w._on_tab_changed(dash_index)
    assert calls == []                    # очищенный вид не перезагружается сам
