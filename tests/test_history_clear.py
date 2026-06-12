"""Test the History tab 'Сбросить историю' (clear view, keep DB)."""


def test_clear_history_view_resets_table_only(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()

    # Simulate a loaded history.
    rows = [{"id": 1, "target": "x", "phase": "recon", "status": "success",
             "started_at": "t", "duration_ms": 5}]
    w._on_history_loaded({"rows": rows})
    assert w.history_table.rowCount() == 1
    assert w._history_rows == rows

    # Clear the view.
    w._clear_history_view()
    assert w.history_table.rowCount() == 0
    assert w._history_rows == []
    assert w._history_view_cleared is True
    assert "БД не затронута" in w.history_count.text()


def test_cleared_view_not_auto_reloaded_on_tab_return(qapp):
    from gui.main_window import MainWindow
    w = MainWindow()
    w._clear_history_view()

    # Returning to the history tab must NOT auto-refresh while cleared.
    calls = []
    w._refresh_history = lambda: calls.append(1)
    hist_index = next(i for i in range(w.tabs.count())
                      if w.tabs.widget(i) is w._history_widget)
    w._on_tab_changed(hist_index)
    assert calls == []
