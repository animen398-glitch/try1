"""TablePaginator (gui/ui_components.py) — UI windowing for large tables.

Renders only a page of an in-memory row list into a QTableWidget (the slow part
is populating the widget, not holding the rows), and maps a table row back to the
full-list record for selection. Headless Qt (offscreen), no data layer.
"""

from qtpy.QtWidgets import QTableWidget, QTableWidgetItem

from gui.ui_components import TablePaginator


def _table():
    return QTableWidget(0, 1)


def _render(table, r, rec):
    table.setItem(r, 0, QTableWidgetItem(str(rec['v'])))


def _rows(n):
    return [{'v': i} for i in range(n)]


def test_renders_only_first_page(qapp):
    p = TablePaginator(_table(), _render, page_size=10)
    p.set_rows(_rows(25))
    assert p.table.rowCount() == 10
    assert p.table.item(0, 0).text() == '0'
    assert p.page_count() == 3


def test_next_and_last_partial_page(qapp):
    p = TablePaginator(_table(), _render, page_size=10)
    p.set_rows(_rows(25))
    p.go_to(1)
    assert p.table.rowCount() == 10 and p.table.item(0, 0).text() == '10'
    p.go_to(2)
    assert p.table.rowCount() == 5 and p.table.item(0, 0).text() == '20'
    p.go_to(99)                              # clamps to the last page
    assert p._page == 2


def test_record_at_maps_table_row_to_full_list(qapp):
    p = TablePaginator(_table(), _render, page_size=10)
    p.set_rows(_rows(25))
    p.go_to(2)                               # page 3 shows full-list rows 20..24
    assert p.index_at(0) == 20
    assert p.record_at(0)['v'] == 20 and p.record_at(4)['v'] == 24
    assert p.record_at(99) is None           # out of range → None


def test_page_size_change_keeps_first_visible(qapp):
    p = TablePaginator(_table(), _render, page_size=100)
    p.set_rows(_rows(1000))
    p.go_to(3)                               # first visible = full-list row 300
    p.size_combo.setCurrentIndex(p.size_combo.findData(500))  # → _on_size_changed
    # 300 // 500 = page 0, so the formerly-first-visible row stays on screen
    assert p.page_start() == 0 and p.table.rowCount() == 500


def test_empty_rows(qapp):
    p = TablePaginator(_table(), _render, page_size=10)
    p.set_rows([])
    assert p.table.rowCount() == 0 and p.page_count() == 1
    assert p.record_at(0) is None
    assert 'Нет строк' in p.page_label.text()


def test_on_page_changed_fires_only_on_real_change(qapp):
    calls = []
    p = TablePaginator(_table(), _render, page_size=10,
                       on_page_changed=lambda: calls.append(1))
    p.set_rows(_rows(25))
    p.go_to(1)
    assert calls == [1]
    p.go_to(1)                               # same page → no extra callback
    assert calls == [1]
