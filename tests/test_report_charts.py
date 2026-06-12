"""Offline inline-CSS chart fragments — stacked_bar."""

from core.report_charts import stacked_bar


def test_stacked_bar_widths_are_proportional():
    out = stacked_bar([('A', 3, '#111'), ('B', 1, '#222')])
    # 3:1 split → 75% / 25% of the bar.
    assert 'width:75.00%' in out
    assert 'width:25.00%' in out
    assert '#111' in out and '#222' in out


def test_stacked_bar_is_offline_no_js():
    out = stacked_bar([('A', 1, '#111')])
    assert '<script' not in out.lower()
    assert 'http://' not in out and 'https://' not in out


def test_stacked_bar_skips_zero_and_negative_segments():
    out = stacked_bar([('A', 2, '#111'), ('Z', 0, '#999'), ('N', -5, '#888')])
    # Only A has positive value → it fills the whole bar; Z/N absent from legend.
    assert 'width:100.00%' in out
    assert 'Z:' not in out and 'N:' not in out


def test_stacked_bar_empty_shows_note():
    out = stacked_bar([('A', 0, '#111')], empty_note='нет данных')
    assert 'нет данных' in out
    assert 'width:' not in out


def test_stacked_bar_legend_toggle():
    # The legend chips carry the count in <b>…</b>; the bar itself only has a
    # hover title. Toggle adds/removes the chip row, not the bar.
    with_legend = stacked_bar([('A', 1, '#111')], legend=True)
    without = stacked_bar([('A', 1, '#111')], legend=False)
    assert 'A: <b>1</b>' in with_legend
    assert 'A: <b>1</b>' not in without
    assert 'width:100.00%' in without          # the bar is still rendered


def test_stacked_bar_escapes_labels():
    out = stacked_bar([('<b>x</b>', 1, '#111')])
    assert '<b>x</b>' not in out
    assert '&lt;b&gt;x&lt;/b&gt;' in out


def test_stacked_bar_formats_integers_and_floats():
    out = stacked_bar([('A', 2.0, '#111'), ('B', 1.5, '#222')])
    assert 'A: <b>2</b>' in out        # whole number → no decimals
    assert 'B: <b>1.5</b>' in out
