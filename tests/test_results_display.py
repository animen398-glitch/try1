"""ResultsDisplay coloured log helpers escape their (plain-text) argument.

QTextEdit.append() renders HTML, so a message containing <, > or & (URLs with
query strings, header values, error text) must be escaped to display verbatim
instead of being swallowed as markup.
"""


def test_append_info_escapes_html_metacharacters(qapp):
    from gui.ui_components import ResultsDisplay
    r = ResultsDisplay()
    r.append_info("GET /a?x=<b>&y=1")

    plain = r.toPlainText()
    # The literal text survives (the <b> was not interpreted as a bold tag).
    assert "<b>" in plain
    assert "&y=1" in plain
    assert "[INFO]" in plain


def test_append_error_escapes_and_keeps_prefix(qapp):
    from gui.ui_components import ResultsDisplay
    r = ResultsDisplay()
    r.append_error("boom <script>alert(1)</script>")

    plain = r.toPlainText()
    assert "<script>" in plain          # shown literally, not stripped
    assert "[ERR]" in plain


def test_raw_append_still_renders_markup(qapp):
    from gui.ui_components import ResultsDisplay
    r = ResultsDisplay()
    r.append('<span style="color:red;">styled</span>')

    plain = r.toPlainText()
    # Intentional-HTML path: the tag is interpreted, only its text remains.
    assert plain.strip() == "styled"
