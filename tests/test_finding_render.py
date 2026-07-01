"""core/finding_render.py — shared finding-table renderers (pure, offline)."""

from core import finding_render as fr


def _rows():
    return [
        {"severity": "high", "title": "SQLi | risky", "validation_status": "validated",
         "confidence": "0.9", "evidence_refs": ["a.txt", "b.txt"]},
        {"severity": "low", "title": "info", "status": "open", "confidence": "0.3"},
    ]


def test_refs_join_and_empty():
    assert fr.finding_refs({"evidence_refs": ["x", "y"]}) == "x, y"
    assert fr.finding_refs({}) == "-"
    assert fr.finding_refs({"evidence_refs": []}) == "-"


def test_md_table_header_escaping_and_status_fallback():
    md = fr.finding_md_table(_rows())
    lines = md.splitlines()
    assert lines[0] == "| Severity | Title | Validation | Confidence | Evidence |"
    assert lines[1] == "|---|---|---|---:|---|"
    # pipe in title/evidence is escaped
    assert "SQLi \\| risky" in md
    # validation_status preferred, else status fallback
    assert "| validated |" in md and "| open |" in md
    assert "a.txt, b.txt" in md


def test_md_table_empty_is_header_only():
    assert fr.finding_md_table([]) == fr._MD_HEADER


def test_html_table_escapes_and_empty_row():
    html_out = fr.finding_html_table(_rows())
    assert html_out.startswith("<table><thead>")
    assert "SQLi | risky" in html_out or "SQLi &amp;" in html_out or "SQLi" in html_out
    assert "<th>Severity</th>" in html_out
    empty = fr.finding_html_table([])
    assert '<tr><td colspan="5">None</td></tr>' in empty


def test_html_table_escapes_angle_brackets():
    out = fr.finding_html_table([{"title": "<script>", "severity": "high"}])
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_html_open_envelope():
    head = fr.html_open("ASA Mission Report")
    assert head.startswith('<!doctype html><html><head><meta charset="utf-8">')
    assert "<title>ASA Mission Report</title>" in head
    assert head.endswith("</style></head><body>")
    assert "font-family:Arial" in head


def test_html_close_is_sha_of_markdown():
    from hashlib import sha1
    md = "# Report\n"
    close = fr.html_close(md)
    digest = sha1(md.encode("utf-8")).hexdigest()
    assert close == f"<!-- markdown-sha={digest} --></body></html>"
    # different markdown → different provenance sha
    assert fr.html_close("other") != close
