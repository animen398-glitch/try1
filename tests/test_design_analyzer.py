"""DesignAnalyzer — colour/font extraction and version comparison."""

from core.design_analyzer import DesignAnalyzer


class _FakeRegistry:
    """No-op operation registry so tests don't touch the real SQLite DB."""

    def start(self, *a, **k):
        return 1

    def finish(self, *a, **k):
        pass


def test_expand_hex_short_and_long():
    d = DesignAnalyzer()
    assert d._expand_hex("#abc") == "#AABBCC"
    assert d._expand_hex("#AABBCC") == "#AABBCC"


def test_extract_colors_hex_rgb_hsl_and_dedup():
    d = DesignAnalyzer()
    css = "a{color:#FFF;background:rgb(255,0,0);border:hsl(120,50%,50%)}"
    colors = d._extract_colors(css)
    kinds = {c["type"] for c in colors}
    assert kinds == {"hex", "rgb", "hsl"}
    assert any(c.get("value") == "#FFFFFF" for c in colors)


def test_extract_colors_rejects_out_of_range_rgb():
    d = DesignAnalyzer()
    assert d._extract_colors("x{color:rgb(999,0,0)}") == []


def test_extract_fonts_drops_generic_keeps_named():
    d = DesignAnalyzer()
    fonts = d._extract_fonts('body{font-family:"Open Sans", Arial, sans-serif}')
    assert fonts == ["Arial", "Open Sans"]
    assert "sans-serif" not in fonts


def test_analyze_missing_source_dir(tmp_path):
    d = DesignAnalyzer()
    d.configure(str(tmp_path / "does-not-exist"))
    result = d.analyze()
    assert result["status"].startswith("Error")


def test_analyze_reads_css_and_inline_style(tmp_path):
    (tmp_path / "site.css").write_text(
        "h1{color:#123456;font-family:'Roboto'}", encoding="utf-8")
    (tmp_path / "index.html").write_text(
        "<style>p{color:rgb(0,128,255)}</style>", encoding="utf-8")
    d = DesignAnalyzer()
    d.configure(str(tmp_path))
    result = d.analyze()

    assert result["status"] == "Success"
    assert result["stats"]["css_files"] == 1
    assert result["stats"]["html_files"] == 1
    assert "Roboto" in result["fonts"]
    hexes = {c.get("value") for c in result["colors"]}
    assert "#123456" in hexes
    # Palette JSON is written next to the sources.
    assert (tmp_path / "ui_palette.json").exists()


def test_compare_versions_added_removed_modified(tmp_path):
    v1 = tmp_path / "v1"
    v2 = tmp_path / "v2"
    v1.mkdir()
    v2.mkdir()
    (v1 / "a.html").write_text("one", encoding="utf-8")
    (v1 / "gone.css").write_text("x", encoding="utf-8")
    (v2 / "a.html").write_text("CHANGED", encoding="utf-8")
    (v2 / "new.js").write_text("y", encoding="utf-8")

    d = DesignAnalyzer(registry=_FakeRegistry())
    result = d.compare_versions(v1, v2)
    assert result["status"] == "Success"
    assert result["summary"]["added"] == 1
    assert result["summary"]["removed"] == 1
    assert result["summary"]["modified"] == 1
    assert "new.js" in result["added"]
    assert "gone.css" in result["removed"]
    assert "a.html" in result["modified"]
