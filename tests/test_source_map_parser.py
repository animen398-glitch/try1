"""Tests for core.source_map_parser — offline .js.map parsing + secret scan."""

import json

from core.source_map_parser import SourceMapParser

_MAP = json.dumps({
    "version": 3,
    "file": "app.min.js",
    "sources": ["webpack://app/src/config.js", "webpack://app/src/ui.js"],
    "names": ["init", "render"],
    "sourcesContent": [
        "const API_KEY = 'AKIA1234567890ABCD56';",
        "export function render() { return 1; }",
    ],
})


def test_parse_summary():
    out = SourceMapParser.parse(_MAP)
    assert out["ok"] is True
    assert out["version"] == 3
    assert out["file"] == "app.min.js"
    assert out["sources_content_count"] == 2
    assert out["has_content"] is True


def test_extract_sources_and_content_pairs():
    assert SourceMapParser.extract_sources(_MAP) == [
        "webpack://app/src/config.js",
        "webpack://app/src/ui.js",
    ]
    pairs = SourceMapParser.extract_sources_content(_MAP)
    assert pairs[0][0] == "webpack://app/src/config.js"
    assert "AKIA" in pairs[0][1]


def test_scan_for_secrets_points_at_original_path():
    findings = SourceMapParser().scan_for_secrets(_MAP)
    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Access Key"
    assert findings[0]["source"] == "webpack://app/src/config.js"


def test_find_map_urls_relative_absolute_and_datauri():
    js = (
        "console.log(1);\n"
        "//# sourceMappingURL=app.min.js.map\n"
    )
    assert SourceMapParser.find_map_urls(js, base_url="https://x.com/static/app.min.js") == [
        "https://x.com/static/app.min.js.map"
    ]
    # No base_url → returned verbatim.
    assert SourceMapParser.find_map_urls(js) == ["app.min.js.map"]
    # Data-URI maps are returned as-is even with a base_url.
    data_js = "//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ=="
    assert SourceMapParser.find_map_urls(data_js, base_url="https://x.com/a.js")[0].startswith("data:")


def test_malformed_map_does_not_raise():
    out = SourceMapParser.parse("{not valid json")
    assert out["ok"] is False and out["sources"] == []
    assert SourceMapParser.extract_sources_content("{bad") == []


def test_map_without_sources_content():
    m = json.dumps({"version": 3, "sources": ["a.js"]})
    out = SourceMapParser.parse(m)
    assert out["ok"] is True and out["has_content"] is False
    assert SourceMapParser().scan_for_secrets(m) == []
