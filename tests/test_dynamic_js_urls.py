"""Tests for the JS URL-extraction helper in core.dynamic_analyzer.

Pure-function tests — they do not import or require Playwright (the import is
guarded in the module), so they run in the headless CI matrix.
"""

from core.dynamic_analyzer import _scan_json_for_secrets, extract_js_urls


def test_extracts_absolute_urls_and_strips_trailing_punctuation():
    js = """fetch("https://api.example.com/v1/users");
            var x = 'https://cdn.example.com/app.js';"""
    urls = extract_js_urls(js)
    assert "https://api.example.com/v1/users" in urls
    assert "https://cdn.example.com/app.js" in urls
    # trailing quote/paren must not be captured
    assert all(not u.endswith(('"', "'", ")")) for u in urls)


def test_resolves_api_relative_paths_against_base_url():
    js = 'const u = "/api/v2/orders"; postTo("/graphql");'
    urls = extract_js_urls(js, base_url="https://shop.example.com/static/main.js")
    assert "https://shop.example.com/api/v2/orders" in urls
    assert "https://shop.example.com/graphql" in urls


def test_relative_paths_returned_raw_without_base_url():
    urls = extract_js_urls('x="/api/v1/me"')
    assert urls == ["/api/v1/me"]


def test_non_api_relative_paths_are_ignored():
    # Only api/v\d/graphql/etc-shaped relative paths are treated as endpoints.
    urls = extract_js_urls('img.src="/static/logo.png"')
    assert urls == []


def test_dedups_and_respects_limit():
    js = " ".join('u="https://a.example.com/%d"' % i for i in range(50))
    assert len(extract_js_urls(js, limit=10)) == 10
    repeated = 'x="https://a.example.com/same" y="https://a.example.com/same"'
    assert extract_js_urls(repeated) == ["https://a.example.com/same"]


def test_empty_input():
    assert extract_js_urls("") == []


def test_json_secret_scan_drops_jwt_false_positive():
    # A base64 blob that matches the JWT pattern but is not a real JWT (the
    # structural validator marks it INVALID) must not be reported as a leaked
    # secret — same placeholder/false-positive filtering the api/audit folders use.
    fake_jwt = 'eyJ' + 'a' * 40 + '.' + 'b' * 40 + '.' + 'c' * 40
    assert _scan_json_for_secrets({'token': fake_jwt}, 'https://x/api') == []


def test_json_secret_scan_keeps_real_pattern_secret():
    # A well-formed credential (valid GitHub token shape) is still reported.
    body = {'config': {'gh': 'ghp_' + 'a1b2c3d4e5' * 3 + 'a1b2c3'}}
    found = _scan_json_for_secrets(body, 'https://x/api')
    assert found and found[0]['type'] == 'GitHub Token'
