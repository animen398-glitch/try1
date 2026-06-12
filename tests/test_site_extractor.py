"""SiteExtractor — HTML cleaning, script discovery, finding provenance."""

from utils.site_extractor import SiteExtractor


class _FakeRegistry:
    def __init__(self):
        self.records = []

    def add_record(self, source, data_type, content, metadata=None):
        self.records.append((source, data_type, content))


def test_strip_html_removes_scripts_styles_tags_and_unescapes():
    html = ("<style>.a{color:red}</style><script>var x=1</script>"
            "<p>Hello&amp;world <b>now</b></p>")
    assert SiteExtractor.strip_html(html) == "Hello&world now"


def test_extract_script_urls_resolves_and_dedups():
    html = ('<script src="/a.js"></script>'
            '<script src="https://cdn/b.js"></script>'
            '<script src="/a.js"></script>')
    urls = SiteExtractor._extract_script_urls(html, "http://x/page")
    assert urls == ["http://x/a.js", "https://cdn/b.js"]


class _FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        pass


class _FakeSession:
    def __init__(self, pages):
        self._pages = pages
        self.headers = {}

    def get(self, url, timeout=None):
        return _FakeResp(self._pages[url])


def test_external_script_findings_attributed_to_script_url(monkeypatch):
    import requests

    pages = {
        "http://x/page": '<script src="/app.js"></script>',
        "http://x/app.js": 'fetch("/api/v1/users")',
    }
    monkeypatch.setattr(requests, "Session", lambda: _FakeSession(pages))

    reg = _FakeRegistry()
    ex = SiteExtractor(data_registry=reg)
    result = ex.fetch_text("http://x/page")

    assert result["status"] == "Success"
    assert result["scripts_analyzed"] == 1
    # The endpoint found inside app.js must be recorded against the SCRIPT URL,
    # not the page URL (provenance of the leak).
    endpoint_records = [r for r in reg.records if r[2] == "/api/v1/users"]
    assert endpoint_records
    assert all(src == "http://x/app.js" for src, _dt, _c in endpoint_records)


def test_fetch_text_never_raises_on_network_error(monkeypatch):
    import requests

    class _BoomSession:
        headers = {}

        def get(self, *a, **k):
            raise requests.exceptions.RequestException("down")

    monkeypatch.setattr(requests, "Session", lambda: _BoomSession())
    ex = SiteExtractor(data_registry=_FakeRegistry())
    result = ex.fetch_text("http://x")
    assert result["status"].startswith("Error")
