"""CloudflareSession — transparent gzip/deflate decoding in fetch()."""

import gzip
import zlib

from core.cloudflare_bypass import CloudflareSession


class _FakeResp:
    def __init__(self, body, headers):
        self._body = body
        self.headers = headers

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, resp):
        self._resp = resp

    def open(self, req, timeout=20):
        return self._resp


def _session_serving(body, headers):
    s = CloudflareSession()
    s.opener = _FakeOpener(_FakeResp(body, headers))
    return s


def test_fetch_decodes_gzip():
    s = _session_serving(gzip.compress("héllo".encode()),
                         {"Content-Encoding": "gzip"})
    assert s.fetch("http://x") == "héllo"


def test_fetch_decodes_deflate():
    s = _session_serving(zlib.compress(b"<html>ok</html>"),
                         {"Content-Encoding": "deflate"})
    assert s.fetch("http://x") == "<html>ok</html>"


def test_fetch_identity_passthrough():
    s = _session_serving(b"<html>plain</html>", {})
    assert s.fetch("http://x") == "<html>plain</html>"
