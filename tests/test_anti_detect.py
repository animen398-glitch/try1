"""AntiDetectSession — transparent content decoding (gzip AND deflate).

The profiles advertise ``Accept-Encoding: gzip, deflate``, so the session must
decode both. A deflate-only regression previously corrupted downloaded CSS/JS
assets (the body was returned still-compressed).
"""

import gzip
import zlib

from core.anti_detect_engine import AntiDetectSession


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
    s = AntiDetectSession()
    s.configure(retry_count=1)
    s._opener = lambda: _FakeOpener(_FakeResp(body, headers))
    return s


def test_fetch_bytes_decodes_gzip():
    s = _session_serving(gzip.compress(b"hello"), {"Content-Encoding": "gzip"})
    assert s.fetch_bytes("http://x") == b"hello"


def test_fetch_bytes_decodes_deflate():
    s = _session_serving(zlib.compress(b"cssdata"), {"Content-Encoding": "deflate"})
    assert s.fetch_bytes("http://x") == b"cssdata"


def test_fetch_bytes_identity_passthrough():
    s = _session_serving(b"plain", {})
    assert s.fetch_bytes("http://x") == b"plain"


def test_fetch_text_decodes_deflate():
    s = _session_serving(zlib.compress("juïce".encode()),
                         {"Content-Encoding": "deflate"})
    assert s.fetch("http://x") == "juïce"
