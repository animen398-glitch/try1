"""Tests for utils.http_retry — deterministic (injected sleep/rng, no network)."""

import gzip
import socket
import urllib.error
import zlib
from email.message import Message

import pytest

import utils.http_retry as hr
from utils.http_retry import (
    decompress, is_transient, retry, urlopen_retry, urlopen_text,
)


def _http_error(code, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers['Retry-After'] = str(retry_after)
    return urllib.error.HTTPError('http://x', code, 'err', headers, None)


# ----------------------------------------------------------- classification

def test_is_transient_classification():
    assert is_transient(_http_error(429)) is True
    assert is_transient(_http_error(503)) is True
    assert is_transient(_http_error(404)) is False
    assert is_transient(urllib.error.URLError('boom')) is True
    assert is_transient(socket.timeout()) is True
    assert is_transient(TimeoutError()) is True
    assert is_transient(ValueError('bad json')) is False


# ------------------------------------------------------------------- retry

def test_succeeds_first_try_without_sleeping():
    slept = []
    out = retry(lambda: 'ok', sleep=slept.append)
    assert out == 'ok'
    assert slept == []


def test_retries_transient_then_succeeds():
    slept, calls = [], []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError('flaky')
        return 'done'

    out = retry(fn, attempts=5, sleep=slept.append, rng=lambda: 0.5)
    assert out == 'done'
    assert len(calls) == 3        # failed twice, succeeded on the third
    assert len(slept) == 2        # slept once per retry


def test_non_transient_raises_immediately():
    slept = []
    with pytest.raises(urllib.error.HTTPError):
        retry(lambda: (_ for _ in ()).throw(_http_error(404)), sleep=slept.append)
    assert slept == []            # 404 is permanent — no retry


def test_exhausts_attempts_and_reraises_last():
    slept, calls = [], []

    def fn():
        calls.append(1)
        raise urllib.error.URLError('always down')

    with pytest.raises(urllib.error.URLError):
        retry(fn, attempts=3, sleep=slept.append, rng=lambda: 0.5)
    assert len(calls) == 3        # tried exactly `attempts` times
    assert len(slept) == 2        # slept between attempts only


def test_backoff_is_exponential_with_jitter():
    slept = []
    calls = []

    def fn():
        calls.append(1)
        raise urllib.error.URLError('down')

    # rng()=0.5 -> jitter factor (0.5 + 0.5) = 1.0, so delay == base*2**i.
    with pytest.raises(urllib.error.URLError):
        retry(fn, attempts=4, base_delay=1.0, max_delay=100,
              sleep=slept.append, rng=lambda: 0.5)
    assert slept == [1.0, 2.0, 4.0]


def test_retry_after_header_overrides_backoff():
    slept = []
    calls = []

    def fn():
        calls.append(1)
        raise _http_error(503, retry_after=2)

    with pytest.raises(urllib.error.HTTPError):
        retry(fn, attempts=2, base_delay=10, sleep=slept.append, rng=lambda: 0.5)
    assert slept == [2.0]         # server's Retry-After wins over computed delay


def test_retry_after_is_capped():
    slept = []
    with pytest.raises(urllib.error.HTTPError):
        retry(lambda: (_ for _ in ()).throw(_http_error(503, retry_after=99999)),
              attempts=2, sleep=slept.append, rng=lambda: 0.5)
    assert slept == [hr._MAX_RETRY_AFTER]


def test_invalid_attempts_rejected():
    with pytest.raises(ValueError):
        retry(lambda: 'x', attempts=0)


# ------------------------------------------------------------- urlopen_retry

class _FakeResp:
    def __init__(self, body, headers, final_url='https://final/'):
        self._body, self.headers, self._url = body, headers, final_url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body

    def geturl(self):
        return self._url


def test_urlopen_retry_returns_body_and_headers(monkeypatch):
    monkeypatch.setattr(hr.urllib.request, 'urlopen',
                        lambda req, timeout: _FakeResp(b'hello', {'X': '1'}))
    body, headers = urlopen_retry('req', 5)
    assert body == b'hello' and headers == {'X': '1'}


def test_urlopen_retry_optional_final_url(monkeypatch):
    # return_final_url=True adds the post-redirect URL as a third element; the
    # default two-tuple shape is unaffected.
    monkeypatch.setattr(hr.urllib.request, 'urlopen', lambda req, timeout:
                        _FakeResp(b'x', {}, final_url='https://x/after-redirect'))
    body, headers, final = urlopen_retry('req', 5, return_final_url=True)
    assert body == b'x' and final == 'https://x/after-redirect'


def test_urlopen_retry_retries_then_succeeds(monkeypatch):
    slept, calls = [], []

    def fake_urlopen(req, timeout):
        calls.append(1)
        if len(calls) < 2:
            raise socket.timeout()
        return _FakeResp(b'ok', {})

    monkeypatch.setattr(hr.urllib.request, 'urlopen', fake_urlopen)
    body, _ = urlopen_retry('req', 5, sleep=slept.append, rng=lambda: 0.5)
    assert body == b'ok'
    assert len(calls) == 2 and len(slept) == 1


# --------------------------------------------------------------- decompress

def test_decompress_gzip_deflate_and_plain():
    assert decompress(gzip.compress(b'hello'), {'Content-Encoding': 'gzip'}) == b'hello'
    assert decompress(zlib.compress(b'hi'), {'Content-Encoding': 'deflate'}) == b'hi'
    assert decompress(b'plain', {}) == b'plain'          # no encoding -> as-is


def test_decompress_falls_back_to_magic_number():
    # Header missing but body is gzip — detected by the 1f 8b magic number.
    assert decompress(gzip.compress(b'magic'), {}) == b'magic'


def test_decompress_returns_raw_on_bad_data():
    # Claims gzip but isn't — must not raise, just return the bytes.
    assert decompress(b'not gzip', {'Content-Encoding': 'gzip'}) == b'not gzip'


def test_urlopen_text_decompresses_and_decodes(monkeypatch):
    headers = Message()
    headers['Content-Encoding'] = 'gzip'
    body = gzip.compress('héllo'.encode('utf-8'))
    monkeypatch.setattr(hr.urllib.request, 'urlopen',
                        lambda req, timeout: _FakeResp(body, headers))
    assert urlopen_text('req', 5) == 'héllo'
