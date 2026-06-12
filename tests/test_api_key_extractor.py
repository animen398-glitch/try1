"""Tests for core.api_key_extractor — offline, focused on the gzip fix.

Regression for the bug where a gzip-compressed page was read without
decompression, so the scanner saw mojibake and reported zero leaks.
"""

import gzip
from email.message import Message

import core.api_key_extractor as ake
import utils.http_retry as hr
from core.api_key_extractor import ApiKeyExtractor
from core.paths import PathManager

_PAGE = (
    "<html><script>"
    "var k='AKIA1234567890ABCD56';"
    "var gh='ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';"
    "</script></html>"
)


class _Resp:
    def __init__(self, body, headers):
        self._body, self.headers = body, headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def _serve(monkeypatch, body, headers):
    monkeypatch.setattr(hr.urllib.request, 'urlopen',
                        lambda req, timeout: _Resp(body, headers))


def test_finds_secrets_in_gzipped_page(monkeypatch, tmp_path):
    # Reports go to an isolated tmp root, not the repo / home dir.
    monkeypatch.setattr(ake, 'get_path_manager',
                        lambda: PathManager(data_root=tmp_path, resource_root=tmp_path))
    headers = Message()
    headers['Content-Encoding'] = 'gzip'
    _serve(monkeypatch, gzip.compress(_PAGE.encode('utf-8')), headers)

    ext = ApiKeyExtractor()
    ext.set_target_url('example.com')
    res = ext.run_extraction()

    assert res['status'] == 'Success'
    assert res['keys_found'] == 2                       # both, despite gzip
    assert 'AWS Access Key' in res['details']
    assert 'GitHub Token' in res['details']


def test_report_written_under_path_manager_not_home(monkeypatch, tmp_path):
    monkeypatch.setattr(ake, 'get_path_manager',
                        lambda: PathManager(data_root=tmp_path, resource_root=tmp_path))
    _serve(monkeypatch, _PAGE.encode('utf-8'), Message())   # uncompressed

    ext = ApiKeyExtractor()
    ext.set_target_url('https://example.com')
    ext.run_extraction()

    report = tmp_path / 'reports' / 'api_keys_example.com.txt'
    assert report.exists()
    assert 'AKIA1234567890ABCD56' in report.read_text(encoding='utf-8')


def test_plain_page_still_scanned(monkeypatch, tmp_path):
    monkeypatch.setattr(ake, 'get_path_manager',
                        lambda: PathManager(data_root=tmp_path, resource_root=tmp_path))
    _serve(monkeypatch, _PAGE.encode('utf-8'), Message())

    ext = ApiKeyExtractor()
    ext.set_target_url('https://example.com')
    res = ext.run_extraction()
    assert res['keys_found'] == 2
