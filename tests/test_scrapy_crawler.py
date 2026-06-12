"""Tests for core.scrapy_crawler — offline (subprocess + scrapy are faked)."""

import json
import subprocess
import types

import core.scrapy_crawler as sc
from core.scrapy_crawler import ScrapyCrawler


def _out_from_cmd(cmd):
    return cmd[cmd.index('--out') + 1]


def test_unavailable_scrapy_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(sc, 'has_scrapy', lambda: False)
    result = ScrapyCrawler().crawl('https://example.com')
    assert result['status'] == 'Error'
    assert 'scrapy not installed' in result['error']
    assert result['items'] == [] and result['pages'] == 0


def test_successful_crawl_parses_feed(monkeypatch, tmp_path):
    monkeypatch.setattr(sc, 'has_scrapy', lambda: True)

    def fake_run(cmd, **kw):
        with open(_out_from_cmd(cmd), 'w', encoding='utf-8') as f:
            f.write(json.dumps({'url': 'https://x.com/', 'status': 200,
                                'title': 'Home', 'depth': 0, 'size': 1200}) + '\n')
            f.write(json.dumps({'url': 'https://x.com/a', 'status': 404,
                                'title': '', 'depth': 1, 'size': 30}) + '\n')
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(sc.subprocess, 'run', fake_run)
    result = ScrapyCrawler().crawl('x.com')

    assert result['status'] == 'Success'
    assert result['url'] == 'https://x.com'        # scheme prepended
    assert result['pages'] == 2
    assert result['items'][0]['title'] == 'Home'
    assert result['truncated'] is False


def test_timeout_returns_partial_results(monkeypatch):
    monkeypatch.setattr(sc, 'has_scrapy', lambda: True)

    def fake_run(cmd, **kw):
        # Simulate a crawl that wrote one page before being killed at timeout.
        with open(_out_from_cmd(cmd), 'w', encoding='utf-8') as f:
            f.write(json.dumps({'url': 'https://x.com/', 'status': 200,
                                'title': 'partial', 'depth': 0, 'size': 10}) + '\n')
        raise subprocess.TimeoutExpired(cmd, kw.get('timeout', 1))

    monkeypatch.setattr(sc.subprocess, 'run', fake_run)
    result = ScrapyCrawler(timeout=1).crawl('https://x.com')

    assert result['status'] == 'Success'
    assert result['truncated'] is True
    assert result['pages'] == 1


def test_nonzero_exit_reports_error(monkeypatch):
    monkeypatch.setattr(sc, 'has_scrapy', lambda: True)

    def fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=2, stdout='', stderr='boom')

    monkeypatch.setattr(sc.subprocess, 'run', fake_run)
    result = ScrapyCrawler().crawl('https://x.com')
    assert result['status'] == 'Error'
    assert 'exited 2' in result['error'] and result['pages'] == 0


def test_read_feed_skips_bad_lines_and_missing(tmp_path):
    p = tmp_path / 'feed.jsonl'
    p.write_text('{"url":"a"}\nnot json\n\n{"url":"b"}\n', encoding='utf-8')
    items = ScrapyCrawler._read_feed(p)
    assert [i['url'] for i in items] == ['a', 'b']
    assert ScrapyCrawler._read_feed(tmp_path / 'nope.jsonl') == []


def test_feed_is_cleaned_up_after_crawl(monkeypatch):
    monkeypatch.setattr(sc, 'has_scrapy', lambda: True)
    captured = {}

    def fake_run(cmd, **kw):
        out = _out_from_cmd(cmd)
        captured['out'] = out
        with open(out, 'w', encoding='utf-8') as f:
            f.write(json.dumps({'url': 'https://x.com/'}) + '\n')
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(sc.subprocess, 'run', fake_run)
    ScrapyCrawler().crawl('https://x.com')
    import os
    assert not os.path.exists(captured['out'])   # temp feed removed


def test_spider_runner_module_imports_without_scrapy():
    # The child runner must import (top-level is stdlib only); scrapy is loaded
    # lazily inside its functions / the subprocess.
    import core._scrapy_spider as spider
    assert hasattr(spider, 'main')
