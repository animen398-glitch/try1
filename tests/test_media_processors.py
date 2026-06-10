"""Tests for the media downloader helpers (network-free)."""

import pytest

from utils.image_processor import ImageExtractor, _prefer_original
from utils.video_processor import QUALITY_FORMATS, VideoDownloader


# ── video format resolution ──────────────────────────────────────────────────

def test_resolve_format_merges_when_ffmpeg(monkeypatch):
    monkeypatch.setattr(VideoDownloader, "has_ffmpeg", staticmethod(lambda: True))
    vd = VideoDownloader(quality="4k")
    assert vd._resolve_format() == QUALITY_FORMATS["4k"]
    assert "+" in vd._resolve_format()


def test_resolve_format_progressive_without_ffmpeg(monkeypatch):
    monkeypatch.setattr(VideoDownloader, "has_ffmpeg", staticmethod(lambda: False))
    vd = VideoDownloader(quality="1080p")
    fmt = vd._resolve_format()
    assert "+" not in fmt
    assert "height<=1080" in fmt


def test_resolve_format_passthrough_raw_expression():
    vd = VideoDownloader(quality="bestaudio[ext=m4a]")
    assert vd._resolve_format() == "bestaudio[ext=m4a]"


def test_build_cmd_includes_cookies_and_merge(monkeypatch):
    monkeypatch.setattr(VideoDownloader, "has_ffmpeg", staticmethod(lambda: True))
    vd = VideoDownloader(quality="4k", cookies="c.txt")
    cmd = vd._build_cmd("https://x/y", "out/%(title)s.%(ext)s")
    assert "--cookies" in cmd and "c.txt" in cmd
    assert "--merge-output-format" in cmd and "mp4" in cmd


def test_build_cmd_audio_extract(monkeypatch):
    monkeypatch.setattr(VideoDownloader, "has_ffmpeg", staticmethod(lambda: True))
    vd = VideoDownloader(quality="audio")
    cmd = vd._build_cmd("https://x/y", "tmpl")
    assert "--extract-audio" in cmd
    assert "--merge-output-format" not in cmd  # audio is a single stream


# ── image url normalization / srcset / routing ───────────────────────────────

def test_prefer_original_strips_resize_params():
    out = _prefer_original("https://cdn/p.jpg?w=320&h=240&quality=70&id=5")
    assert "w=" not in out and "h=" not in out and "quality=" not in out
    assert "id=5" in out  # non-resize params preserved


def test_prefer_original_strips_cdn_size_segment():
    out = _prefer_original("https://scontent.cdninstagram.com/v/t51/s640x640/a_n.jpg")
    assert "s640x640" not in out
    assert out.endswith("/v/t51/a_n.jpg")


def test_prefer_original_leaves_plain_url():
    url = "https://img.site/photo.png"
    assert _prefer_original(url) == url


@pytest.mark.parametrize("srcset,expected", [
    ("small.jpg 320w, medium.jpg 768w, large.jpg 1920w", "large.jpg"),
    ("a.jpg 1x, b.jpg 3x, c.jpg 2x", "b.jpg"),
    ("only.jpg", "only.jpg"),
])
def test_largest_srcset(srcset, expected):
    assert ImageExtractor._largest_srcset(srcset) == expected


@pytest.mark.parametrize("url,expected", [
    ("https://www.instagram.com/p/abc/", True),
    ("https://x.com/user/status/1", True),
    ("https://example.com/gallery", False),
])
def test_is_gallery_host(url, expected):
    assert ImageExtractor._is_gallery_host(url) is expected
