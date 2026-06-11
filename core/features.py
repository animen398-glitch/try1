"""core/features.py
Centralised detection of optional, externally-installed capabilities.

The app's heavy features (dynamic sniffing, media download, 4K merge, the web
console) depend on optional packages / binaries that are intentionally not
bundled. This module is the single place that answers "is X available?" so the
GUI and CLI can surface what's enabled instead of scattering ad-hoc checks.
"""

import importlib.util
import shutil


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def has_playwright() -> bool:
    return _has_module('playwright')


def has_ytdlp() -> bool:
    return _has_binary('yt-dlp') or _has_module('yt_dlp')


def has_ffmpeg() -> bool:
    return _has_binary('ffmpeg')


def has_fastapi() -> bool:
    return _has_module('fastapi') and _has_module('uvicorn')


def has_lxml() -> bool:
    return _has_module('lxml')


def has_scrapy() -> bool:
    # find_spec only — never import scrapy in the GUI process (it pulls in the
    # Twisted reactor); the actual crawl runs in a child process.
    return _has_module('scrapy')


# Optional feature -> (what it enables, detector).
OPTIONAL_FEATURES = {
    'playwright': ('Dynamic API Sniffing (headless Chromium)', has_playwright),
    'yt-dlp':     ('Video / Instagram download',               has_ytdlp),
    'ffmpeg':     ('4K/1080p video merge',                     has_ffmpeg),
    'fastapi':    ('Web console (LAN)',                        has_fastapi),
    'lxml':       ('Faster HTML parsing',                      has_lxml),
    'scrapy':     ('Deep site crawl (subprocess)',             has_scrapy),
}


def summary() -> dict:
    """Map each optional feature to {available, enables}."""
    return {
        name: {'available': detect(), 'enables': desc}
        for name, (desc, detect) in OPTIONAL_FEATURES.items()
    }


def missing() -> list:
    """Names of optional features that are not currently available."""
    return [name for name, (_desc, detect) in OPTIONAL_FEATURES.items()
            if not detect()]
