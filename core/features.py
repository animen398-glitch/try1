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


def has_nuclei() -> bool:
    """projectdiscovery/nuclei — external vuln-template scanner (optional)."""
    return _has_binary('nuclei')


def has_katana() -> bool:
    """projectdiscovery/katana — external crawler (optional)."""
    return _has_binary('katana')


def has_amass() -> bool:
    """owasp/amass — external subdomain enumeration (optional)."""
    return _has_binary('amass')


def has_subfinder() -> bool:
    """projectdiscovery/subfinder — external passive subdomain enum (optional)."""
    return _has_binary('subfinder')


def has_httpx() -> bool:
    """projectdiscovery/httpx — external HTTP prober / liveness (optional)."""
    return _has_binary('httpx')


def has_bbot() -> bool:
    """blacklanternsecurity/bbot — external recon/ASM enrichment engine (optional).

    Detected by its CLI on PATH (like the other external tools), never imported:
    BBOT is AGPL-3.0, so it is used only as a separate external tool via
    subprocess + its JSON output, never as a bundled or required dependency
    (EPIC EXT-OSINT F1). Absent → the BBOT phase degrades to a skip."""
    return _has_binary('bbot')


def has_ollama() -> bool:
    """A local Ollama answering on localhost (optional LLM narrative).

    Unlike the others this probes a *running service*, so it makes a short
    localhost request rather than a find_spec/which check — kept out of
    OPTIONAL_FEATURES below so the instant, network-free detection there is
    preserved. Callers that want it ask for it explicitly.
    """
    from core.llm_summary import available
    return available()


# Optional feature -> (what it enables, detector).
OPTIONAL_FEATURES = {
    'playwright': ('Dynamic API Sniffing (headless Chromium)', has_playwright),
    'yt-dlp':     ('Video / Instagram download',               has_ytdlp),
    'ffmpeg':     ('4K/1080p video merge',                     has_ffmpeg),
    'fastapi':    ('Web console (LAN)',                        has_fastapi),
    'lxml':       ('Faster HTML parsing',                      has_lxml),
    'scrapy':     ('Deep site crawl (subprocess)',             has_scrapy),
    'nuclei':     ('Nuclei vuln templates (external binary)',  has_nuclei),
    'katana':     ('Katana crawler — endpoints (external)',    has_katana),
    'amass':      ('Amass subdomain enum (external)',          has_amass),
    'subfinder':  ('Subfinder passive subdomain enum (external)', has_subfinder),
    'httpx':      ('Httpx HTTP prober — live hosts (external)', has_httpx),
    'bbot':       ('BBOT external recon/ASM enrichment (external)', has_bbot),
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
