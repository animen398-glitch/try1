"""Scan-cache clear helpers used by the Settings 'Очистить кеш' button."""

from core.recon_engine import _GEO_CACHE, clear_geo_cache
from core.subdomain_scanner import _PASSIVE_CACHE, clear_passive_cache


def test_clear_geo_cache_empties_and_counts():
    _GEO_CACHE.clear()
    _GEO_CACHE.set("1.2.3.4", {"country": "US"})
    _GEO_CACHE.set("5.6.7.8", {"country": "DE"})
    assert clear_geo_cache() == 2
    assert len(_GEO_CACHE) == 0


def test_clear_passive_cache_empties_and_counts():
    _PASSIVE_CACHE.clear()
    _PASSIVE_CACHE.set(("crtsh", "example.com"), ["a.example.com"])
    assert clear_passive_cache() == 1
    assert len(_PASSIVE_CACHE) == 0


def test_clear_on_empty_cache_returns_zero():
    _GEO_CACHE.clear()
    assert clear_geo_cache() == 0
