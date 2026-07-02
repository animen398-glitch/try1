"""Passive OSINT Intelligence Layer (Roadmap E1).

Enrich known assets from third-party OSINT databases with **zero target
traffic** — every lookup queries a public dataset (Shodan, Censys, cert logs),
never the target host itself. Strictly passive: no scanning, probing, exploit or
stealth behaviour of any kind.

First provider (keyless-first): **Shodan InternetDB**
(``https://internetdb.shodan.io/{ip}``) — a free, key-less endpoint that returns
Shodan's *already-collected* view of an IP (open ports, hostnames, CPEs, tags,
CVE ids). Because it reads Shodan's database, our process sends no packet to the
target; it is the canonical E1 "zero target traffic" source.

Design (mirrors ``core.update_check`` / ``core.threat_feed``)
------------------------------------------------------------
- Pure parsing is separated from the transport, and the transport (``_fetch``)
  is injectable, so every code path is unit-tested offline with no network.
- Never raises: a bad address, a network error or malformed JSON degrades to an
  empty result, so a caller can enrich best-effort without a try/except.
- Maps into the existing canonical DTOs (``asset_adapter.Asset`` /
  ``findings_adapter.from_raw``) — no second store, no new finding model. This
  module writes nothing; persistence is an explicit later step.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import urllib.request
from typing import Any, Callable, Dict, List, NamedTuple, Optional


class PassiveSource(NamedTuple):
    """Descriptor for one passive OSINT provider (registry entry)."""
    name: str
    requires_key: bool
    target_kind: str          # what the lookup key is: 'ip' | 'domain'
    description: str


# Registry of passive providers. Keyless-first; keyed providers (Shodan API,
# Censys) plug in here later behind an opt-in configured key.
PASSIVE_SOURCES: Dict[str, PassiveSource] = {
    "shodan_internetdb": PassiveSource(
        name="shodan_internetdb",
        requires_key=False,
        target_kind="ip",
        description="Shodan InternetDB — open ports/CPEs/CVEs for an IP (keyless, "
                    "zero target traffic).",
    ),
    "shodan_api": PassiveSource(
        name="shodan_api",
        requires_key=True,
        target_kind="ip",
        description="Shodan Host API — richer ports/hostnames/CPEs/CVEs for an IP "
                    "(needs an API key; zero target traffic).",
    ),
    "censys": PassiveSource(
        name="censys",
        requires_key=True,
        target_kind="ip",
        description="Censys Hosts API — services/ports/DNS/software for an IP "
                    "(needs API id+secret; zero target traffic).",
    ),
}

_INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
_CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
_USER_AGENT = "AdvancedSiteAnalyzer-PassiveOSINT"


def list_sources(*, keyless_only: bool = False) -> List[PassiveSource]:
    """All registered passive sources (optionally only the keyless ones)."""
    sources = sorted(PASSIVE_SOURCES.values(), key=lambda s: s.name)
    return [s for s in sources if not (keyless_only and s.requires_key)]


def _fetch(url: str, timeout: float) -> Dict[str, Any]:
    """HTTPS-only GET returning parsed JSON (raises on any failure)."""
    if not str(url).lower().startswith("https://"):
        raise ValueError("passive OSINT endpoint must be https://")
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https-only, checked
        return json.loads(resp.read().decode("utf-8", "replace"))


def _str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    return out


def parse_internetdb(payload: Any) -> Dict[str, Any]:
    """Normalize a Shodan InternetDB response into a stable dict.

    Returns ``{ip, ports, hostnames, cpes, tags, vulns}`` (empty when the payload
    carries no IP). Tolerates missing/foreign keys; ``ports`` are coerced to
    ints, everything else to de-duplicated string lists.
    """
    if not isinstance(payload, dict):
        return {}
    ip = str(payload.get("ip") or "").strip()
    if not ip:
        return {}
    ports: List[int] = []
    for raw in payload.get("ports") or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if port not in ports:
            ports.append(port)
    return {
        "ip": ip,
        "ports": sorted(ports),
        "hostnames": _str_list(payload.get("hostnames")),
        "cpes": _str_list(payload.get("cpes")),
        "tags": _str_list(payload.get("tags")),
        "vulns": _str_list(payload.get("vulns")),
        "source": "shodan_internetdb",
    }


def query_internetdb(
    ip: str,
    *,
    fetch: Optional[Callable[[str, float], Dict[str, Any]]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Look an IP up in Shodan's InternetDB (passive, best-effort).

    Validates ``ip`` locally first (no request for a non-IP), then fetches and
    parses. ``fetch`` is injectable for offline tests. Never raises — any
    failure yields ``{}`` so callers enrich opportunistically.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {}
    getter = fetch if fetch is not None else _fetch
    try:
        payload = getter(_INTERNETDB_URL.format(ip=addr), timeout)
    except Exception:
        return {}
    return parse_internetdb(payload)


# --- keyed providers (opt-in, behind a configured key) -----------------------

def _fetch_basic(url: str, timeout: float, api_id: str, api_secret: str) -> Dict[str, Any]:
    """HTTPS-only GET with HTTP Basic auth (for Censys); raises on failure."""
    if not str(url).lower().startswith("https://"):
        raise ValueError("passive OSINT endpoint must be https://")
    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode("ascii")
    req = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": _USER_AGENT,
        "Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https-only, checked
        return json.loads(resp.read().decode("utf-8", "replace"))


def parse_shodan_host(payload: Any) -> Dict[str, Any]:
    """Normalize a Shodan Host API response to the common shape.

    Shodan returns ``ip_str``/``ports``/``hostnames``/``tags`` plus a ``data``
    list of service banners carrying ``cpe``/``cpe23`` and per-service ``vulns``.
    Flattened into the same ``{ip, ports, hostnames, cpes, tags, vulns}`` shape
    as InternetDB.
    """
    if not isinstance(payload, dict):
        return {}
    ip = str(payload.get("ip_str") or payload.get("ip") or "").strip()
    if not ip:
        return {}
    ports: List[int] = []
    for raw in payload.get("ports") or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if port not in ports:
            ports.append(port)
    cpes: List[str] = []
    vulns: List[str] = list(payload.get("vulns") or [])
    for svc in payload.get("data") or []:
        if not isinstance(svc, dict):
            continue
        for key in ("cpe23", "cpe"):
            cpes.extend(svc.get(key) or [])
        svc_vulns = svc.get("vulns")
        if isinstance(svc_vulns, dict):
            vulns.extend(svc_vulns.keys())
        elif isinstance(svc_vulns, list):
            vulns.extend(svc_vulns)
    return {
        "ip": ip,
        "ports": sorted(ports),
        "hostnames": _str_list(payload.get("hostnames")),
        "cpes": _str_list(cpes),
        "tags": _str_list(payload.get("tags")),
        "vulns": _str_list(vulns),
        "source": "shodan_api",
    }


def query_shodan(
    ip: str,
    api_key: str,
    *,
    fetch: Optional[Callable[[str, float], Dict[str, Any]]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Look an IP up via the keyed Shodan Host API (opt-in, best-effort).

    Returns ``{}`` when ``api_key`` is empty, the IP is invalid, or the request
    fails — never raises. ``fetch`` is injectable for offline tests.
    """
    key = str(api_key or "").strip()
    if not key:
        return {}
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {}
    getter = fetch if fetch is not None else _fetch
    try:
        payload = getter(_SHODAN_HOST_URL.format(ip=addr, key=key), timeout)
    except Exception:
        return {}
    return parse_shodan_host(payload)


def parse_censys_host(payload: Any) -> Dict[str, Any]:
    """Normalize a Censys Hosts API v2 response to the common shape.

    Censys nests the host under ``result`` with ``services[].port`` and DNS
    names under ``dns``/``services[].dns``. CVEs are not part of the base host
    view, so ``vulns`` is typically empty here.
    """
    if not isinstance(payload, dict):
        return {}
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    ip = str(result.get("ip") or "").strip()
    if not ip:
        return {}
    ports: List[int] = []
    cpes: List[str] = []
    for svc in result.get("services") or []:
        if not isinstance(svc, dict):
            continue
        try:
            port = int(svc.get("port"))
        except (TypeError, ValueError):
            port = None
        if port is not None and port not in ports:
            ports.append(port)
        for sw in svc.get("software") or []:
            if isinstance(sw, dict) and sw.get("uniform_resource_identifier"):
                cpes.append(sw["uniform_resource_identifier"])
    dns = result.get("dns") if isinstance(result.get("dns"), dict) else {}
    hostnames = dns.get("names") or (dns.get("reverse_dns") or {}).get("names") or []
    return {
        "ip": ip,
        "ports": sorted(ports),
        "hostnames": _str_list(hostnames),
        "cpes": _str_list(cpes),
        "tags": _str_list(result.get("labels")),
        "vulns": [],
        "source": "censys",
    }


def query_censys(
    ip: str,
    api_id: str,
    api_secret: str,
    *,
    fetch: Optional[Callable[[str, float], Dict[str, Any]]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Look an IP up via the keyed Censys Hosts API (opt-in, best-effort).

    Returns ``{}`` without both credentials, on an invalid IP, or on request
    failure — never raises. ``fetch`` is injectable for offline tests; the real
    default uses HTTP Basic auth with the id+secret.
    """
    cid = str(api_id or "").strip()
    secret = str(api_secret or "").strip()
    if not (cid and secret):
        return {}
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {}
    getter = fetch if fetch is not None else (
        lambda u, t: _fetch_basic(u, t, cid, secret))
    try:
        payload = getter(_CENSYS_HOST_URL.format(ip=addr), timeout)
    except Exception:
        return {}
    return parse_censys_host(payload)


def _osint_config() -> Dict[str, Any]:
    """The ``passive_osint`` settings block (best-effort; ``{}`` on any error)."""
    try:
        from core.config import load_settings
        cfg = load_settings().get("passive_osint")
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        return {}


def query_best(
    ip: str,
    *,
    config: Optional[Dict[str, Any]] = None,
    fetch_map: Optional[Dict[str, Callable[[str, float], Dict[str, Any]]]] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Enrich an IP from the richest available passive source.

    Prefers keyed providers when a key is configured (Shodan API, then Censys),
    falling back to keyless InternetDB. Keyed lookups are guarded so a keyed
    failure falls through; the final InternetDB call is left bare (it already
    soft-degrades to ``{}``), so this composes with the scan phase's backstop.
    """
    cfg = config if isinstance(config, dict) else _osint_config()
    fetches = fetch_map or {}

    shodan_key = str(cfg.get("shodan_api_key") or "").strip()
    if shodan_key:
        try:
            result = query_shodan(ip, shodan_key,
                                  fetch=fetches.get("shodan_api"), timeout=timeout)
        except Exception:
            result = {}
        if result:
            return result

    censys_id = str(cfg.get("censys_api_id") or "").strip()
    censys_secret = str(cfg.get("censys_api_secret") or "").strip()
    if censys_id and censys_secret:
        try:
            result = query_censys(ip, censys_id, censys_secret,
                                  fetch=fetches.get("censys"), timeout=timeout)
        except Exception:
            result = {}
        if result:
            return result

    return query_internetdb(ip, fetch=fetches.get("shodan_internetdb"), timeout=timeout)


# --- mapping into canonical DTOs (no store writes) ---------------------------

def osint_to_assets(result: Dict[str, Any], *, source: Optional[str] = None) -> List["Any"]:
    """Map a parsed passive result into ``asset_adapter.Asset`` DTOs.

    The IP itself (with ports/tags as context), each resolved hostname, and each
    CPE (as a technology) become assets tagged with the discovering source. No
    persistence — the caller decides whether to sync them. ``source`` overrides
    the stored source label (the scan integration passes the phase name
    ``passive_osint`` so the asset lifecycle gates GONE on that phase).
    """
    from core.asset_adapter import Asset

    if not isinstance(result, dict) or not result.get("ip"):
        return []
    source = source or result.get("source") or "passive_osint"
    assets: List[Any] = []
    ip_attrs = {"source": source}
    if result.get("ports"):
        ip_attrs["ports"] = list(result["ports"])
    if result.get("tags"):
        ip_attrs["tags"] = list(result["tags"])
    assets.append(Asset("ip", str(result["ip"]), attrs=ip_attrs))
    for host in result.get("hostnames") or []:
        assets.append(Asset("subdomain", host, attrs={"source": source}))
    for cpe in result.get("cpes") or []:
        assets.append(Asset("technology", cpe, attrs={"source": source}))
    return assets


def osint_to_findings(result: Dict[str, Any]) -> List["Any"]:
    """Map CVE ids from a passive result into ``findings_adapter.Finding`` DTOs.

    Passive OSINT associates CVEs with an IP via CPE inference — it is *not* a
    confirmed vulnerability on the target. So each is emitted at ``Info``
    severity with an explicit "passive OSINT, unverified" detail, and gets the
    canonical CVE identity via ``from_raw`` (so it dedups with real scanner CVE
    findings rather than double-counting). No persistence here.
    """
    from core.findings_adapter import from_raw

    if not isinstance(result, dict) or not result.get("ip"):
        return []
    ip = str(result["ip"])
    source = result.get("source") or "passive_osint"
    findings: List[Any] = []
    for cve in result.get("vulns") or []:
        findings.append(
            from_raw(
                {
                    "title": f"{cve} associated with {ip} (passive OSINT)",
                    "severity": "Info",
                    "cve": cve,
                    "source": source,
                    "location": ip,
                    "detail": (
                        f"{cve} is associated with {ip} in Shodan's dataset via "
                        "CPE inference — passive OSINT, unverified against the "
                        "live target."
                    ),
                }
            )
        )
    return findings
