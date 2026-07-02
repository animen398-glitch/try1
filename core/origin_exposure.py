"""Origin Exposure & Cloud Edge Intelligence (Roadmap E6).

Passively flag a potential **CDN bypass**: when the target's apex is served
behind a pure CDN edge (Cloudflare / Fastly / Akamai) but other names in the same
footprint resolve to *non-CDN* IPs, those IPs are candidate **origin** servers an
attacker could hit directly — bypassing the edge's WAF / rate-limiting / DDoS
protection. Surfacing them lets an authorized tester recommend locking the origin
down (allowlist the CDN, rotate the IP).

Pure / offline / derive-on-read over the scan report — it reuses
:mod:`core.cloud_classifier` (the SSOT for edge-vs-origin classification) over
data already collected (recon infrastructure + the opt-in subdomain phase). Zero
target traffic, no new network, no new dependency. **Display / intel only**: like
exposure / criticality it never changes the authoritative risk verdict, and it
never asserts a candidate *is* the origin — these are leads to verify.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.cloud_classifier import classify_cloud, is_cdn_cloud


def _phase_data(report: Dict[str, Any], name: str) -> Dict[str, Any]:
    phase = (report.get("phases") or {}).get(name)
    data = phase.get("data") if isinstance(phase, dict) else None
    return data if isinstance(data, dict) else {}


def _edge_cloud(recon: Dict[str, Any], infra: Dict[str, Any]) -> str:
    """The apex's hosting cloud — reuse the infra classification, else derive."""
    cloud = str(infra.get("cloud") or "").strip()
    if cloud:
        return cloud
    return str(
        classify_cloud(
            provider=infra.get("provider", ""),
            asn_name=infra.get("asn_name", ""),
            asn=infra.get("asn", ""),
            technologies=recon.get("technologies"),
        ).get("cloud", "")
    )


def _origin_candidates(report: Dict[str, Any], edge_ip: str) -> List[Dict[str, Any]]:
    """Non-CDN IPs in the footprint that could be a direct origin (deduped by IP).

    Source: the opt-in subdomain phase's resolved A-records. A subdomain that is
    itself CDN-fronted (its CNAME points to a CDN) is an edge, not an origin, so
    it is skipped; the apex's own edge IP is skipped too.
    """
    candidates: List[Dict[str, Any]] = []
    seen: set[str] = set()
    sub = _phase_data(report, "subdomains")
    results = sub.get("results") if isinstance(sub.get("results"), list) else []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip") or "").strip()
        host = str(entry.get("subdomain") or "").strip()
        if not ip or ip == edge_ip or ip in seen:
            continue
        sub_cloud = str(classify_cloud(cname=entry.get("cname") or "").get("cloud", ""))
        if is_cdn_cloud(sub_cloud):
            continue  # a CDN-fronted name resolves to an edge, not an origin
        seen.add(ip)
        candidates.append(
            {
                "ip": ip,
                "host": host,
                "source": "subdomain",
                "cloud": sub_cloud or "unknown",
            }
        )
    return candidates


def _empty() -> Dict[str, Any]:
    return {
        "behind_cdn": False,
        "edge": {},
        "candidates": [],
        "exposed": False,
        "summary": {"behind_cdn": False, "candidates": 0, "exposed": False,
                    "edge_cloud": ""},
    }


def build_origin_exposure(report: Dict[str, Any]) -> Dict[str, Any]:
    """Derive the origin-exposure view from a scan ``report`` (pure, offline).

    Returns ``{behind_cdn, edge:{cloud,ip}, candidates:[{ip,host,source,cloud}],
    exposed, summary}``. ``exposed`` is True only when the apex is behind a pure
    CDN edge *and* at least one non-CDN origin candidate exists. Malformed input
    yields a safe empty view rather than raising.
    """
    if not isinstance(report, dict):
        return _empty()
    recon = _phase_data(report, "recon")
    infra = recon.get("infrastructure")
    infra = infra if isinstance(infra, dict) else {}

    edge_cloud = _edge_cloud(recon, infra)
    behind_cdn = is_cdn_cloud(edge_cloud)
    edge_ip = str(recon.get("ip") or infra.get("ip") or "").strip()

    candidates = _origin_candidates(report, edge_ip)
    exposed = bool(behind_cdn and candidates)

    edge: Dict[str, Any] = {}
    if edge_cloud:
        edge["cloud"] = edge_cloud
    if edge_ip:
        edge["ip"] = edge_ip

    return {
        "behind_cdn": behind_cdn,
        "edge": edge,
        "candidates": candidates,
        "exposed": exposed,
        "summary": {
            "behind_cdn": behind_cdn,
            "candidates": len(candidates),
            "exposed": exposed,
            "edge_cloud": edge_cloud,
        },
    }
