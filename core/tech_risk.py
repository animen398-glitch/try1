"""Technology Risk Scoring (Epic 15).

Pure derive-on-read scoring over technologies and JS dependency data already
present in a collection report. It does not fetch, probe, or add new findings:
the output is a display/handoff layer that explains which detected technologies
deserve attention without double-counting CVE/dependency findings in the main
risk verdict.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple


_SEV_POINTS = {"critical": 55, "high": 40, "medium": 25, "low": 10, "info": 5}
_BAND_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Conservative lifecycle/EOL policy hints. These are not CVE assertions; they are
# maintenance risk signals for versions/families that are broadly unsupported.
_TECH_POLICIES = {
    "php": {"below": "8.1.0", "points": 35, "reason": "PHP branch is likely EOL"},
    "angular": {"below": "2.0.0", "points": 35, "reason": "AngularJS-era version"},
    "flask / werkzeug": {
        "below": "2.3.0",
        "points": 20,
        "reason": "older Werkzeug/Flask stack",
    },
}

_DEPENDENCY_EOL = {
    "angular": {"points": 35, "reason": "AngularJS is end-of-life"},
}


def _parse_version(value: Any) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in str(value or "").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _lt(a: Any, b: Any) -> bool:
    return _parse_version(a) < _parse_version(b)


def _band(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def _norm_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _recon(report: Dict[str, Any]) -> Dict[str, Any]:
    phases = report.get("phases", {}) if isinstance(report, dict) else {}
    phase = phases.get("recon", {}) if isinstance(phases, dict) else {}
    data = phase.get("data", {}) if isinstance(phase, dict) else {}
    return data if isinstance(data, dict) else {}


def _vuln_score(vulns: Iterable[Dict[str, Any]]) -> Tuple[int, str]:
    score = 0
    worst = "info"
    for vuln in vulns:
        sev = str(vuln.get("severity") or "info").lower()
        score += _SEV_POINTS.get(sev, 5)
        if _BAND_ORDER.get(sev, 99) < _BAND_ORDER.get(worst, 99):
            worst = sev
    return score, worst


def _item(kind: str, name: str, version: Any, category: str, score: int,
          reason: str, evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        "version": version or "",
        "category": category,
        "score": min(100, max(0, int(score))),
        "band": _band(score),
        "reason": reason,
        "evidence": [str(e) for e in (evidence or []) if e],
    }


def _technology_items(technologies: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for tech in technologies or []:
        if not isinstance(tech, dict):
            continue
        name = str(tech.get("name") or "").strip()
        version = tech.get("version")
        category = str(tech.get("category") or "Technology")
        evidence = [str(tech.get("evidence") or "")]
        key = _norm_name(name)
        policy = _TECH_POLICIES.get(key)
        if policy and version and _lt(version, policy["below"]):
            items.append(_item("technology", name, version, category,
                               policy["points"], policy["reason"], evidence))
            continue
        if version and category in {"Server", "Backend", "Language"}:
            items.append(_item("technology", name, version, category, 10,
                               "technology version is publicly exposed",
                               evidence))
    return items


def _dependency_items(dependencies: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    libs = dependencies.get("libraries") if isinstance(dependencies, dict) else []
    for lib in libs or []:
        if not isinstance(lib, dict):
            continue
        name = str(lib.get("name") or lib.get("library") or "").strip()
        library = _norm_name(lib.get("library") or name)
        version = lib.get("version")
        vulns = [v for v in (lib.get("vulnerabilities") or []) if isinstance(v, dict)]
        if vulns:
            points, worst = _vuln_score(vulns)
            ids = []
            for vuln in vulns:
                if vuln.get("cve"):
                    ids.append(str(vuln["cve"]))
                elif vuln.get("detail"):
                    ids.append(str(vuln["detail"])[:80])
            items.append(_item(
                "dependency", name, version, "JS dependency", points,
                f"{len(vulns)} known vulnerable advisory/advisories; worst={worst}",
                ids,
            ))
            continue
        policy = _DEPENDENCY_EOL.get(library)
        if policy:
            items.append(_item("dependency", name, version, "JS dependency",
                               policy["points"], policy["reason"],
                               [library]))
    return items


def build_technology_risk(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact technology-risk view from an existing collection report."""
    recon = _recon(report)
    techs = recon.get("technologies") if isinstance(recon.get("technologies"), list) else []
    deps = recon.get("dependencies") if isinstance(recon.get("dependencies"), dict) else {}
    items = _technology_items(techs) + _dependency_items(deps)
    items.sort(key=lambda item: (-item["score"], item["name"].lower()))
    score = min(100, sum(item["score"] for item in items))
    summary = {
        "score": score,
        "band": _band(score),
        "items": len(items),
        "high": sum(1 for item in items if item["band"] == "high"),
        "medium": sum(1 for item in items if item["band"] == "medium"),
        "outdated_technologies": sum(
            1 for item in items
            if item["kind"] == "technology" and item["score"] >= 20
        ),
        "vulnerable_dependencies": sum(
            1 for item in items
            if item["kind"] == "dependency" and "known vulnerable" in item["reason"]
        ),
        "version_exposed": sum(
            1 for item in items
            if item["kind"] == "technology" and "version is publicly exposed" in item["reason"]
        ),
    }
    return {"summary": summary, "items": items}


def from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Public alias mirroring other derive-on-read core helpers."""
    return build_technology_risk(report)


def load_technology_risk(project) -> Dict[str, Any]:
    """Score a project's latest-scan technology risk (thin reader, EPIC 15).

    ``project`` is a :class:`core.project.Project` (report-based, like
    ``intelligence.load_accuracy`` — the posture needs the scan's recon phase). Loads
    the latest scan's ``report.json`` and delegates to :func:`build_technology_risk`.
    Offline, read-only, guarded — a missing report degrades to an empty view rather
    than crashing the caller."""
    empty = {"summary": {}, "items": []}
    try:
        if project is None:
            return dict(empty)
        latest = project.latest_scan()
        scan_id = latest.get("id") if isinstance(latest, dict) else None
        report = project.load_scan_report(scan_id) if scan_id else None
        if not isinstance(report, dict):
            return dict(empty)
        return build_technology_risk(report)
    except Exception as e:  # noqa: BLE001 — surface as data, never crash a caller
        return {**empty, "error": str(e)}
