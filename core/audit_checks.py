"""Safe active checks for Client-Safe Pentest Workbench.

Checks are deliberately small, client-safe, and testable offline. Any operation
that might touch a target is gated by ROE/scope/action policy first and uses an
injected fetcher; no check performs network I/O by itself.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from core.audit_scope import normalize_roe, roe_allows_action


SAFE_CHECKS = (
    "headers_check",
    "cookie_flags_check",
    "source_map_detection",
    "non_destructive_endpoint_probe",
)


def _blocked(action: str, target: str, roe: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    decision = roe_allows_action(action, target, roe)
    if not decision["allowed"]:
        return {
            "action": action,
            "target": target,
            "allowed": False,
            "findings": [],
            "reason": decision.get("reason", ""),
        }
    return None


def headers_check(target: str, roe: Dict[str, Any], *, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    blocked = _blocked("headers_check", target, roe)
    if blocked:
        return blocked
    if not evidence or "headers" not in evidence:
        return {
            "action": "headers_check",
            "target": target,
            "allowed": True,
            "findings": [],
            "reason": "headers evidence is required",
        }
    headers = {str(k).lower(): str(v) for k, v in evidence.get("headers", {}).items()}
    findings = []
    if "strict-transport-security" not in headers:
        findings.append({
            "category": "header",
            "rule_id": "missing-hsts",
            "title": "Missing Strict-Transport-Security header",
            "severity": "medium",
            "location": target,
            "evidence": {
                "location": target,
                "impact": "Transport downgrade risk.",
                "remediation": "Set Strict-Transport-Security on HTTPS responses.",
                "reachability": "response headers were available",
                "evidence_refs": [f"headers:{target}"],
                "confidence": 80,
            },
        })
    return {"action": "headers_check", "target": target, "allowed": True, "findings": findings}


def cookie_flags_check(target: str, roe: Dict[str, Any], *, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    blocked = _blocked("cookie_flags_check", target, roe)
    if blocked:
        return blocked
    findings = []
    for cookie in (evidence or {}).get("cookies", []) or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "cookie")
        missing = []
        if not cookie.get("secure"):
            missing.append("Secure")
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
        if missing:
            findings.append({
                "category": "cookie",
                "rule_id": "cookie-missing-flags",
                "title": f"Cookie {name} missing {'/'.join(missing)}",
                "severity": "medium",
                "location": target,
                "evidence": {
                    "location": target,
                    "impact": "Cookie exposure risk.",
                    "remediation": "Set Secure and HttpOnly where applicable.",
                    "reachability": "set-cookie header was available",
                    "evidence_refs": [f"cookie:{name}"],
                    "confidence": 80,
                },
            })
    return {"action": "cookie_flags_check", "target": target, "allowed": True, "findings": findings}


def source_map_detection(target: str, roe: Dict[str, Any], *, evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    blocked = _blocked("source_map_detection", target, roe)
    if blocked:
        return blocked
    urls = [str(url) for url in (evidence or {}).get("urls", [])]
    findings = [
        {
            "category": "sourcemap",
            "rule_id": "source-map-exposed",
            "title": "Exposed JavaScript source map",
            "severity": "medium",
            "location": url,
            "evidence": {
                "location": url,
                "impact": "Source disclosure can expose implementation details.",
                "remediation": "Remove source maps from production.",
                "reachability": "source map URL was observed",
                "evidence_refs": [f"sourcemap:{url}"],
                "confidence": 85,
            },
        }
        for url in urls
        if url.lower().endswith(".map")
    ]
    return {"action": "source_map_detection", "target": target, "allowed": True, "findings": findings}


def non_destructive_endpoint_probe(
    target: str,
    roe: Dict[str, Any],
    *,
    fetcher: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    blocked = _blocked("non_destructive_endpoint_probe", target, roe)
    if blocked:
        return blocked
    if fetcher is None:
        return {
            "action": "non_destructive_endpoint_probe",
            "target": target,
            "allowed": True,
            "findings": [],
            "reason": "fetcher is required",
        }
    response = fetcher(target)
    status = int(response.get("status", 0))
    return {
        "action": "non_destructive_endpoint_probe",
        "target": target,
        "allowed": True,
        "findings": [],
        "evidence": {"status": status},
    }


def run_safe_checks(
    target: str,
    roe: Optional[Dict[str, Any]],
    *,
    checks: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Dict[str, Any]]] = None,
    fetcher: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    normalized = normalize_roe(roe)
    selected = checks or list(SAFE_CHECKS)
    evidence = evidence or {}
    results = []
    for check in selected:
        if check not in SAFE_CHECKS:
            results.append({
                "action": check,
                "target": target,
                "allowed": False,
                "findings": [],
                "reason": "unknown safe check",
            })
            continue
        if check == "headers_check":
            results.append(headers_check(target, normalized, evidence=evidence.get(check)))
        elif check == "cookie_flags_check":
            results.append(cookie_flags_check(target, normalized, evidence=evidence.get(check)))
        elif check == "source_map_detection":
            results.append(source_map_detection(target, normalized, evidence=evidence.get(check)))
        elif check == "non_destructive_endpoint_probe":
            results.append(non_destructive_endpoint_probe(target, normalized, fetcher=fetcher))
    findings = [finding for result in results for finding in result.get("findings", [])]
    return {"target": target, "results": results, "findings": findings}
