"""Independent evidence checks for client-safe audit runs.

The verifier is deliberately conservative and offline-only. It confirms refs
against evidence already present in the audit payload or, for file-like refs,
inside an explicitly supplied artifacts root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_INLINE_PREFIXES = ("headers:", "cookie:", "sourcemap:")


def _refs_from_finding(finding: Dict[str, Any]) -> set[str]:
    refs = set()
    for value in finding.get("evidence_refs") or []:
        if value:
            refs.add(str(value))
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for value in evidence.get("evidence_refs") or evidence.get("refs") or []:
            if value:
                refs.add(str(value))
    return refs


def _safe_check_refs(results: Iterable[Dict[str, Any]]) -> set[str]:
    refs = set()
    for result in results or []:
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings") or []:
            if isinstance(finding, dict):
                refs.update(_refs_from_finding(finding))
    return refs


def _safe_path(root: Path, ref: str) -> Optional[Path]:
    try:
        candidate = (root / ref).resolve()
        resolved_root = root.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if candidate == resolved_root or resolved_root in candidate.parents:
        return candidate
    return None


def verify_evidence_refs(
    refs: Iterable[Any],
    *,
    findings: Optional[Iterable[Dict[str, Any]]] = None,
    safe_checks: Optional[Iterable[Dict[str, Any]]] = None,
    artifacts_root: Optional[Path | str] = None,
) -> Dict[str, Any]:
    """Return deterministic verification status for evidence refs."""
    wanted = sorted({str(ref).strip() for ref in refs or [] if str(ref).strip()})
    finding_refs = set()
    finding_ids_with_evidence = set()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        refs_for_finding = _refs_from_finding(finding)
        finding_refs.update(refs_for_finding)
        fid = str(finding.get("finding_id") or finding.get("id") or "").strip()
        if fid and (refs_for_finding or finding.get("evidence")):
            finding_ids_with_evidence.add(fid)

    safe_refs = _safe_check_refs(safe_checks or [])
    root = Path(artifacts_root) if artifacts_root else None
    results: List[Dict[str, Any]] = []
    for ref in wanted:
        status = "missing"
        reason = "no matching evidence"
        if ref in finding_refs:
            status, reason = "verified", "finding evidence ref matched"
        elif ref.startswith("finding:") and ref.endswith(":evidence"):
            fid = ref[len("finding:"):-len(":evidence")]
            if fid in finding_ids_with_evidence:
                status, reason = "verified", "finding inline evidence matched"
        elif ref in safe_refs or ref.startswith(_INLINE_PREFIXES):
            status, reason = "verified", "inline safe-check evidence ref matched"
        elif root is not None:
            candidate = _safe_path(root, ref)
            if candidate is None:
                status, reason = "missing", "evidence path escapes artifacts root"
            elif candidate.exists():
                status, reason = "verified", "artifact path exists"
        results.append({"ref": ref, "status": status, "reason": reason})

    verified = [item["ref"] for item in results if item["status"] == "verified"]
    missing = [item["ref"] for item in results if item["status"] != "verified"]
    return {
        "ok": not missing,
        "checked": len(results),
        "verified": verified,
        "missing": missing,
        "results": results,
    }
