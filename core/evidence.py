"""Scan evidence manifest helpers.

Evidence Manifest v1 is a scan-local inventory of files produced by collection
phases. It is pure/stdlib-only and intentionally derives from the scan directory
instead of asking phases to register artifacts one by one.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from utils.atomic_io import atomic_write_json

MANIFEST_NAME = "evidence_manifest.json"
_REPORT_FILES = {"report.json", "report.html", MANIFEST_NAME}
_SOURCE_ARTIFACTS = {
    "secret": ("api/api_keys.json",),
    "secret-audit": ("security/audit.json",),
    "security-audit": ("security/audit.json",),
    "dns": ("dns/dns.json",),
    "subdomain-active": ("subdomains/subdomains.json",),
    "dependency-audit": ("recon/recon.json",),
    "nuclei": ("security/vulns.json", "recon/osv.json"),
    "osv": ("recon/osv.json", "security/vulns.json"),
}
_CATEGORY_ARTIFACTS = {
    "cookie": ("security/cookies.json", "security/vulns.json"),
    "dependency": ("recon/recon.json", "security/vulns.json"),
    "graphql": ("security/audit.json",),
    "header": ("recon/recon.json", "security/vulns.json"),
    "sourcemap": ("security/audit.json",),
    "tech": ("recon/recon.json",),
    "transport": ("recon/recon.json", "security/vulns.json"),
}
_TITLE_ARTIFACTS = (
    ("cookie", ("security/cookies.json", "security/vulns.json")),
    ("content-security-policy", ("recon/recon.json", "security/vulns.json")),
    ("csp", ("recon/recon.json", "security/vulns.json")),
    ("hsts", ("recon/recon.json", "security/vulns.json")),
    ("referrer-policy", ("recon/recon.json", "security/vulns.json")),
    ("x-frame-options", ("recon/recon.json", "security/vulns.json")),
    ("security header", ("recon/recon.json", "security/vulns.json")),
    ("plain http", ("recon/recon.json", "security/vulns.json")),
    ("cms/stack", ("recon/recon.json",)),
    ("framework", ("recon/recon.json",)),
)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _phase_for(rel_path: str) -> str:
    first = rel_path.split("/", 1)[0]
    if first in _REPORT_FILES:
        return "report"
    return first or "unknown"


def _kind_for(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return suffix or "file"


def iter_artifact_files(scan_dir: Path) -> Iterable[Path]:
    """Yield scan artifact files, excluding generated reports/manifest."""
    root = Path(scan_dir)
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = _rel(path, root)
        if rel in _REPORT_FILES:
            continue
        yield path


def build_manifest(scan_dir: Path, report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build an evidence manifest without writing it."""
    root = Path(scan_dir)
    artifacts = []
    for path in iter_artifact_files(root):
        rel = _rel(path, root)
        stat = path.stat()
        artifact_id = f"sha256:{sha256_file(path)}"
        artifacts.append({
            "id": artifact_id,
            "phase": _phase_for(rel),
            "path": rel,
            "kind": _kind_for(path),
            "size": stat.st_size,
            "sha256": artifact_id.split(":", 1)[1],
            "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
        })
    return {
        "version": 1,
        "scan_id": (report or {}).get("scan_id") or root.name,
        "url": (report or {}).get("url"),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def artifact_index(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(a.get("path")): a for a in manifest.get("artifacts", [])
        if isinstance(a, dict) and a.get("path")
    }


def write_manifest(scan_dir: Path, report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build and persist ``evidence_manifest.json``; return summary + manifest."""
    root = Path(scan_dir)
    manifest = build_manifest(root, report)
    path = root / MANIFEST_NAME
    atomic_write_json(path, manifest)
    return {
        "manifest": manifest,
        "path": MANIFEST_NAME,
        "sha256": sha256_file(path),
        "artifact_count": manifest["artifact_count"],
    }


def verify_manifest(scan_dir: Path,
                    manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify that manifest artifacts still exist and match their hashes."""
    root = Path(scan_dir)
    if manifest is None:
        try:
            manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "checked": 0, "missing": [], "changed": [],
                    "error": str(exc)}
    missing: list[str] = []
    changed: list[str] = []
    checked = 0
    for artifact in manifest.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        rel = str(artifact.get("path") or "")
        if not rel:
            continue
        path = root / rel
        if not path.is_file():
            missing.append(rel)
            continue
        checked += 1
        if sha256_file(path) != artifact.get("sha256"):
            changed.append(rel)
    return {
        "ok": not missing and not changed,
        "checked": checked,
        "missing": missing,
        "changed": changed,
    }


def audit_scan(scan_dir: Path) -> Dict[str, Any]:
    """Read and verify a scan's evidence manifest.

    This is the stable, CLI-friendly integrity contract: no exceptions for normal
    missing/corrupt/changed evidence states, just a structured status.
    """
    root = Path(scan_dir)
    manifest_path = root / MANIFEST_NAME
    if not root.is_dir():
        return {
            "ok": False,
            "status": "missing_scan_dir",
            "scan_dir": str(root),
            "manifest": MANIFEST_NAME,
            "checked": 0,
            "missing": [],
            "changed": [],
            "error": "scan directory not found",
        }
    if not manifest_path.is_file():
        return {
            "ok": False,
            "status": "missing_manifest",
            "scan_dir": str(root),
            "manifest": MANIFEST_NAME,
            "checked": 0,
            "missing": [],
            "changed": [],
            "error": "evidence manifest not found",
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "status": "corrupt_manifest",
            "scan_dir": str(root),
            "manifest": MANIFEST_NAME,
            "checked": 0,
            "missing": [],
            "changed": [],
            "error": str(exc),
        }
    verified = verify_manifest(root, manifest)
    status = "ok" if verified.get("ok") else "failed"
    return {
        **verified,
        "status": status,
        "scan_dir": str(root),
        "manifest": MANIFEST_NAME,
        "artifact_count": manifest.get("artifact_count"),
        "scan_id": manifest.get("scan_id"),
        "url": manifest.get("url"),
    }


def integrity_warning(audit: Optional[Dict[str, Any]],
                      label: str = "scan") -> Optional[str]:
    """Human-readable non-blocking warning for an audit result.

    ``None`` means evidence is intact. The text intentionally summarizes only
    manifest status and artifact paths, never artifact contents.
    """
    if not isinstance(audit, dict):
        return f"{label}: evidence integrity unavailable"
    if audit.get("ok"):
        return None
    status = str(audit.get("status") or "failed")
    parts = [f"{label}: evidence integrity {status}"]
    missing = audit.get("missing") if isinstance(audit.get("missing"), list) else []
    changed = audit.get("changed") if isinstance(audit.get("changed"), list) else []
    if missing:
        parts.append(f"missing={len(missing)}")
    if changed:
        parts.append(f"changed={len(changed)}")
    error = audit.get("error")
    if error and not missing and not changed:
        parts.append(str(error))
    return parts[0] + (f" ({', '.join(parts[1:])})" if len(parts) > 1 else "")


def evidence_refs_for_finding(finding: Dict[str, Any],
                              manifest: Dict[str, Any]) -> list[Dict[str, str]]:
    """Map a raw finding to existing manifest artifacts by its source."""
    source = str(finding.get("source") or "").lower()
    category = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()
    index = artifact_index(manifest)
    refs = []
    paths: list[str] = []
    for group in (
        _SOURCE_ARTIFACTS.get(source, ()),
        _CATEGORY_ARTIFACTS.get(category, ()),
        next((v for k, v in _TITLE_ARTIFACTS if k in title), ()),
        ("security/vulns.json",) if source == "vuln" else (),
    ):
        for path in group:
            if path not in paths:
                paths.append(path)
    for path in paths:
        artifact = index.get(path)
        if artifact:
            refs.append({
                "artifact_id": str(artifact["id"]),
                "path": str(artifact["path"]),
                "phase": str(artifact["phase"]),
            })
    return refs


def attach_finding_refs(report: Dict[str, Any], manifest: Dict[str, Any]) -> int:
    """Attach evidence_refs to vuln findings where a source artifact exists."""
    vulns = report.get("phases", {}).get("vulns")
    if not isinstance(vulns, dict):
        return 0
    findings = vulns.get("findings")
    if not isinstance(findings, list):
        return 0
    attached = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        refs = evidence_refs_for_finding(finding, manifest)
        if refs:
            finding["evidence_refs"] = refs
            attached += 1
    return attached
