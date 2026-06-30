"""core/tool_ingest.py
Bridge: a tool run's result → the platform's canonical Finding / Asset DTOs.

The next safe layer above the tool pipeline. It is a **pure converter**: a
:class:`~core.tool_adapter.ToolRunResult` (already gated, parsed and normalized)
is mapped onto the platform's identity-bearing :class:`core.findings_adapter.Finding`
and :class:`core.asset_adapter.Asset` DTOs, **reusing** those adapters so tool
findings get the same canonical identity (fingerprint), category and severity
normalization as any scanner finding.

It writes to **no store** — persistence stays an explicit, separate step the
caller performs later. No network, no new dependencies, deterministic.
"""

from __future__ import annotations

from typing import List

from core.asset_adapter import Asset
from core.findings_adapter import Finding, from_raw
from core.tool_adapter import ToolRunResult

# Map a tool's client-safe action class onto the platform's finding category, so
# the canonical identity is meaningful. An unmapped action falls through to
# findings_adapter's own derivation (default ``vuln``).
_ACTION_CATEGORY = {
    "headers_check": "header",
    "cookie_flags_check": "cookie",
    "source_map_detection": "sourcemap",
    "tls_config_check": "tls",
    "graphql_introspection_detection": "graphql",
    "dependency_cve_correlation": "vuln",
    "iac_local_config_check": "iac",
}


def tool_result_to_findings(result: ToolRunResult) -> List[Finding]:
    """Map a result's findings onto canonical :class:`Finding` DTOs (pure).

    Reuses ``findings_adapter.from_raw`` so each tool finding gets the same
    fingerprint identity / category / severity normalization as a scanner
    finding. The tool's string evidence refs are carried in ``detail`` (they are
    not manifest artifacts, so they do not populate ``Finding.evidence_refs``).
    Writes to no store.
    """
    if not isinstance(result, ToolRunResult):
        raise TypeError("result must be a ToolRunResult")
    category = _ACTION_CATEGORY.get(result.action)
    findings: List[Finding] = []
    for tf in result.findings:
        raw = {
            "title": tf.title,
            "severity": tf.severity,
            "location": tf.location,
            "source": result.tool,
        }
        if category:
            raw["category"] = category
        refs = ", ".join(ref for ref in (tf.evidence_refs or []) if ref)
        if refs:
            raw["detail"] = f"evidence: {refs}"
        findings.append(from_raw(raw))
    return findings


def tool_result_to_assets(result: ToolRunResult) -> List[Asset]:
    """Map a result's assets onto canonical :class:`Asset` DTOs (pure).

    The discovering tool is recorded in ``attrs['source']``. Writes to no store.
    """
    if not isinstance(result, ToolRunResult):
        raise TypeError("result must be a ToolRunResult")
    assets: List[Asset] = []
    for ta in result.assets:
        value = str(ta.value or "").strip()
        if not value:
            continue
        attrs = {"source": ta.source} if ta.source else {}
        assets.append(Asset(
            type=str(ta.asset_type or "unknown").strip() or "unknown",
            value=value,
            attrs=attrs,
        ))
    return assets
