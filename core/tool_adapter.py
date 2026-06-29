"""core/tool_adapter.py
Tool Adapter Contract — Mission Center M3.

A pure, offline, deterministic contract for plugging external recon/audit tools
(nuclei, nmap, katana, httpx, ...) into a pentest mission *without* running them,
opening sockets, or touching any store.

The adapter only does four things:

* describe a tool as a :class:`ToolCapability` (canonical name + the client-safe
  action class it maps onto for policy — it never invents a new action
  vocabulary, it reuses ``core.action_policy``);
* build a :class:`ToolRunRequest` bound to a mission's id / project / target /
  profile / ROE so a runner later has everything it needs (in this codebase the
  mission's **ROE is the scope SSOT** — it carries ``allowed_domains`` /
  ``active_scan_enabled`` / ``passive_only`` / ``forbidden_paths``);
* answer whether a tool is allowed for a mission, by *reusing* the existing
  policy stack (``core.scope_policy`` → ``core.action_policy`` + ``core.scope_guard``);
  no policy logic lives here;
* normalize already-parsed tool output into :class:`ToolFinding` /
  :class:`ToolAsset` DTOs, leaving persistence to the caller.

It contains no exploit/bruteforce/stealth/payload behaviour, performs no network
I/O, writes to no store, and changes no risk verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from core.scope_policy import evaluate_scope_policy

SEVERITIES = ("critical", "high", "medium", "low", "info")

RESULT_STATUSES = {"completed", "failed", "blocked", "skipped"}


@dataclass(frozen=True)
class ToolCapability:
    """What a tool does, expressed in terms the policy layer understands.

    ``action`` is the client-safe action class the tool maps onto (see
    ``core.action_policy.CLIENT_SAFE_ALLOWED``)."""

    name: str
    action: str
    passive: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "action": self.action,
            "passive": self.passive,
            "description": self.description,
        }


# Canonical registry of supported tools. Every action here is a client-safe
# action class; destructive tools are intentionally absent — the contract still
# blocks them by action class if one is passed explicitly.
TOOL_CAPABILITIES: Dict[str, ToolCapability] = {
    "header_audit": ToolCapability(
        "header_audit", "headers_check", True, "Security response header audit"
    ),
    "cookie_audit": ToolCapability(
        "cookie_audit", "cookie_flags_check", True, "Cookie flag audit"
    ),
    "tls_audit": ToolCapability(
        "tls_audit", "tls_config_check", True, "TLS configuration audit"
    ),
    "source_map_finder": ToolCapability(
        "source_map_finder", "source_map_detection", True, "Exposed source map detection"
    ),
    "graphql_introspector": ToolCapability(
        "graphql_introspector",
        "graphql_introspection_detection",
        False,
        "GraphQL introspection exposure check",
    ),
    "dependency_auditor": ToolCapability(
        "dependency_auditor",
        "dependency_cve_correlation",
        True,
        "JS dependency CVE correlation",
    ),
    "safe_active_prober": ToolCapability(
        "safe_active_prober", "safe_active_probe", False, "Non-destructive active probe"
    ),
    "iac_config_auditor": ToolCapability(
        "iac_config_auditor", "iac_local_config_check", True, "Local IaC config audit"
    ),
}


@dataclass(frozen=True)
class ToolRunRequest:
    """Everything a runner needs to (later) execute a tool against a mission.

    ``roe`` is the mission's Rules of Engagement — the scope SSOT in this
    codebase (it embeds allowed_domains / active_scan_enabled / passive_only /
    forbidden_paths)."""

    tool: str
    action: str
    mission_id: str
    project: str
    target: str
    profile: str
    roe: Dict[str, Any]
    passive: bool
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "mission_id": self.mission_id,
            "project": self.project,
            "target": self.target,
            "profile": self.profile,
            "roe": _canonical(self.roe),
            "passive": self.passive,
            "params": _canonical(self.params),
        }


@dataclass(frozen=True)
class ToolFinding:
    """Normalized finding DTO. Mirrors safe finding fields without duplicating
    FindingsStore — persistence is the caller's job."""

    title: str
    severity: str
    asset: str
    location: str
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "asset": self.asset,
            "location": self.location,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class ToolAsset:
    """Normalized asset DTO discovered by a tool."""

    value: str
    asset_type: str
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "asset_type": self.asset_type,
            "source": self.source,
        }


@dataclass(frozen=True)
class ToolRunResult:
    """Normalized, store-free result of one tool run."""

    tool: str
    action: str
    mission_id: str
    target: str
    status: str
    findings: List[ToolFinding] = field(default_factory=list)
    assets: List[ToolAsset] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "mission_id": self.mission_id,
            "target": self.target,
            "status": self.status,
            "findings": [item.to_dict() for item in self.findings],
            "assets": [item.to_dict() for item in self.assets],
            "evidence_refs": list(self.evidence_refs),
        }


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def normalize_tool_name(tool: str) -> str:
    """Canonical tool name (lower, trimmed). Empty input is rejected."""
    name = str(tool or "").strip().lower()
    if not name:
        raise ValueError("tool name is required")
    return name


def resolve_tool_capability(tool: Union[str, ToolCapability]) -> ToolCapability:
    """Resolve a registered tool name (or pass a capability through).

    Unknown or empty tools are rejected so the rest of the contract can assume a
    valid action class."""
    if isinstance(tool, ToolCapability):
        return tool
    name = normalize_tool_name(tool)
    capability = TOOL_CAPABILITIES.get(name)
    if capability is None:
        raise ValueError(f"unknown tool: {name}")
    return capability


def _target_from_mission(mission: Dict[str, Any], target: Optional[str]) -> str:
    """The run target: an explicit one wins, else the first ROE allowed domain.

    Missions in this codebase carry no single ``target`` field — the ROE's
    ``allowed_domains`` is the authorized surface, so the first entry is the
    natural default."""
    explicit = str(target or "").strip()
    if explicit:
        return explicit
    roe = mission.get("roe") if isinstance(mission, dict) else {}
    domains = (roe or {}).get("allowed_domains") or []
    host = str(domains[0] or "").strip() if domains else ""
    if not host:
        return ""
    return host if host.startswith(("http://", "https://")) else f"https://{host}"


def build_tool_request(
    mission: Dict[str, Any],
    tool: Union[str, ToolCapability],
    *,
    target: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
) -> ToolRunRequest:
    """Build a deterministic run request bound to a mission's identity / ROE."""
    if not isinstance(mission, dict):
        raise TypeError("mission must be a mission payload dict")
    capability = resolve_tool_capability(tool)
    clean_target = _target_from_mission(mission, target)
    if not clean_target:
        raise ValueError("target is required")
    mission_id = str(mission.get("mission_id") or "").strip()
    project = str(mission.get("project") or "").strip()
    if not mission_id:
        raise ValueError("mission_id is required")
    if not project:
        raise ValueError("project is required")
    return ToolRunRequest(
        tool=capability.name,
        action=capability.action,
        mission_id=mission_id,
        project=project,
        target=clean_target,
        profile=str(mission.get("profile") or "client_safe"),
        roe=_canonical(mission.get("roe") or {}),
        passive=capability.passive,
        params=_canonical(params or {}),
    )


def evaluate_tool_allowed_for_mission(
    mission: Dict[str, Any],
    tool: Union[str, ToolCapability],
    *,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """Whether a tool may run for a mission.

    Adds no policy of its own: it maps the tool to its action class and defers to
    the existing ``evaluate_scope_policy`` (which reuses ``action_policy`` and
    ``scope_guard``), passing the mission's ROE as the scope."""
    capability = resolve_tool_capability(tool)
    clean_target = _target_from_mission(mission or {}, target)
    decision = evaluate_scope_policy(
        capability.action,
        clean_target,
        mission.get("roe") if isinstance(mission, dict) else None,
        profile=str((mission or {}).get("profile") or "client_safe"),
    )
    result = decision.as_dict()
    result["tool"] = capability.name
    result["passive"] = capability.passive
    return result


def _normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in SEVERITIES else "info"


def _normalize_refs(values: Any) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    if isinstance(values, str):
        values = [values]
    for raw in values or []:
        ref = str(raw or "").strip()
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)
    out.sort()
    return out


def _to_finding(raw: Dict[str, Any]) -> ToolFinding:
    return ToolFinding(
        title=str(raw.get("title") or "").strip(),
        severity=_normalize_severity(raw.get("severity")),
        asset=str(raw.get("asset") or "").strip(),
        location=str(raw.get("location") or "").strip(),
        evidence_refs=_normalize_refs(raw.get("evidence_refs")),
    )


def _to_asset(raw: Dict[str, Any]) -> ToolAsset:
    return ToolAsset(
        value=str(raw.get("value") or "").strip(),
        asset_type=str(raw.get("asset_type") or raw.get("type") or "unknown").strip()
        or "unknown",
        source=str(raw.get("source") or "").strip(),
    )


def map_tool_result_to_findings(
    request: ToolRunRequest,
    parser_output: Dict[str, Any],
    *,
    status: str = "completed",
) -> ToolRunResult:
    """Normalize already-parsed tool output into store-free DTOs.

    ``parser_output`` is plain data (``{"findings": [...], "assets": [...],
    "evidence_refs": [...]}``) produced by some offline parser — this function
    never executes a tool and never writes to a store."""
    if not isinstance(request, ToolRunRequest):
        raise TypeError("request must be a ToolRunRequest")
    clean_status = str(status or "").strip().lower()
    if clean_status not in RESULT_STATUSES:
        raise ValueError(f"invalid tool run status: {clean_status}")
    data = parser_output if isinstance(parser_output, dict) else {}

    findings = [
        _to_finding(item)
        for item in data.get("findings") or []
        if isinstance(item, dict)
    ]
    findings.sort(key=lambda f: (f.severity, f.title, f.asset, f.location))

    assets = [
        _to_asset(item) for item in data.get("assets") or [] if isinstance(item, dict)
    ]
    deduped: List[ToolAsset] = []
    seen_assets: set[tuple] = set()
    for asset in sorted(assets, key=lambda a: (a.asset_type, a.value, a.source)):
        key = (asset.asset_type, asset.value, asset.source)
        if key not in seen_assets:
            seen_assets.add(key)
            deduped.append(asset)

    return ToolRunResult(
        tool=request.tool,
        action=request.action,
        mission_id=request.mission_id,
        target=request.target,
        status=clean_status,
        findings=findings,
        assets=deduped,
        evidence_refs=_normalize_refs(data.get("evidence_refs")),
    )


def tool_result_to_json(result: ToolRunResult) -> Dict[str, Any]:
    """Canonical, schema-shaped JSON export of a tool run result."""
    if not isinstance(result, ToolRunResult):
        raise TypeError("result must be a ToolRunResult")
    if result.status not in RESULT_STATUSES:
        raise ValueError(f"invalid tool run status: {result.status}")
    if not result.tool:
        raise ValueError("tool is required")
    if not result.mission_id:
        raise ValueError("mission_id is required")
    return _canonical(result.to_dict())
