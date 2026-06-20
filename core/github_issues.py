"""core/github_issues.py
GitHub Issues integration (EPIC 16 wave 2, B2) — push active findings to a repo's
issue tracker so they can be triaged / closed in GitHub.

Design / invariants (mirrors ``core/alerts.py``):
  * Strictly opt-in and offline-first. Nothing egresses unless a ``github`` config
    with ``enabled: True`` plus token/owner/repo is supplied.
  * I1 (no new deps): the GitHub REST v3 call goes over ``urllib`` (stdlib).
  * I5 (network split from logic): ``_api_request`` is module-level so tests stub
    it and never touch the network; everything else is pure.
  * Reuse SSOTs: issue bodies are rendered from ``finding_knowledge`` (the same
    description/impact/remediation enrichment as the SARIF / CSV exports).
  * Create-only and idempotent: each finding maps to exactly one open issue via an
    ``ISSUE_CREATED`` event in the existing ``finding_events`` table (no new table,
    no schema bump). Re-running never duplicates; a fixed-then-reappeared finding
    (a fresh REOPENED episode) is eligible for a new issue. Auto-closing a tracked
    issue when its finding is FIXED is intentionally deferred.

Config shape (lives in settings.json under "github", so the token stays out of the
per-project metadata files)::

    {
      "enabled": true,
      "token": "ghp_...",
      "owner": "my-org",
      "repo": "my-repo",
      "min_severity": "high",          # high | medium | low | info | critical
      "labels": ["site-analyzer"]      # base labels; the severity is added too
    }
"""

import json
import urllib.request
from typing import Dict, List, Optional

# Severity scale (highest first) shared with the rest of the platform; used to
# apply the min-severity gate so the tracker is not flooded with info findings.
_SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

_API_ROOT = 'https://api.github.com'


# ── transport (module-level so tests stub it; no network in unit tests) ───────

def _api_request(method: str, url: str, token: str,
                 data: Optional[Dict] = None, timeout: float = 15.0) -> tuple:
    """Perform a GitHub REST v3 request; return ``(status_code, parsed_json)``.

    Raises on transport error (the caller turns that into a per-finding error).
    ``data`` (when given) is JSON-encoded as the request body."""
    body = json.dumps(data).encode('utf-8') if data is not None else None
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'AdvancedSiteAnalyzer',
        'Content-Type': 'application/json',
    }
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — explicit https GitHub API
        status = getattr(resp, 'status', resp.getcode())
        raw = resp.read().decode('utf-8') or '{}'
    try:
        return status, json.loads(raw)
    except (ValueError, TypeError):
        return status, {}


# ── pure: render an issue from a finding ──────────────────────────────────────

def issue_title(finding: Dict) -> str:
    """One-line issue title: ``[severity] title``."""
    sev = str(finding.get('severity') or 'info').strip()
    title = str(finding.get('title') or finding.get('rule_id') or 'Finding').strip()
    return f'[{sev}] {title}'


def issue_body(finding: Dict) -> str:
    """Markdown issue body from a finding (description/impact/remediation pulled
    from the finding_knowledge catalog — same enrichment as the SARIF/CSV export).
    Pure; safe on a finding that lacks catalog text (sections are omitted)."""
    from core.finding_knowledge import describe
    info = describe(finding.get('category', ''), finding.get('rule_id', ''),
                    finding.get('title', ''), finding.get('evidence'))
    ev = finding.get('evidence') if isinstance(finding.get('evidence'), dict) else {}
    location = str(ev.get('location') or '').strip()

    lines: List[str] = []
    meta = [f"**Severity:** {finding.get('severity') or 'info'}"]
    if finding.get('category'):
        meta.append(f"**Category:** {finding['category']}")
    if location:
        meta.append(f"**Location:** {location}")
    if finding.get('first_seen_at'):
        meta.append(f"**First seen:** {finding['first_seen_at']}")
    lines.append(' · '.join(meta))

    for label, key in (('Description', 'description'), ('Impact', 'impact'),
                       ('Remediation', 'remediation')):
        text = str(info.get(key) or '').strip()
        if text:
            lines.append(f'\n### {label}\n{text}')

    fid = finding.get('id')
    if fid:
        lines.append(f'\n---\n`finding:{fid}` · opened by Advanced Site Analyzer')
    return '\n'.join(lines)


def issue_labels(finding: Dict, base: Optional[List[str]] = None) -> List[str]:
    """Issue labels: the configured base labels plus the finding's severity
    (de-duplicated, order preserved)."""
    out = list(base if base is not None else ['site-analyzer'])
    sev = str(finding.get('severity') or '').strip()
    if sev:
        out.append(sev)
    return list(dict.fromkeys(s for s in out if s))


def _meets_min(severity: str, min_severity: str) -> bool:
    return _SEVERITY_RANK.get(str(severity or 'info').lower(), 0) >= \
        _SEVERITY_RANK.get(str(min_severity or 'high').lower(), 3)


# ── client ────────────────────────────────────────────────────────────────────

class GitHubIssueClient:
    """Thin GitHub Issues client (create only) over the module-level transport."""

    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo

    def create_issue(self, title: str, body: str,
                     labels: Optional[List[str]] = None) -> Dict:
        """Create an issue; return ``{number, url}``. Raises on a non-2xx status or
        transport error (the caller records the failure and leaves the finding
        untracked, so it is retried next run)."""
        url = f'{_API_ROOT}/repos/{self.owner}/{self.repo}/issues'
        payload: Dict = {'title': title, 'body': body}
        if labels:
            payload['labels'] = labels
        status, data = _api_request('POST', url, self.token, data=payload)
        if not (200 <= status < 300):
            raise RuntimeError(f'GitHub API returned http {status}: '
                               f'{data.get("message", "")}'.strip())
        return {'number': data.get('number'), 'url': data.get('html_url', '')}


def build_client(config: Optional[Dict]) -> Optional[GitHubIssueClient]:
    """Construct a client when the config is enabled and complete, else None."""
    cfg = config or {}
    if not cfg.get('enabled'):
        return None
    token, owner, repo = cfg.get('token'), cfg.get('owner'), cfg.get('repo')
    if token and owner and repo:
        return GitHubIssueClient(token, owner, repo)
    return None


# ── orchestration ─────────────────────────────────────────────────────────────

def sync_findings(store, project: str, config: Optional[Dict], *,
                  client: Optional[GitHubIssueClient] = None,
                  scan_id: Optional[str] = None) -> Dict:
    """Open a GitHub issue for each not-yet-tracked active finding at/above the
    configured ``min_severity`` (default ``high``); idempotent.

    Pure of the network *decision* (which findings to push) — the only egress is the
    injected/constructed ``client``. ``store`` is injected so tests use a temp DB.
    Returns ``{enabled, created, skipped, errors, total, reason?}``: a finding that
    already has a current issue is counted in ``skipped``; an API failure is recorded
    in ``errors`` and the finding stays untracked (retried next run)."""
    if not config or not config.get('enabled'):
        return {'enabled': False, 'created': [], 'skipped': 0, 'errors': [],
                'total': 0, 'reason': 'disabled'}
    client = client or build_client(config)
    if client is None:
        return {'enabled': True, 'created': [], 'skipped': 0, 'errors': [],
                'total': 0, 'reason': 'not configured'}

    min_sev = config.get('min_severity', 'high')
    base_labels = config.get('labels')
    eligible = [f for f in store.active_findings(project)
                if _meets_min(f.get('severity', ''), min_sev)]
    by_id = {f['id']: f for f in eligible if f.get('id')}
    pending = store.untracked_for_issue(project, list(by_id))
    skipped = len(by_id) - len(pending)

    created: List[Dict] = []
    errors: List[Dict] = []
    for fid in pending:
        finding = by_id.get(fid)
        if finding is None:
            continue
        try:
            issue = client.create_issue(
                issue_title(finding), issue_body(finding),
                issue_labels(finding, base_labels))
        except Exception as e:   # noqa: BLE001 — one failure must not block the rest
            errors.append({'id': fid, 'error': str(e)})
            continue
        store.record_issue(project, fid, issue.get('number'),
                           issue.get('url', ''), scan_id=scan_id)
        created.append({'id': fid, 'number': issue.get('number'),
                        'url': issue.get('url', ''), 'title': issue_title(finding)})

    return {'enabled': True, 'created': created, 'skipped': skipped,
            'errors': errors, 'total': len(by_id)}
