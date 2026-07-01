"""
remote/web_app.py
Local Wi-Fi management console for Advanced Site Analyzer.
Exposes http://0.0.0.0:5000 — accessible from any device on the LAN.

Requires:  pip install fastapi uvicorn[standard]
Run alone: python remote/web_app.py
"""

import asyncio
import json
import hmac
import os
import secrets
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import uvicorn
    from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import (
        FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse,
    )
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False

from core import alerts, monitor
from core.api_key_extractor import ApiKeyExtractor
from core.collection_runner import CollectionRunner
from core.config import DEFAULT_SETTINGS, OPERATIONS_DB, REGISTRY_DB, load_settings
from core.content_capture import SiteContentCapture
from core.cookie_auditor import CookieAuditor
from core.findings_store import STATUSES, FindingsStore
from core.design_analyzer import DesignAnalyzer
from core.frontend_cloner import FrontendCloner
from core.paywall_bypass import PaywallBypass
from core.project import ProjectStore, project_slug
from core.recon_engine import ReconEngine
from core.scan_diff import write_diff_report
from core.security_auditor import SecurityAuditor
from core.subdomain_scanner import SubdomainScanner
from utils.data_viewer import DataViewer
from utils.operation_registry import OperationRegistry

def _configured_report_base() -> Path:
    """Reports/output base from settings.json (fallback preserves legacy default)."""
    fallback = DEFAULT_SETTINGS.get('output_dir') or str(Path.home() / 'SiteAnalyzer')
    return Path(load_settings().get('output_dir') or fallback).expanduser().resolve()


# Reports/output live under here; report serving is restricted to this tree.
_REPORT_BASE = _configured_report_base()

# Active web-console auth token. Empty = no token required (loopback single-user
# default). ``start_server`` sets it from settings.json / ASA_WEB_TOKEN, and
# force-generates one for a LAN bind. Tests set it directly.
_AUTH_TOKEN = ''
# Paths served without a token even when one is set: just the static dashboard
# shell, so the browser can load the page and prompt for the token. No data here.
_PUBLIC_PATHS = {'/'}
_LOOPBACK_HOSTS = {'127.0.0.1', 'localhost', '::1', ''}


def _is_loopback(host: str) -> bool:
    return str(host or '').strip().lower() in _LOOPBACK_HOSTS


def _request_token(request) -> str:
    """Token from the ``Authorization: Bearer`` header, else the ``token`` query
    param (so a browser EventSource / link, which cannot set headers, still
    authenticates)."""
    auth = request.headers.get('authorization') or ''
    if auth[:7].lower() == 'bearer ':
        return auth[7:].strip()
    return str(request.query_params.get('token') or '')

# ── Global state ──────────────────────────────────────────────────────────────
# Bounds so a long-running console process can't grow unbounded: the SSE queue
# drops its oldest entry when full (newest logs win), and only the most recent
# job results are retained for the /results endpoint.
_LOG_QUEUE_MAX = 1000
_MAX_JOB_RESULTS = 200
_log_queue: asyncio.Queue = asyncio.Queue(maxsize=_LOG_QUEUE_MAX)
_job_results: Dict[str, dict] = {}
_active_job: Optional[str] = None
# The currently running job's cancellable engine, if it exposes ``cancel()``
# (e.g. a CollectionRunner). Long jobs register one so /cancel can stop them.
_active_cancellable: Optional[object] = None


def _record_job_result(job_id: str, result: dict) -> None:
    """Store a job result, evicting the oldest so ``_job_results`` stays bounded
    (FIFO; dicts preserve insertion order)."""
    _job_results[job_id] = result
    while len(_job_results) > _MAX_JOB_RESULTS:
        del _job_results[next(iter(_job_results))]


class _EventCanceller:
    """Adapts a ``threading.Event`` (cancel-signal style) to a ``cancel()`` call,
    so engines that take a cancel Event register uniformly alongside those that
    expose ``cancel()`` directly."""

    def __init__(self, event):
        self._event = event

    def cancel(self):
        self._event.set()


def _register_cancellable(obj) -> None:
    """A running job registers its cancellable engine here (best-effort)."""
    global _active_cancellable
    _active_cancellable = obj


def _request_cancel() -> dict:
    """Signal the active job to stop, if it registered a cancellable engine.

    Returns ``{status, job}`` when a cancel was signalled, or ``{error}``. The
    engine (e.g. CollectionRunner) polls the signal and stops at its next safe
    point — cooperative, never a hard kill. Pure over module state, so the
    endpoint stays a thin wrapper and this is unit-testable."""
    if not _active_job:
        return {'error': 'no job running'}
    obj = _active_cancellable
    if obj is None or not hasattr(obj, 'cancel'):
        return {'error': f'job {_active_job} is not cancellable'}
    obj.cancel()
    return {'status': 'cancelling', 'job': _active_job}


async def _push(msg: str, level: str = 'info', msg_type: str = 'log', data: Optional[dict] = None):
    payload: dict = {'type': msg_type, 'message': msg, 'level': level, 'ts': time.time()}
    if data:
        payload['data'] = data
    # Bound the queue: if no SSE consumer is draining it, drop the oldest entry
    # so memory stays capped (newest log wins) instead of blocking/growing.
    if _log_queue.full():
        try:
            _log_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
    try:
        _log_queue.put_nowait(payload)
    except asyncio.QueueFull:
        pass


# ── Job registry ──────────────────────────────────────────────────────────────
# One synchronous runner per GUI-equivalent feature. Each takes (url, push) and
# returns a result dict; ``push(msg, level)`` streams progress to the console.
# JOBS is the single source of truth for what the console can do (mirrors the
# GUI tabs) and is introspectable via the /jobs endpoint.

def _out_dir(url: str, suffix: str) -> Path:
    domain = urlparse(url if '://' in url else 'https://' + url).netloc.replace('www.', '') or 'site'
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return _REPORT_BASE / f'{domain}_{stamp}_{suffix}'


def _run_recon(url: str, push: Callable) -> dict:
    engine = ReconEngine()
    engine.configure()
    return engine.run_recon(url)


def _run_subdomain(url: str, push: Callable) -> dict:
    domain = urlparse(url if '://' in url else 'https://' + url).netloc or url
    scanner = SubdomainScanner()
    _register_cancellable(scanner)   # scanner.cancel() stops at next checkpoint
    return scanner.scan(
        domain,
        on_found=lambda e: push(f"found: {e['subdomain']}"),
        on_update=lambda e: push(
            f"{e['subdomain']} — {e.get('status', '')}",
            'wn' if e.get('takeover') else 'info'),
        passive=True, brute=True, active=True,
    )


def _run_apikeys(url: str, push: Callable) -> dict:
    ex = ApiKeyExtractor()
    ex.set_target_url(url)
    ex.set_profile('chrome_windows')
    return ex.run_extraction()


def _run_capture(url: str, push: Callable) -> dict:
    out = _out_dir(url, 'capture')
    cap = SiteContentCapture()
    cap.configure(url, str(out), max_pages=30)
    cap.set_progress_callback(lambda m: push(m))
    result = cap.run_capture()
    result['output_dir'] = str(out)
    return result


def _run_clone(url: str, push: Callable) -> dict:
    # The console only has a URL, so capture the site first, then clone the
    # captured pages into a self-contained offline copy (mirrors the GUI flow
    # of capture -> clone, and CollectionRunner's capture/clone phases).
    base = _out_dir(url, 'clone')
    capture_dir = base / 'capture'
    cap = SiteContentCapture()
    cap.configure(url, str(capture_dir), max_pages=20)
    cap.set_progress_callback(lambda m: push(m))
    cap_result = cap.run_capture()
    if cap_result.get('pages_captured', 0) == 0:
        return {'status': 'Error', 'error': 'no pages captured to clone',
                'output_dir': str(capture_dir)}

    clone_dir = base / 'clone'
    cloner = FrontendCloner()
    cloner.configure(str(capture_dir), str(clone_dir))
    cloner.set_progress_callback(lambda m: push(m))
    result = cloner.clone()
    result['output_dir'] = str(clone_dir)
    return result


def _run_paywall(url: str, push: Callable) -> dict:
    bypass = PaywallBypass()
    bypass.configure()
    result = bypass.extract(url)
    if result.get('status') == 'Success' and result.get('html'):
        out = _out_dir(url, 'bypass')
        out.parent.mkdir(parents=True, exist_ok=True)
        path = out.with_suffix('.html')
        path.write_text(result['html'], encoding='utf-8')
        result['saved_to'] = str(path)
    return result


def _run_cookies(url: str, push: Callable) -> dict:
    return CookieAuditor().audit(url)


def _run_security(url: str, push: Callable) -> dict:
    try:
        from core.registry import DataRegistry
        registry = DataRegistry()
    except Exception:
        registry = None
    auditor = SecurityAuditor(data_registry=registry)
    auditor.set_progress_callback(lambda m: push(m))
    # SecurityAuditor cancels via a threading.Event, so adapt it to cancel().
    cancel_event = threading.Event()
    auditor.set_cancel_event(cancel_event)
    _register_cancellable(_EventCanceller(cancel_event))
    return auditor.audit(url)


def _run_design(url: str, push: Callable) -> dict:
    out = _out_dir(url, 'design')
    cap = SiteContentCapture()
    cap.configure(url, str(out), max_pages=10)
    cap.set_progress_callback(lambda m: push(m))
    cap.run_capture()
    analyzer = DesignAnalyzer()
    analyzer.configure(str(out))
    analyzer.set_progress_callback(lambda m: push(m))
    return analyzer.analyze()


def _run_collection(url: str, push: Callable) -> dict:
    runner = CollectionRunner(max_pages=20)
    runner.set_progress_callback(lambda m: push(m))
    _register_cancellable(runner)   # runner.cancel() stops at next phase boundary
    res = runner.run(url, str(_REPORT_BASE))
    # Compact summary (full per-phase data is on disk in report.json).
    return {
        'status': res.get('status'),
        'project_dir': res.get('project_dir'),
        'report_html': res.get('report_html'),
        'warnings': res.get('warnings') or [],
        'phases': {k: v.get('status') for k, v in res.get('phases', {}).items()},
    }


def _run_scandiff(url: str, push: Callable) -> dict:
    """Diff the two most recent scans of the target's project (Scan Diff / P8).

    The job framework hands a single URL, so this defaults to the most useful
    comparison — previous scan vs latest — for that project. Needs at least two
    scans; otherwise it reports cleanly rather than failing."""
    store = ProjectStore(str(_REPORT_BASE))
    project = store.get(project_slug(url))
    if project is None:
        push('Проект не найден — сначала запустите Full Collection')
        return {'status': 'No project', 'url': url}
    ids = [s['id'] for s in project.scans() if s.get('id')]
    if len(ids) < 2:
        push(f'Недостаточно сканов для diff (есть {len(ids)}, нужно 2)')
        return {'status': 'Need >=2 scans', 'scans': len(ids)}
    push(f'Diff: {ids[-2]} → {ids[-1]}')
    out = write_diff_report(project, ids[-2], ids[-1])
    return {'status': 'Success', 'line': out['line'],
            'report_html': out['html_path']}


JOBS: Dict[str, dict] = {
    'recon':      {'label': 'Recon',           'fn': _run_recon},
    'subdomain':  {'label': 'Subdomains',      'fn': _run_subdomain},
    'apikeys':    {'label': 'API Keys',        'fn': _run_apikeys},
    'capture':    {'label': 'Capture',         'fn': _run_capture},
    'clone':      {'label': 'Clone Frontend',  'fn': _run_clone},
    'paywall':    {'label': 'Bypass Paywall',  'fn': _run_paywall},
    'cookies':    {'label': 'Cookie Audit',    'fn': _run_cookies},
    'security':   {'label': 'Security Audit',  'fn': _run_security},
    'design':     {'label': 'Design Lab',      'fn': _run_design},
    'collection': {'label': 'Full Collection', 'fn': _run_collection},
    'scandiff':   {'label': 'Scan Diff',       'fn': _run_scandiff},
}

_HEAVY_KEYS = ('html', 'reader_view', 'body', 'output')


def _strip_heavy(result) -> dict:
    """Drop large payloads before sending a result to the browser."""
    if not isinstance(result, dict):
        return {'result': result}
    out = {k: v for k, v in result.items() if k not in _HEAVY_KEYS}
    if isinstance(result.get('html'), str):
        out['html_size'] = len(result['html'])
    return out


def _safe_report_path(file: str) -> Optional[Path]:
    """Resolve a report path, but only inside the SiteAnalyzer tree.

    Guards against path traversal: returns the Path only if it stays under
    _REPORT_BASE, exists, and is an .html file; otherwise None.
    """
    if not file:
        return None
    try:
        candidate = (_REPORT_BASE / file).resolve() if not Path(file).is_absolute() \
            else Path(file).resolve()
    except Exception:
        return None
    try:
        candidate.relative_to(_REPORT_BASE)
    except ValueError:
        return None
    if candidate.is_file() and candidate.suffix.lower() == '.html':
        return candidate
    return None


def _recent_history(limit: int = 100) -> list:
    """Read-only recent operations from the operations registry."""
    try:
        return OperationRegistry(db_path=str(OPERATIONS_DB)).history(limit=limit)
    except Exception:
        return []


def _registry_data(limit: int = 50) -> dict:
    """Read-only DataRegistry summary + recent records for the console."""
    try:
        viewer = DataViewer(db_path=str(REGISTRY_DB))
        return {'summary': viewer.get_summary(),
                'records': viewer.get_recent_records(limit=limit)}
    except Exception as e:
        return {'summary': {}, 'records': [], 'error': str(e)}


# ── Findings Management (F1, T1.6) ──────────────────────────────────────────────
# Thin wrappers over core.findings_store (the same SQLite store the GUI tab and
# CollectionRunner use — single source of truth). Pure over the store so the
# endpoints stay thin and these are unit-testable without FastAPI.

def _findings_list(project: Optional[str] = None, status: Optional[str] = None,
                   severity: Optional[str] = None) -> dict:
    """Findings (optionally filtered) + the project list + a status summary."""
    try:
        from core import threat_intel
        from core.finding_knowledge import annotate as annotate_knowledge
        from core.findings_sla import annotate as annotate_sla
        store = FindingsStore()
        findings = store.list_findings(project=project, status=status,
                                       severity=severity)
        # KEV/EPSS threat block first (offline; cold cache = no-op), so the SLA
        # clock below is tightened for known-exploited findings — consistent with
        # the GUI/report.
        findings = threat_intel.annotate_offline(findings)
        # SLA clock is reopen-aware → pass the latest reopen date per finding.
        annotate_sla(findings, reopened=store.reopen_dates(project))
        annotate_knowledge(findings)  # + description/impact/remediation (F-O4)
        return {'projects': store.projects(),
                'findings': findings,
                'summary': store.summary(project)}
    except Exception as e:
        return {'projects': [], 'findings': [], 'summary': {}, 'error': str(e)}


def _findings_sarif(project: Optional[str] = None) -> str:
    """SARIF 2.1.0 of a project's active findings (EPIC 16 F1).

    Always returns a valid SARIF document so the endpoint can be uploaded straight
    to GitHub code scanning / a CI step; a store failure degrades to an empty run."""
    from core.config import APP_VERSION
    from core.report_export import findings_sarif
    try:
        findings = FindingsStore().active_findings(project)
    except Exception:  # noqa: BLE001 — degrade to an empty but valid SARIF run
        findings = []
    return findings_sarif(findings, tool_version=APP_VERSION)


def _report_markdown_view(project: Optional[str] = None) -> str:
    """Markdown deliverable of a project's latest scan (EPIC 16 F2).

    Report-based (resolves the project and loads its latest report.json); always
    returns valid Markdown (at least a header) so the endpoint never errors."""
    from core.report_export import report_markdown
    try:
        proj = ProjectStore(str(_REPORT_BASE)).get(project) if project else None
        report = None
        if proj is not None:
            latest = proj.latest_scan()
            sid = latest.get('id') if isinstance(latest, dict) else None
            report = proj.load_scan_report(sid) if sid else None
        return report_markdown(report if isinstance(report, dict) else {})
    except Exception:  # noqa: BLE001 — degrade to a minimal valid Markdown header
        return report_markdown({})


def _findings_set_status(finding_id: str, status: str,
                         note: Optional[str] = None) -> dict:
    """Change one finding's triage status (user-sourced). Returns the updated
    row, or an ``{'error': ...}`` for an unknown status / finding."""
    if status not in STATUSES:
        return {'error': f'unknown status: {status} (expected {list(STATUSES)})'}
    try:
        row = FindingsStore().set_status(finding_id, status, note=note,
                                         source='user')
        return {'status': 'ok', 'finding': row}
    except KeyError:
        return {'error': f'finding not found: {finding_id}'}
    except Exception as e:
        return {'error': str(e)}


def _finding_assign(finding_id: str, assignee: Optional[str] = None) -> dict:
    """Assign (or, with an empty value, unassign) one finding — event-sourced over
    finding_events. Returns the current assignee, or an ``{'error': ...}``."""
    try:
        who = FindingsStore().assign(finding_id, assignee or '')
        return {'status': 'ok', 'finding_id': finding_id, 'assignee': who}
    except KeyError:
        return {'error': f'finding not found: {finding_id}'}
    except Exception as e:
        return {'error': str(e)}


def _finding_comment(finding_id: str, text: str,
                     author: Optional[str] = None) -> dict:
    """Append a triage comment to one finding (event-sourced). Returns the stored
    comment, or an ``{'error': ...}`` for empty text / an unknown finding."""
    try:
        comment = FindingsStore().add_comment(finding_id, text, author=author or '')
        return {'status': 'ok', 'finding_id': finding_id, 'comment': comment}
    except KeyError:
        return {'error': f'finding not found: {finding_id}'}
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}


def _finding_triage(finding_id: str) -> dict:
    """Read-only triage view of one finding: current assignee + comment thread."""
    try:
        store = FindingsStore()
        if store.get(finding_id) is None:
            return {'error': f'finding not found: {finding_id}'}
        return {'finding_id': finding_id, 'assignee': store.get_assignee(finding_id),
                'comments': store.comments(finding_id)}
    except Exception as e:
        return {'error': str(e)}


# ── Asset Inventory (web parity) ────────────────────────────────────────────────
# Thin read-only wrapper over core.asset_store (the same SQLite store the GUI tab
# and CollectionRunner use). Assets are observed, not user-triaged, so there is no
# write endpoint — parity with the read-only Assets tab.

def _assets_list(project: Optional[str] = None, type: Optional[str] = None,
                 status: Optional[str] = None) -> dict:
    """Assets (optionally filtered) + the project list + a status summary."""
    try:
        from core.asset_store import AssetStore
        store = AssetStore()
        return {'projects': store.projects(),
                'assets': store.list_assets(project=project, type=type,
                                            status=status),
                'summary': store.summary(project)}
    except Exception as e:
        return {'projects': [], 'assets': [], 'summary': {}, 'error': str(e)}


# ── Executive Overview (F5, web parity) ─────────────────────────────────────────
# Thin wrapper over core.portfolio (the same aggregates the GUI Overview tab
# shows). Read-only over the server's SiteAnalyzer projects tree; ``base`` is
# parametrised only so it is unit-testable against a tmp tree.

def _overview_summary(base: Optional[str] = None) -> dict:
    """Cross-project executive portfolio (rows + estate totals) for the console."""
    try:
        from core.portfolio import load_portfolio
        return load_portfolio(base or str(_REPORT_BASE))
    except Exception as e:
        return {'rows': [], 'totals': {}, 'error': str(e)}


# ── Company / Workspace tier (F-C4, web parity) ─────────────────────────────────
# Read roll-up over core.company (the same aggregates the GUI Overview tab shows)
# plus a single user-sourced write (assign a project to a company), mirroring the
# GUI assign control. Both bound to the server's SiteAnalyzer projects tree.

def _company_view(base: Optional[str] = None) -> dict:
    """Per-company roll-up (rows + estate totals) for the console."""
    try:
        from core.company import load_company_view
        return load_company_view(base or str(_REPORT_BASE))
    except Exception as e:
        return {'rows': [], 'totals': {}, 'error': str(e)}


def _company_assign(slug: str, name: Optional[str],
                    base: Optional[str] = None) -> dict:
    """Assign (or, with an empty name, clear) a project's company (user-sourced).

    A non-empty name is registered (idempotent) and its slug stored on the
    project; an empty/absent name unassigns. Returns the assigned company slug,
    or an ``{'error': ...}`` for an unknown project."""
    try:
        from core.company import CompanyRegistry
        cslug = CompanyRegistry().create(name) if name and name.strip() else None
        ok = ProjectStore(base or str(_REPORT_BASE)).assign(slug, cslug)
        if not ok:
            return {'error': f'project not found: {slug}'}
        return {'status': 'ok', 'slug': slug, 'company': cslug}
    except Exception as e:
        return {'error': str(e)}


# ── Cross-entity correlation (F-K4, web parity) ─────────────────────────────────
# Read-only over core.correlation — the same exposure (findings ↔ assets ↔ infra)
# the GUI surfaces. Inherently per-project: an empty project yields an empty view.

def _correlation_view(project: Optional[str] = None) -> dict:
    """Exposure-by-asset correlation for one project (empty without a project)."""
    if not project:
        return {'exposure': [], 'asset_findings': {}, 'finding_chains': {},
                'summary': {}}
    try:
        from core.asn_intel import load_related_assets
        from core.asset_graph import load_asset_graph
        from core.correlation import load_correlation
        data = load_correlation(project)
        # EPIC 5: asset↔asset relationships + shared-infra exposure clusters
        # alongside the finding↔asset correlation (the same engine surface). The
        # infra-chain tail (co-hosted external domains) is surfaced as external
        # `related` nodes when the opt-in asn_intel phase ran for this project.
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        related = load_related_assets(proj) if proj is not None else None
        data['asset_graph'] = load_asset_graph(project, related=related)
        return data
    except Exception as e:
        return {'exposure': [], 'summary': {}, 'error': str(e)}


# ── Core Intelligence (EPIC 7, web parity) ──────────────────────────────────────
# Read-only over core.intelligence — findings ranked by priority with a confidence
# score + explanation. Inherently per-project: an empty project yields an empty view.

def _intelligence_view(project: Optional[str] = None) -> dict:
    """Priority-ranked findings (confidence + explanation) for one project."""
    if not project:
        return {'items': [], 'top': [], 'summary': {}}
    try:
        from core.intelligence import load_intelligence
        # F2: fold in the project's Business Context Model so business criticality /
        # data sensitivity reach priority (best-effort — missing project → topology).
        business = None
        try:
            proj = ProjectStore(str(_REPORT_BASE)).get(project)
            if proj is not None:
                business = proj.get_business_context()
        except Exception:
            business = None
        return load_intelligence(project, business=business)
    except Exception as e:
        return {'items': [], 'top': [], 'summary': {}, 'error': str(e)}


# ── Asset Criticality + Attack Paths (EPIC 9/11, web parity) ─────────────────────
# Read-only over core.intelligence — the same display-only rankings the report cards
# show. Inherently per-project: an empty project yields an empty view.

def _criticality_view(project: Optional[str] = None) -> dict:
    """Assets ranked by criticality (importance) for one project."""
    if not project:
        return {'items': [], 'top': [], 'summary': {}}
    try:
        from core.intelligence import load_asset_criticality
        # F1: fold in the project's Business Context Model when available
        # (best-effort — a missing project just yields the technical ranking).
        business = None
        try:
            proj = ProjectStore(str(_REPORT_BASE)).get(project)
            if proj is not None:
                business = proj.get_business_context()
        except Exception:
            business = None
        return load_asset_criticality(project, business=business)
    except Exception as e:
        return {'items': [], 'top': [], 'summary': {}, 'error': str(e)}


def _attack_paths_view(project: Optional[str] = None) -> dict:
    """Lateral attack paths (entry → pivot → critical goal) for one project."""
    if not project:
        return {'paths': [], 'top': [], 'summary': {}}
    try:
        from core.intelligence import load_attack_paths
        # F3: fold in the project's Business Context Model so the goal criticality
        # is business-aware (best-effort — missing project → topology only).
        business = None
        try:
            proj = ProjectStore(str(_REPORT_BASE)).get(project)
            if proj is not None:
                business = proj.get_business_context()
        except Exception:
            business = None
        return load_attack_paths(project, business=business)
    except Exception as e:
        return {'paths': [], 'top': [], 'summary': {}, 'error': str(e)}


def _remediation_view(project: Optional[str] = None) -> dict:
    """Remediation tasks (status/owner/due per finding) for one project (F4)."""
    if not project:
        return {'tasks': [], 'summary': {}}
    try:
        from core.remediation import load_remediation
        return load_remediation(project)
    except Exception as e:
        return {'tasks': [], 'summary': {}, 'error': str(e)}


def _exposure_view(project: Optional[str] = None) -> dict:
    """Assets ranked by exposure (likelihood — reachability/attackability) for one
    project."""
    if not project:
        return {'items': [], 'top': [], 'summary': {}}
    try:
        from core.intelligence import load_exposure
        return load_exposure(project)
    except Exception as e:
        return {'items': [], 'top': [], 'summary': {}, 'error': str(e)}


def _accuracy_view(project: Optional[str] = None) -> dict:
    """Scan detection accuracy (confidence per scanned entity) for one project.

    Report-based (like the timeline) — resolves the project from the report base
    and delegates to ``load_accuracy``; an empty/unknown project yields an empty
    view. MODULE 1 web parity."""
    if not project:
        return {'by_type': {}, 'items': [], 'summary': {}}
    try:
        from core.intelligence import load_accuracy
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        if proj is None:
            return {'by_type': {}, 'items': [], 'summary': {},
                    'error': f'project not found: {project}'}
        return load_accuracy(proj)
    except Exception as e:
        return {'by_type': {}, 'items': [], 'summary': {}, 'error': str(e)}


def _osint_catalog_view(project: Optional[str] = None) -> dict:
    """OSINT workflow coverage for one project's latest scan (EXT-OSINT F3).

    Report-based (like accuracy/technology-risk) — resolves the project and
    delegates to ``osint_catalog.load_catalog``. A display/guide view: it never
    affects the risk score. Empty/unknown project yields the bare catalog."""
    from core.osint_catalog import available, load_catalog, summary
    if not project:
        return {'summary': summary(), 'workflows': [], 'available': available()}
    try:
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        if proj is None:
            return {'summary': summary(), 'workflows': [], 'available': available(),
                    'error': f'project not found: {project}'}
        return load_catalog(proj)
    except Exception as e:
        return {'summary': summary(), 'workflows': [], 'available': available(),
                'error': str(e)}


def _technology_risk_view(project: Optional[str] = None) -> dict:
    """Technology-risk posture (outdated tech + vulnerable deps) for one project.

    Report-based (like accuracy) — resolves the project from the report base and
    delegates to ``tech_risk.load_technology_risk``. A display view (EPIC 15): it does
    not alter the authoritative risk verdict. Empty/unknown project yields an empty
    view."""
    if not project:
        return {'summary': {}, 'items': []}
    try:
        from core.tech_risk import load_technology_risk
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        if proj is None:
            return {'summary': {}, 'items': [],
                    'error': f'project not found: {project}'}
        return load_technology_risk(proj)
    except Exception as e:
        return {'summary': {}, 'items': [], 'error': str(e)}


def _related_assets_view(project: Optional[str] = None) -> dict:
    """Co-hosted external domains sharing the project's IP (infra-chain tail).

    Report-based (like accuracy) — resolves the project and delegates to
    ``asn_intel.load_related_assets``. A display view: a co-hosted neighbour is not
    an owned asset. Empty/unknown project yields an empty view."""
    empty = {'shared_ip': '', 'related': [], 'count': 0, 'total': 0}
    if not project:
        return dict(empty)
    try:
        from core.asn_intel import load_related_assets
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        if proj is None:
            return {**empty, 'error': f'project not found: {project}'}
        return load_related_assets(proj)
    except Exception as e:
        return {**empty, 'error': str(e)}


# ── Timeline / Change feed (F2, web parity) ─────────────────────────────────────
# Read-only over core.timeline — the same derive-on-read change feed (series +
# events) the GUI Timeline tab shows. Inherently per-project: an empty project
# yields an empty view.

def _timeline_view(project: Optional[str] = None) -> dict:
    """A project's change timeline (scan series + events) for the console."""
    if not project:
        return {'series': [], 'events': []}
    try:
        from core.timeline import build_timeline
        from core.trends import trend_summary
        proj = ProjectStore(str(_REPORT_BASE)).get(project)
        if proj is None:
            return {'series': [], 'events': [],
                    'error': f'project not found: {project}'}
        tl = build_timeline(proj)
        # EPIC 4: per-metric trend analytics alongside the series (risk direction,
        # delta since the first scan, peak) — derived from the same series.
        tl['trend'] = trend_summary(tl.get('series') or [])
        return tl
    except Exception as e:
        return {'series': [], 'events': [], 'error': str(e)}


# ── Audit Runs (Workbench v2) ───────────────────────────────────────────────
# Read-only parity with the GUI Audit Runs tab. The AuditRunStore is the
# persistence for audit-run payloads; comparison is derived on read from two
# stored runs (no second findings source, no new table).

def _audit_runs_list(project: Optional[str] = None) -> dict:
    try:
        from core.audit_store import AuditRunStore
        runs = AuditRunStore().list_runs(project)
        return {'project': project, 'runs': [
            {'run_id': r.get('id'), 'project': r.get('project'),
             'status': r.get('status'), 'profile': r.get('profile'),
             'updated_at': r.get('updated_at')}
            for r in runs
        ]}
    except Exception as e:
        return {'project': project, 'runs': [], 'error': str(e)}


def _audit_run_view(run_id: str) -> dict:
    try:
        from core.audit_store import AuditRunStore
        payload = AuditRunStore().export_run(str(run_id))
        return {'run': payload}
    except KeyError:
        return {'error': f'audit run not found: {run_id}'}
    except Exception as e:
        return {'error': str(e)}


def _missions_list(project: Optional[str] = None) -> dict:
    try:
        from core.mission_store import MissionStore
        missions = MissionStore().list_missions(project)
        return {'project': project, 'missions': [
            {'mission_id': m.get('id'), 'project': m.get('project'),
             'status': m.get('status'), 'profile': m.get('profile'),
             'objective': (m.get('payload') or {}).get('objective')
             if isinstance(m.get('payload'), dict) else None,
             'updated_at': m.get('updated_at')}
            for m in missions
        ]}
    except Exception as e:
        return {'project': project, 'missions': [], 'error': str(e)}


def _mission_view(mission_id: str) -> dict:
    try:
        from core.mission_store import MissionStore
        payload = MissionStore().export_mission(str(mission_id))
        return {'mission': payload}
    except KeyError:
        return {'error': f'mission not found: {mission_id}'}
    except Exception as e:
        return {'error': str(e)}


def _mission_set_schedule(mission_id: str, interval: str,
                          enabled: bool = True) -> dict:
    """Enable/disable a mission's recurring schedule (M9)."""
    try:
        from core.mission_schedule import (disable_mission_schedule,
                                           set_mission_schedule)
        if not enabled:
            sched = disable_mission_schedule(mission_id)
            if sched is None:
                return {'error': f'mission not scheduled: {mission_id}'}
            return {'mission_id': mission_id, 'schedule': sched}
        sched = set_mission_schedule(mission_id, interval, enabled=True)
        return {'mission_id': mission_id, 'schedule': sched}
    except KeyError:
        return {'error': f'mission not found: {mission_id}'}
    except Exception as e:
        return {'error': str(e)}


def _missions_run_due() -> dict:
    """Run every enabled + due scheduled mission (M9)."""
    try:
        from core.mission_schedule import run_due_missions
        return {'results': run_due_missions()}
    except Exception as e:
        return {'results': [], 'error': str(e)}


def _missions_overview(project: Optional[str] = None) -> dict:
    """Portfolio overview of missions (counts by status + last-run outcomes)."""
    try:
        from core.mission_overview import build_mission_overview
        return build_mission_overview(project=project)
    except Exception as e:
        return {'total': 0, 'counts': {}, 'client_facing': 0, 'missions': [],
                'error': str(e)}


def _missions_csv(project: Optional[str] = None) -> str:
    """CSV of the mission portfolio (mirrors /findings.sarif, /report.md)."""
    try:
        from core.mission_overview import build_mission_overview
        from core.report_export import missions_csv
        return missions_csv(build_mission_overview(project=project))
    except Exception as e:
        return f'error,{e}\n'


def _mission_create(project: str, objective: str, *, template=None, roe=None,
                    allowed_actions=None) -> dict:
    """Create + persist a client-safe mission. 400-shaped error if not valid."""
    try:
        from core.mission_store import MissionStore
        from core.pentest_mission import create_mission, validate_mission
        mission = create_mission(project, objective, template=template, roe=roe,
                                 allowed_actions=allowed_actions)
        check = validate_mission(mission)
        if not check['valid']:
            return {'error': 'invalid mission: ' + '; '.join(check['errors'])}
        saved = MissionStore().save_mission(mission)
        return {'mission_id': saved['id'], 'status': saved['status']}
    except Exception as e:
        return {'error': str(e)}


def _mission_runs(mission_id: str) -> dict:
    """A mission's run-history trend (client-facing count per linked run, M15)."""
    try:
        from core.mission_overview import mission_run_trend
        from core.mission_store import MissionStore
        row = MissionStore().get_mission(str(mission_id))
        if row is None:
            return {'error': f'mission not found: {mission_id}'}
        return {'mission_id': mission_id, 'runs': mission_run_trend(row['payload'])}
    except Exception as e:
        return {'error': str(e)}


def _mission_prune_links(mission_id: str) -> dict:
    """Drop a mission's stale (deleted run/finding) links (M14)."""
    try:
        from core.mission_links import prune_stale_links
        from core.mission_store import MissionStore
        store = MissionStore()
        row = store.get_mission(str(mission_id))
        if row is None:
            return {'error': f'mission not found: {mission_id}'}
        out = prune_stale_links(row['payload'])
        store.save_mission(out['mission'])
        return {'mission_id': mission_id, 'removed_runs': out['removed_runs'],
                'removed_findings': out['removed_findings']}
    except Exception as e:
        return {'error': str(e)}


def _mission_report(mission_id: str) -> dict:
    """Assemble a mission's evidence-first report (read-only view over stores)."""
    try:
        from core import mission_report
        from core.mission_store import MissionStore
        row = MissionStore().get_mission(str(mission_id))
        if row is None:
            return {'error': f'mission not found: {mission_id}'}
        return {'report': mission_report.build_mission_report(row['payload'])}
    except Exception as e:
        return {'error': str(e)}


def _mission_run(mission_id: str) -> dict:
    """Execute a ready mission as an audit run (mutation). Bounded + offline by
    default (no fetcher), so it runs synchronously like the other per-resource
    mutation POSTs (e.g. /findings/{id}/status), not via the named-phase JOBS."""
    try:
        from core.mission_runner import run_mission
        from core.mission_store import MissionStore
        row = MissionStore().get_mission(str(mission_id))
        if row is None:
            return {'error': f'mission not found: {mission_id}'}
        out = run_mission(row['payload'])
        return {'mission_id': out['mission_id'], 'run_id': out['run_id'],
                'status': out['status']}
    except Exception as e:
        return {'error': str(e)}


def _mission_run_tool(mission_id: str, tool: str,
                      evidence: Optional[dict] = None, *,
                      from_scan: bool = False,
                      scan_id_src: Optional[str] = None) -> dict:
    """Run one client-safe tool against a mission from captured evidence
    (mutation). The tool is never executed — the operator supplies the captured
    evidence (or, with ``from_scan``, it is pulled from the mission's project
    scan via ``tool_evidence``), the run is gated by the mission's ROE, and a
    completed run's findings/assets are ingested into the project stores
    (blocked/skipped → no write). Mirrors the Missions tab 'Run tool' surface."""
    try:
        from core.mission_store import MissionStore
        from core.tool_runner import run_tool_for_mission, tool_scan_id
        row = MissionStore().get_mission(str(mission_id))
        if row is None:
            return {'error': f'mission not found: {mission_id}'}
        if not str(tool or '').strip():
            return {'error': 'tool is required'}
        payload = row['payload']
        # Pull evidence from the mission's project scan when asked and none given.
        if from_scan and not evidence:
            from core.tool_evidence import evidence_from_project_scan
            evidence = evidence_from_project_scan(
                payload.get('project'), str(tool), base=str(_REPORT_BASE),
                scan_id=scan_id_src)
        scan_id = tool_scan_id(str(tool))
        out = run_tool_for_mission(payload, str(tool),
                                   evidence or {}, scan_id=scan_id)
        result, ingest = out['result'], out['ingest']
        return {'mission_id': mission_id, 'tool': str(tool),
                'status': result.status, 'written': ingest['written'],
                'findings': ingest['findings'], 'assets': ingest['assets']}
    except Exception as e:
        return {'error': str(e)}


# ── Engagements (Engagement & ROE Foundation, web parity) ────────────────────
# Read + thin mutations over EngagementStore + the pure core.engagement contract
# (mirrors the missions endpoints). Authorized-pentest only; no second store.

def _engagements_list(project: Optional[str] = None) -> dict:
    try:
        from core.engagement_store import EngagementStore
        rows = EngagementStore().list_engagements(project)
        return {'project': project, 'engagements': [
            {'engagement_id': r.get('id'), 'client': r.get('client'),
             'project': r.get('project'), 'status': r.get('status'),
             'updated_at': r.get('updated_at')}
            for r in rows]}
    except Exception as e:
        return {'project': project, 'engagements': [], 'error': str(e)}


def _engagement_view(engagement_id: str) -> dict:
    try:
        from core.engagement_store import EngagementStore
        return {'engagement': EngagementStore().export_engagement(str(engagement_id))}
    except KeyError:
        return {'error': f'engagement not found: {engagement_id}'}
    except Exception as e:
        return {'error': str(e)}


def _engagement_create(client: str, project: str, *, scope=None, roe=None,
                       authorization=None) -> dict:
    """Create + persist a client-safe engagement. 400-shaped if not valid."""
    try:
        from core.engagement import create_engagement, validate_engagement
        from core.engagement_store import EngagementStore
        engagement = create_engagement(client, project, scope=scope, roe=roe,
                                       authorization=authorization)
        check = validate_engagement(engagement)
        if not check['valid']:
            return {'error': 'invalid engagement: ' + '; '.join(check['errors'])}
        saved = EngagementStore().save_engagement(engagement)
        return {'engagement_id': saved['id'], 'status': saved['status']}
    except Exception as e:
        return {'error': str(e)}


def _engagement_advance(engagement_id: str, new_status: str) -> dict:
    try:
        from core.engagement import advance_engagement_status
        from core.engagement_store import EngagementStore
        store = EngagementStore()
        row = store.get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        saved = store.save_engagement(
            advance_engagement_status(row['payload'], str(new_status)))
        return {'engagement_id': saved['id'], 'status': saved['status']}
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}


def _engagement_link(engagement_id: str, kind: str, ref_id: str) -> dict:
    """Link an existing mission / audit_run / finding to the engagement (checked)."""
    try:
        from core import engagement_links as el
        from core.engagement_store import EngagementStore
        store = EngagementStore()
        row = store.get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        linker = {'mission': el.link_mission_checked,
                  'audit_run': el.link_audit_run_checked,
                  'finding': el.link_finding_checked}.get(str(kind))
        if linker is None:
            return {'error': f'unknown link kind: {kind} '
                             '(mission / audit_run / finding)'}
        saved = store.save_engagement(linker(row['payload'], str(ref_id)))
        return {'engagement_id': saved['id'], 'kind': str(kind),
                'ref_id': str(ref_id)}
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}


def _engagement_prune_links(engagement_id: str) -> dict:
    try:
        from core.engagement_links import prune_stale_links
        from core.engagement_store import EngagementStore
        store = EngagementStore()
        row = store.get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        out = prune_stale_links(row['payload'])
        store.save_engagement(out['engagement'])
        return {'engagement_id': str(engagement_id),
                'removed_missions': out['removed_missions'],
                'removed_runs': out['removed_runs'],
                'removed_findings': out['removed_findings']}
    except Exception as e:
        return {'error': str(e)}


def _engagement_report(engagement_id: str) -> dict:
    try:
        from core.engagement_report import build_engagement_report
        from core.engagement_store import EngagementStore
        row = EngagementStore().get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        return {'report': build_engagement_report(row['payload'])}
    except Exception as e:
        return {'error': str(e)}


def _engagement_retest(engagement_id: str) -> dict:
    try:
        from core.engagement_retest import build_retest
        from core.engagement_store import EngagementStore
        row = EngagementStore().get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        return {'retest': build_retest(row['payload'])}
    except Exception as e:
        return {'error': str(e)}


def _engagements_overview(project: Optional[str] = None) -> dict:
    try:
        from core.engagement_overview import build_engagement_overview
        return build_engagement_overview(project=project)
    except Exception as e:
        return {'total': 0, 'counts': {}, 'engagements': [], 'error': str(e)}


def _engagements_csv(project: Optional[str] = None) -> str:
    from core.engagement_overview import build_engagement_overview
    from core.report_export import engagements_csv
    return engagements_csv(build_engagement_overview(project=project))


def _engagement_create_mission(engagement_id: str, objective: str,
                               allowed_actions=None) -> dict:
    """Create a mission under an engagement (ROE inherited) + link it back."""
    try:
        from core.engagement_missions import create_mission_under_engagement
        from core.engagement_store import EngagementStore
        row = EngagementStore().get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        return create_mission_under_engagement(
            row['payload'], objective, allowed_actions=allowed_actions)
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}


def _engagement_retest_run(engagement_id: str) -> dict:
    """Take + persist a retest snapshot for an engagement (R4)."""
    try:
        from core.engagement_store import EngagementStore
        from core.retest_runner import run_retest
        row = EngagementStore().get_engagement(str(engagement_id))
        if row is None:
            return {'error': f'engagement not found: {engagement_id}'}
        out = run_retest(row['payload'])
        return {'retest_run_id': out['retest_run_id'], 'status': out['status'],
                'summary': out['summary']}
    except Exception as e:
        return {'error': str(e)}


def _engagement_retest_runs(engagement_id: str) -> dict:
    """List persisted retest runs for an engagement (newest snapshot first)."""
    try:
        from core.retest_run_store import RetestRunStore
        rows = RetestRunStore().list_retest_runs(engagement_id=str(engagement_id))
        return {'engagement_id': str(engagement_id), 'retest_runs': [
            {'retest_run_id': r.get('id'), 'status': r.get('status'),
             'created_at': r.get('created_at'),
             'summary': (r.get('payload') or {}).get('summary')}
            for r in rows]}
    except Exception as e:
        return {'engagement_id': str(engagement_id), 'retest_runs': [],
                'error': str(e)}


def _retest_run_view(run_id: str) -> dict:
    try:
        from core.retest_run_store import RetestRunStore
        row = RetestRunStore().get_retest_run(str(run_id))
        if row is None:
            return {'error': f'retest run not found: {run_id}'}
        return {'retest_run': row['payload']}
    except Exception as e:
        return {'error': str(e)}


def _audit_compare_view(baseline_id: str, candidate_id: str) -> dict:
    try:
        from core.audit_store import AuditRunStore
        from core.audit_compare import compare_stored
        return compare_stored(AuditRunStore(), str(baseline_id), str(candidate_id))
    except KeyError as e:
        return {'error': f'audit run not found: {e}'}
    except Exception as e:
        return {'error': str(e)}


# ── Continuous Monitoring (#8) ─────────────────────────────────────────────────
# Thin wrappers over core.monitor (single source of truth, shared with the CLI
# and GUI). All bound to the same project store the jobs use.

def _monitor_store() -> ProjectStore:
    return ProjectStore(str(_REPORT_BASE))


def _monitor_event_text(ev: dict) -> str:
    """Render a monitor run event for the live console feed (shared formatter)."""
    return monitor.format_event(ev)


# ── Alert Center (#9) ──────────────────────────────────────────────────────────
# The console reports alert status and can fire a test, but does NOT edit channel
# tokens over the LAN (those are set in the GUI / settings.json). Read-only here.

def _alerts_config() -> dict:
    cfg = load_settings().get('alerts')
    return cfg if isinstance(cfg, dict) else {}


def _alerts_overview() -> dict:
    """Enabled flag + which channels are configured (no token values)."""
    cfg = _alerts_config()
    return {
        'enabled': bool(cfg.get('enabled')),
        'channels': [ch.name for ch in alerts.build_channels(cfg)],
        'types': cfg.get('types') or list(alerts.ALERT_TYPES),
    }


# ── Dashboard HTML ────────────────────────────────────────────────────────────

_DASHBOARD = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Advanced Site Analyzer</title>
<style>
:root{--bg:#0d1117;--sf:#161b22;--br:#30363d;--tx:#e6edf3;--mu:#8b949e;
--ac:#58a6ff;--ok:#3fb950;--wn:#d29922;--er:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Segoe UI',system-ui,sans-serif;
min-height:100vh;display:flex;flex-direction:column}
header{background:var(--sf);border-bottom:1px solid var(--br);padding:10px 16px;
display:flex;align-items:center;gap:8px;position:sticky;top:0;z-index:10}
header h1{font-size:.95rem;font-weight:600;color:var(--ac)}
.hdr-status{margin-left:auto;font-size:.72rem;color:var(--mu);display:flex;align-items:center;gap:5px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mu)}
.dot.on{background:var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.wrap{max-width:860px;margin:0 auto;padding:12px;width:100%;flex:1}
.card{background:var(--sf);border:1px solid var(--br);border-radius:8px;
padding:14px;margin-bottom:10px}
.card-title{font-size:.7rem;color:var(--mu);text-transform:uppercase;
letter-spacing:.06em;margin-bottom:10px}
.row{display:flex;gap:8px;flex-wrap:wrap}
input[type=text]{flex:1;min-width:0;background:var(--bg);border:1px solid var(--br);
border-radius:6px;color:var(--tx);padding:8px 11px;font-size:.88rem;outline:none}
input[type=text]:focus{border-color:var(--ac)}
select{background:var(--bg);border:1px solid var(--br);border-radius:6px;
color:var(--tx);padding:8px 11px;font-size:.88rem;outline:none}
select:focus{border-color:var(--ac)}
.btn{background:var(--ac);color:#0d1117;border:none;border-radius:6px;
padding:7px 14px;font-size:.85rem;font-weight:600;cursor:pointer;
white-space:nowrap;transition:opacity .15s}
.btn:hover{opacity:.82}.btn:disabled{opacity:.38;cursor:not-allowed}
.btn.sec{background:var(--sf);color:var(--tx);border:1px solid var(--br)}
.btn.ok{background:var(--ok)}.btn.er{background:var(--er)}
.btn.wn{background:var(--wn);color:#0d1117}
.btns{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.console{background:#010409;border:1px solid var(--br);border-radius:6px;
padding:10px;font-family:Consolas,Monaco,monospace;font-size:.76rem;
height:260px;overflow-y:auto}
@media(max-width:480px){.console{height:190px}}
.ln{line-height:1.55;padding:1px 0}
.ln.info{color:#8b949e}.ln.ok{color:#3fb950}.ln.wn{color:#d29922}
.ln.er{color:#f85149}.ln.data{color:#58a6ff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:7px}
.met{background:var(--bg);border:1px solid var(--br);border-radius:6px;padding:9px 11px}
.mlb{font-size:.68rem;color:var(--mu);text-transform:uppercase}
.mvl{font-size:1.15rem;font-weight:600;color:var(--ac);margin-top:2px;
word-break:break-all}
.bdg{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.7rem;
font-weight:600;margin:2px}
.bcms{background:rgba(88,166,255,.13);color:var(--ac);border:1px solid rgba(88,166,255,.3)}
.bgeo{background:rgba(63,185,80,.13);color:var(--ok);border:1px solid rgba(63,185,80,.3)}
.spin{display:inline-block;width:9px;height:9px;border:2px solid var(--br);
border-top-color:var(--ac);border-radius:50%;animation:sp .7s linear infinite;
margin-right:5px;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<header>
  <h1>Advanced Site Analyzer</h1>
  <div class="hdr-status">
    <span class="dot" id="dot"></span>
    <span id="stxt">Connecting...</span>
  </div>
</header>
<div class="wrap">

  <div class="card">
    <div class="card-title">Target</div>
    <div class="row">
      <input type="text" id="url" placeholder="https://example.com">
    </div>
    <div class="btns" id="jobbtns">
      <button class="btn wn" id="b-cancel" onclick="cancelJob()" disabled>Cancel</button>
      <button class="btn er" id="b-clr" onclick="clr()">Clear</button>
      <button class="btn sec" onclick="showHistory()">History</button>
      <button class="btn sec" onclick="showData()">Data</button>
      <button class="btn sec" onclick="showFindings()">Findings</button>
      <button class="btn sec" onclick="showAssets()">Assets</button>
      <button class="btn sec" onclick="showOverview()">Overview</button>
      <button class="btn sec" onclick="showCompanies()">Companies</button>
      <button class="btn sec" onclick="showCorrelation()">Correlation</button>
      <button class="btn sec" onclick="showTimeline()">Timeline</button>
      <button class="btn sec" onclick="showIntelligence()">Intelligence</button>
      <button class="btn sec" onclick="showCriticality()">Criticality</button>
      <button class="btn sec" onclick="showExposure()">Exposure</button>
      <button class="btn sec" onclick="showRelatedAssets()">Related Assets</button>
      <button class="btn sec" onclick="showAttackPaths()">Attack Paths</button>
      <button class="btn sec" onclick="showRemediation()">Remediation</button>
      <button class="btn sec" onclick="showAccuracy()">Scan Accuracy</button>
      <button class="btn sec" onclick="showTechnologyRisk()">Technology Risk</button>
      <button class="btn sec" onclick="showOsintCatalog()">OSINT Catalog</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Continuous Monitoring</div>
    <div class="row">
      <select id="mon-interval">
        <option value="daily">Daily</option>
        <option value="weekly">Weekly</option>
        <option value="monthly">Monthly</option>
      </select>
      <button class="btn" onclick="monEnable()">Watch</button>
      <button class="btn sec" onclick="monDisable()">Unwatch</button>
    </div>
    <div class="btns">
      <button class="btn sec" onclick="monStatus()">Status</button>
      <button class="btn sec" id="b-mon-run" onclick="monRun()">Run due now</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Alert Center</div>
    <div class="btns">
      <button class="btn sec" onclick="alertStatus()">Status</button>
      <button class="btn sec" onclick="alertTest()">Send test alert</button>
    </div>
  </div>

  <div class="card" id="mc" style="display:none">
    <div class="card-title">Last Result</div>
    <div class="grid" id="mg"></div>
    <div style="margin-top:8px" id="ba"></div>
  </div>

  <div class="card">
    <div class="card-title">Live Console</div>
    <div class="console" id="con"></div>
  </div>

</div>
<script>
// Web-console auth: attach the token (stored locally) to every fetch + the SSE
// stream. On a 401 prompt for it once and store. No token configured server-side
// (loopback default) → requests pass through untouched.
function asaTok(){return localStorage.getItem('asaToken')||'';}
function asaUrl(u){var t=asaTok();return t?u+(u.indexOf('?')<0?'?':'&')+'token='+encodeURIComponent(t):u;}
var _asaFetch=window.fetch;
window.fetch=function(u,o){o=o||{};var h=o.headers||{};var t=asaTok();if(t)h['Authorization']='Bearer '+t;o.headers=h;
  return _asaFetch(u,o).then(function(r){if(r.status===401){var nt=prompt('Web console token:');if(nt){localStorage.setItem('asaToken',nt.trim());location.reload();}}return r;});};
const con=document.getElementById('con'),dot=document.getElementById('dot'),
stxt=document.getElementById('stxt');
let es=null;

function ts(){return new Date().toTimeString().slice(0,8)}

function log(msg,cls='info'){
  const d=document.createElement('div');
  d.className='ln '+cls;
  d.textContent='['+ts()+'] '+msg;
  con.appendChild(d);
  con.scrollTop=con.scrollHeight;
}

function clr(){
  con.innerHTML='';
  document.getElementById('mc').style.display='none';
}

function setConn(ok){
  dot.className='dot'+(ok?' on':'');
  stxt.textContent=ok?'Connected':'Disconnected';
}

function setRunning(v){
  // Disable job buttons while one runs; enable Cancel only then. Driven by the
  // real job lifecycle (SSE result/error), not a fixed timeout.
  document.querySelectorAll('#jobbtns .btn.sec').forEach(b=>{b.disabled=v;});
  const c=document.getElementById('b-cancel'); if(c) c.disabled=!v;
}

async function loadJobs(){
  try{
    const r=await fetch('/jobs'); const jobs=await r.json();
    const box=document.getElementById('jobbtns');
    jobs.slice().reverse().forEach(j=>{
      const b=document.createElement('button');
      b.className='btn sec'; b.id='b-'+j.name; b.textContent=j.label;
      b.onclick=()=>go(j.name);
      box.insertBefore(b, box.firstChild);
    });
  }catch(ex){log('Failed to load jobs: '+ex.message,'er');}
}

function metrics(data){
  const mc=document.getElementById('mc'),
        mg=document.getElementById('mg'),
        ba=document.getElementById('ba');
  mc.style.display='block';
  mg.innerHTML='';ba.innerHTML='';
  const rows=[];
  if(data.ip) rows.push(['IP',data.ip]);
  if(data.geo?.country) rows.push(['Country',data.geo.country]);
  if(data.geo?.city) rows.push(['City',data.geo.city]);
  if(data.geo?.isp) rows.push(['ISP',data.geo.isp]);
  if(data.total_api_calls!==undefined) rows.push(['API Calls',data.total_api_calls]);
  if(data.pages_captured!==undefined) rows.push(['Pages',data.pages_captured]);
  if(data.pages_processed!==undefined) rows.push(['Cloned pages',data.pages_processed]);
  if(data.assets_downloaded!==undefined) rows.push(['Assets',data.assets_downloaded]);
  if(data.quality!==undefined) rows.push(['Quality',data.quality]);
  if(data.strategy_used) rows.push(['Strategy',data.strategy_used]);
  if(data.html_size!==undefined) rows.push(['HTML size',(data.html_size/1024).toFixed(1)+' KB']);
  if(data.keys_found!==undefined) rows.push(['Keys found',data.keys_found]);
  if(data.total!==undefined) rows.push(['Total',data.total]);
  if(data.live_count!==undefined) rows.push(['Live',data.live_count]);
  if(data.weak!==undefined) rows.push(['Weak cookies',data.weak]);
  if(data.takeover_candidates&&data.takeover_candidates.length) rows.push(['Takeovers',data.takeover_candidates.length]);
  if(data.stats&&data.stats.total_colors!==undefined) rows.push(['Colors',data.stats.total_colors]);
  if(data.stats&&data.stats.total_fonts!==undefined) rows.push(['Fonts',data.stats.total_fonts]);
  if(data.summary&&data.summary.secrets!==undefined){
    rows.push(['Secrets',data.summary.secrets]);
    rows.push(['Endpoints',data.summary.endpoints]);
    rows.push(['Source maps',data.summary.source_maps]);
    rows.push(['JS scanned',data.summary.scanned_scripts]);
  }
  if(data.report_html) rows.push(['Report',data.report_html]);
  rows.forEach(([l,v])=>{
    const val=(l==='Report')
      ? `<a href="/report?file=${encodeURIComponent(v)}" target="_blank" style="color:var(--ac)">open report</a>`
      : v;
    mg.innerHTML+=`<div class="met"><div class="mlb">${l}</div><div class="mvl">${val}</div></div>`;
  });
  (data.cms||[]).forEach(c=>ba.innerHTML+=`<span class="bdg bcms">${c}</span>`);
  if(data.geo?.as) ba.innerHTML+=`<span class="bdg bgeo">${data.geo.as}</span>`;
}

function sse(){
  if(es)es.close();
  es=new EventSource(asaUrl('/events'));
  es.onopen=()=>setConn(true);
  es.onerror=()=>{setConn(false);setTimeout(sse,3000)};
  es.onmessage=e=>{
    try{
      const d=JSON.parse(e.data);
      if(d.type==='log') log(d.message,d.level||'info');
      else if(d.type==='result'){log(d.message,'ok');if(d.data)metrics(d.data);setRunning(false);}
      else if(d.type==='error'){log(d.message,'er');setRunning(false);}
    }catch(ex){}
  };
}

async function go(name){
  const url=document.getElementById('url').value.trim();
  if(!url){log('Enter a URL first','wn');return;}
  setRunning(true);
  log('Sending '+name+' request for: '+url,'data');
  try{
    const r=await fetch('/run/'+name,{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error){log(d.error,'er');setRunning(false);}
    else log('Job started: '+d.job_id,'ok');
  }catch(ex){log('Request failed: '+ex.message,'er');setRunning(false);}
}

async function cancelJob(){
  log('Cancelling current job…','wn');
  try{
    const r=await fetch('/cancel',{method:'POST'});
    const d=await r.json();
    if(d.error) log(d.error,'er');
    else log('Cancel signalled for: '+d.job,'wn');
  }catch(ex){log('Cancel failed: '+ex.message,'er');}
}

async function monEnable(){
  const url=document.getElementById('url').value.trim();
  if(!url){log('Enter a URL first','wn');return;}
  const interval=document.getElementById('mon-interval').value;
  try{
    const r=await fetch('/monitor/enable',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url,interval})});
    const d=await r.json();
    if(d.error) log(d.error,'er');
    else log('Watching '+d.slug+' ('+interval+'). Next: '+d.schedule.next_run,'ok');
  }catch(ex){log('Enable failed: '+ex.message,'er');}
}

async function monDisable(){
  const url=document.getElementById('url').value.trim();
  if(!url){log('Enter a URL first','wn');return;}
  try{
    const r=await fetch('/monitor/disable',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error) log(d.error,'er');
    else log('Stopped watching '+d.slug,'wn');
  }catch(ex){log('Disable failed: '+ex.message,'er');}
}

async function monStatus(){
  try{
    const r=await fetch('/monitor'); const rows=await r.json();
    if(!rows.length){log('No monitored projects','data');return;}
    log('Monitored: '+rows.length+' project(s)','data');
    rows.forEach(m=>log('['+(m.enabled?'on':'off')+'] '+m.slug+' · '+m.interval
        +' · next: '+(m.next_run||'—')+' · last: '+(m.last_run||'—'),
        m.enabled?'info':'wn'));
  }catch(ex){log('Status failed: '+ex.message,'er');}
}

async function monRun(){
  setRunning(true);
  log('Running due monitor scans…','data');
  try{
    const r=await fetch('/monitor/run',{method:'POST'});
    const d=await r.json();
    if(d.error){log(d.error,'er');setRunning(false);}
    else log('Monitor run started','ok');
  }catch(ex){log('Monitor run failed: '+ex.message,'er');setRunning(false);}
}

async function alertStatus(){
  try{
    const r=await fetch('/alerts'); const d=await r.json();
    log('Alerts: '+(d.enabled?'enabled':'disabled')+' · channels: '
        +(d.channels.length?d.channels.join(', '):'none')
        +' · types: '+d.types.join(', '),d.enabled?'data':'wn');
  }catch(ex){log('Alert status failed: '+ex.message,'er');}
}

async function alertTest(){
  log('Sending test alert…','data');
  try{
    const r=await fetch('/alerts/test',{method:'POST'});
    const d=await r.json();
    if(d.reason) log('Test not sent: '+d.reason,'wn');
    else{
      log('Test alert sent to '+d.sent+' channel(s)','ok');
      (d.results||[]).forEach(x=>log('  '+x.channel+': '+x.status
          +(x.error?(' — '+x.error):''),x.status==='ok'?'ok':'er'));
    }
  }catch(ex){log('Test alert failed: '+ex.message,'er');}
}

async function showHistory(){
  try{
    const r=await fetch('/history'); const rows=await r.json();
    log('History: '+rows.length+' operation(s)','data');
    rows.slice(0,20).forEach(o=>{
      const m=o.metadata||{};
      const stages=(m.warning_summary||[]).slice(0,3).map(w=>w.stage||'pipeline').join(',');
      const warn=(m.warning_count||0)?' · warnings: '+m.warning_count+(stages?' ['+stages+']':''):'';
      log('#'+o.id+' '+o.phase+' ['+o.status+'] '+(o.target||'')+warn,
          o.status==='failed'?'er':(o.status==='success'?'ok':'info'));
    });
  }catch(ex){log('History failed: '+ex.message,'er');}
}

async function showData(){
  try{
    const r=await fetch('/data'); const d=await r.json();
    const s=d.summary||{};
    log('Registry: '+(s.total||0)+' records · '+(s.subdomains||0)+' subdomains · '
        +(s.api_endpoints||0)+' endpoints','data');
    (d.records||[]).slice(0,20).forEach(rec=>{
      const c=(rec.content||'').slice(0,80);
      log('['+(rec.data_type||'')+'] '+c,'info');
    });
  }catch(ex){log('Data failed: '+ex.message,'er');}
}

async function showFindings(){
  try{
    const r=await fetch('/findings'); const d=await r.json();
    const s=d.summary||{};
    log('Findings: '+(s.active||0)+' active / '+(s.total||0)+' total · projects: '
        +(d.projects||[]).length,'data');
    (d.findings||[]).slice(0,20).forEach(f=>{
      log('['+(f.severity||'')+'] '+(f.title||'')+' — '+(f.status||'')
          +' ('+(f.id||'').slice(0,8)+')',
          f.status==='OPEN'?'wn':(f.status==='FIXED'?'ok':'info'));
    });
  }catch(ex){log('Findings failed: '+ex.message,'er');}
}

async function showAssets(){
  try{
    const r=await fetch('/assets'); const d=await r.json();
    const s=d.summary||{};
    log('Assets: '+(s.active||0)+' active / '+(s.total||0)+' total · projects: '
        +(d.projects||[]).length,'data');
    (d.assets||[]).slice(0,20).forEach(a=>{
      log('['+(a.type||'')+'] '+(a.label||a.value||'')+' — '+(a.status||''),
          a.status==='ACTIVE'?'ok':'wn');
    });
  }catch(ex){log('Assets failed: '+ex.message,'er');}
}

async function showOverview(){
  try{
    const r=await fetch('/overview'); const d=await r.json();
    const t=d.totals||{};
    log('Overview: '+(t.projects||0)+' projects · worst risk: '
        +(t.worst_risk_level||'—')+' · secrets: '+(t.secrets||0)
        +' · warnings: '+(t.warning_count||0)
        +' · active findings: '+(t.active_findings||0),'data');
    (d.rows||[]).slice(0,20).forEach(p=>{
      const d2=(p.risk_delta==null)?'':(p.risk_delta>0?' ▲':(p.risk_delta<0?' ▼':''));
      log('  '+p.slug+' — '+(p.risk_level||'—')
          +' ('+(p.risk_score==null?'?':p.risk_score)+')'+d2
          +' · warnings: '+(p.warning_count||0)
          +(p.warning_stages?' ['+p.warning_stages+']':'')
          +' · findings: '+(p.active_findings||0),'info');
    });
  }catch(ex){log('Overview failed: '+ex.message,'er');}
}
async function showCompanies(){
  try{
    const r=await fetch('/companies'); const d=await r.json();
    const t=d.totals||{};
    log('Companies: '+(t.companies||0)+' over '+(t.projects||0)+' projects · '
        +'worst risk: '+(t.worst_risk_level||'—')+' · secrets: '+(t.secrets||0)
        +' · warnings: '+(t.warning_count||0)
        +' · assets: '+(t.assets||0),'data');
    (d.rows||[]).slice(0,20).forEach(c=>{
      log('  '+(c.name||c.slug)+' — '+(c.project_count||0)+' proj · '
          +(c.risk_level||'—')+' · findings: '+(c.active_findings||0)
          +' · warnings: '+(c.warning_count||0)
          +' · assets: '+(c.asset_total||0),'info');
    });
  }catch(ex){log('Companies failed: '+ex.message,'er');}
}
async function showCorrelation(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Correlation: no projects','data'); return;}
    const r=await fetch('/correlation?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Correlation ['+proj+']: '+(s.correlated||0)+'/'+(s.findings||0)
        +' findings linked to assets · exposed: '+(s.exposed_assets||0),'data');
    (d.exposure||[]).slice(0,15).forEach(a=>{
      log('  '+(a.label||a.value)+' — '+(a.worst||'—')+' · '
          +(a.findings_count||0)+' finding(s)','info');
    });
    const ag=d.asset_graph||{}; const gs=ag.summary||{};
    log('Asset graph: '+(gs.nodes||0)+' assets · '+(gs.edges||0)+' links · '
        +(gs.clusters||0)+' shared-infra cluster(s)'
        +(gs.related?' · '+gs.related+' co-hosted domain(s)':''),'data');
    (ag.shared_infra||[]).slice(0,10).forEach(c=>{
      log('  '+(c.type||'')+' '+(c.node||'')+' ← '+(c.count||0)+' assets'
          +(c.cdn?' (CDN edge)':''),'info');
    });
    (ag.graph&&ag.graph.nodes||[]).filter(n=>n.external).slice(0,15).forEach(n=>{
      log('  co-hosted: '+(n.value||''),'info');
    });
  }catch(ex){log('Correlation failed: '+ex.message,'er');}
}

async function showTimeline(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Timeline: no projects','data'); return;}
    const r=await fetch('/timeline?project='+encodeURIComponent(proj));
    const d=await r.json(); const ev=d.events||[];
    log('Timeline ['+proj+']: '+ev.length+' event(s) · '
        +((d.series||[]).length)+' scan(s)','data');
    ev.slice(-20).forEach(e=>{
      log('  '+(e.at||'')+' ['+(e.severity||'')+'] '+(e.type||'')+': '
          +(e.title||''),'info');
    });
  }catch(ex){log('Timeline failed: '+ex.message,'er');}
}

async function showIntelligence(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Intelligence: no projects','data'); return;}
    const r=await fetch('/intelligence?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Intelligence ['+proj+']: '+(s.findings||0)+' findings · top priority '
        +(s.top_priority||0)+' · '+(s.high_confidence||0)+' high-confidence','data');
    (d.top||[]).slice(0,10).forEach(i=>{
      log('  P'+(i.priority||0)+' ['+(i.severity||'')+'] '+(i.title||'')
          +' — conf '+(i.confidence||0)+'%','info');
    });
  }catch(ex){log('Intelligence failed: '+ex.message,'er');}
}

async function showCriticality(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Criticality: no projects','data'); return;}
    const r=await fetch('/criticality?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Asset criticality ['+proj+']: '+(s.assets||0)+' assets · top '
        +(s.top_criticality||0)+' · '+(s.high_criticality||0)+' critical','data');
    (d.top||[]).slice(0,10).forEach(i=>{
      log('  C'+(i.criticality||0)+' ['+(i.band||'')+'] '+(i.type||'')+' '
          +(i.value||''),'info');
    });
  }catch(ex){log('Criticality failed: '+ex.message,'er');}
}

async function showExposure(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Exposure: no projects','data'); return;}
    const r=await fetch('/exposure?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Asset exposure ['+proj+']: '+(s.assets||0)+' assets · top '
        +(s.top_exposure||0)+' · '+(s.exposed_assets||0)+' exposed','data');
    (d.top||[]).slice(0,10).forEach(i=>{
      log('  X'+(i.exposure||0)+' ['+(i.band||'')+'] '+(i.type||'')+' '
          +(i.value||''),'info');
    });
  }catch(ex){log('Exposure failed: '+ex.message,'er');}
}

async function showRelatedAssets(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Related assets: no projects','data'); return;}
    const r=await fetch('/related-assets?project='+encodeURIComponent(proj));
    const d=await r.json();
    log('Related assets ['+proj+']: '+(d.count||0)+' co-hosted on '
        +(d.shared_ip||'—')+' (of '+(d.total||0)+' neighbours)','data');
    (d.related||[]).slice(0,20).forEach(x=>{
      log('  '+(x.host||'')+'  ↔ '+(x.shared_ip||''),'info');
    });
  }catch(ex){log('Related assets failed: '+ex.message,'er');}
}

async function showAttackPaths(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Attack paths: no projects','data'); return;}
    const r=await fetch('/attack-paths?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Attack paths ['+proj+']: '+(s.paths||0)+' path(s) · top '
        +(s.top_score||0)+' · '+(s.critical_paths||0)+' critical','data');
    (d.top||[]).slice(0,10).forEach(p=>{
      log('  S'+(p.score||0)+' '+(p.entry||'')+' → '+(p.pivot_type||'')+' '
          +(p.pivot_node||'')+' → '+((p.targets||[]).length)+' targets','info');
    });
  }catch(ex){log('Attack paths failed: '+ex.message,'er');}
}

async function showRemediation(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Remediation: no projects','data'); return;}
    const r=await fetch('/remediation?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Remediation ['+proj+']: '+(s.total||0)+' task(s) · '+(s.open||0)+' open · '
        +(s.overdue||0)+' overdue','data');
    (d.tasks||[]).slice(0,10).forEach(t=>{
      const tk=t.task||{};
      log('  ['+(t.status_label||tk.status||'')+'] '+(t.severity||'')+' '
          +(t.title||'')+(tk.due?(' · due '+tk.due+(t.overdue?' ⚠':'')):''),'info');
    });
  }catch(ex){log('Remediation failed: '+ex.message,'er');}
}

async function showAccuracy(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Accuracy: no projects','data'); return;}
    const r=await fetch('/accuracy?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Scan accuracy ['+proj+']: '+(s.entities||0)+' entities · avg conf '
        +(s.avg_confidence||0)+'% · '+(s.high_confidence||0)+' high','data');
    (d.items||[]).slice(0,10).forEach(i=>{
      log('  '+(i.score||0)+'% ['+(i.band||'')+'] '+(i.entity_type||'')+' '
          +(i.label||''),'info');
    });
  }catch(ex){log('Accuracy failed: '+ex.message,'er');}
}

async function showTechnologyRisk(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('Technology risk: no projects','data'); return;}
    const r=await fetch('/technology-risk?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('Technology risk ['+proj+']: score '+(s.score||0)+' ('+(s.band||'clean')
        +') · '+(s.items||0)+' items · vuln deps '+(s.vulnerable_dependencies||0),'data');
    (d.items||[]).slice(0,10).forEach(i=>{
      log('  '+(i.score||0)+' ['+(i.band||'')+'] '+(i.kind||'')+' '+(i.name||'')+' '
          +(i.version||'')+' — '+(i.reason||''),'info');
    });
  }catch(ex){log('Technology risk failed: '+ex.message,'er');}
}

async function showOsintCatalog(){
  try{
    const o=await fetch('/overview'); const od=await o.json();
    const proj=(od.rows&&od.rows[0])?od.rows[0].slug:null;
    if(!proj){log('OSINT catalog: no projects','data'); return;}
    const r=await fetch('/osint-catalog?project='+encodeURIComponent(proj));
    const d=await r.json(); const s=d.summary||{};
    log('OSINT coverage ['+proj+']: '+(s.covered||0)+' covered · '
        +(s.partial||0)+' partial · '+(s.not_run||0)+' not run (of '
        +(s.total||0)+')','data');
    (d.workflows||[]).forEach(w=>{
      log('  ['+(w.status||'')+'] '+(w.name||'')+' — '+(w.category||''),'info');
    });
  }catch(ex){log('OSINT catalog failed: '+ex.message,'er');}
}

loadJobs();
sse();
log('Web console ready. Accessible on your local network.','ok');
</script>
</body>
</html>
"""


# ── FastAPI setup ─────────────────────────────────────────────────────────────

if _FASTAPI_OK:

    async def require_token(request: Request):
        """App-wide auth gate. When a token is active (``_AUTH_TOKEN``), every
        request outside ``_PUBLIC_PATHS`` must present it (Bearer header or
        ``?token=``); constant-time compared. No active token → open (the
        loopback single-user default). 401 on missing/invalid."""
        if not _AUTH_TOKEN or request.url.path in _PUBLIC_PATHS:
            return
        provided = _request_token(request)
        if not provided or not hmac.compare_digest(provided, _AUTH_TOKEN):
            raise HTTPException(status_code=401,
                                detail='missing or invalid web console token')

    app = FastAPI(title='Advanced Site Analyzer', docs_url=None, redoc_url=None,
                  dependencies=[Depends(require_token)])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_methods=['*'],
        allow_headers=['*'],
    )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception):
        # Uniform JSON error envelope so every endpoint honours the console's
        # ``response.json()`` contract even on an unexpected failure, instead of
        # Starlette's plain-text 500. The traceback is logged server-side by
        # Starlette; only the type+message reach the LAN client (mirrors the
        # ``{'error': str(e)}`` shape the data wrappers already return).
        return JSONResponse(
            {'error': f'{type(exc).__name__}: {exc}'}, status_code=500)

    class TargetRequest(BaseModel):
        url: str

    # ── Dashboard ────────────────────────────────────────────────────────

    @app.get('/', response_class=HTMLResponse)
    async def dashboard():
        return HTMLResponse(_DASHBOARD)

    # ── SSE stream ───────────────────────────────────────────────────────

    @app.get('/events')
    async def events(request: Request):
        async def generate():
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(_log_queue.get(), timeout=20.0)
                    yield f'data: {json.dumps(msg)}\n\n'
                except asyncio.TimeoutError:
                    yield f'data: {json.dumps({"type":"heartbeat"})}\n\n'
        return StreamingResponse(
            generate(),
            media_type='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    # ── Generic background runner ────────────────────────────────────────

    async def _run_job(name: str, url: str, job_id: str):
        global _active_job, _active_cancellable
        loop = asyncio.get_event_loop()
        label = JOBS[name]['label']
        await _push(f'[{label}] start: {url}')
        try:
            def push_sync(msg, level: str = 'info'):
                asyncio.run_coroutine_threadsafe(_push(str(msg), level), loop)

            result = await loop.run_in_executor(
                None, JOBS[name]['fn'], url, push_sync)
            compact = _strip_heavy(result)
            _record_job_result(job_id, compact)
            await _push(f'[{label}] complete', 'ok', 'result', compact)
        except Exception as e:
            await _push(f'[{label}] error: {e}', 'er', 'error')
        finally:
            _active_job = None
            _active_cancellable = None

    # ── Endpoints ────────────────────────────────────────────────────────

    def _check_busy():
        if _active_job:
            return JSONResponse({'error': f'Job already running: {_active_job}'}, status_code=409)
        return None

    @app.get('/jobs')
    async def jobs():
        return [{'name': n, 'label': s['label']} for n, s in JOBS.items()]

    @app.post('/run/{name}')
    async def run_job(name: str, body: TargetRequest, bg: BackgroundTasks):
        global _active_job
        if name not in JOBS:
            return JSONResponse({'error': f'unknown job: {name}'}, status_code=404)
        busy = _check_busy()
        if busy:
            return busy
        job_id = str(uuid.uuid4())[:8]
        _active_job = name
        bg.add_task(_run_job, name, body.url, job_id)
        return {'job_id': job_id, 'job': name, 'url': body.url, 'status': 'started'}

    @app.post('/cancel')
    async def cancel():
        result = _request_cancel()
        if 'error' in result:
            return JSONResponse(result, status_code=409)
        await _push(f"[{result['job']}] cancel requested — stopping…", 'wn')
        return result

    # ── Continuous Monitoring (#8) ───────────────────────────────────────

    class MonitorRequest(BaseModel):
        url: str
        interval: str = 'daily'

    @app.get('/monitor')
    async def monitor_status():
        return JSONResponse(monitor.status(_monitor_store()))

    @app.post('/monitor/enable')
    async def monitor_enable(body: MonitorRequest):
        if body.interval not in monitor.INTERVALS:
            return JSONResponse(
                {'error': f'interval must be one of {monitor.INTERVALS}'},
                status_code=400)
        out = monitor.enable(_monitor_store(), body.url, body.interval)
        await _push(f'[monitor] watching {out["slug"]} ({body.interval})', 'ok')
        return out

    @app.post('/monitor/disable')
    async def monitor_disable(body: TargetRequest):
        out = monitor.disable(_monitor_store(), body.url)
        if 'error' in out:
            return JSONResponse(out, status_code=404)
        await _push(f'[monitor] stopped watching {out["slug"]}', 'wn')
        return out

    async def _run_monitor_due():
        global _active_job
        loop = asyncio.get_event_loop()
        await _push('[monitor] running due scans…')
        try:
            def on_event(ev):
                asyncio.run_coroutine_threadsafe(
                    _push(_monitor_event_text(ev),
                          'er' if 'error' in ev.get('type', '') else 'info'),
                    loop)

            results = await loop.run_in_executor(
                None, lambda: monitor.run_due(_monitor_store(), on_event=on_event))
            await _push(f'[monitor] ran {len(results)} due project(s)', 'ok',
                        'result', {'ran': len(results)})
        except Exception as e:
            await _push(f'[monitor] error: {e}', 'er', 'error')
        finally:
            _active_job = None

    @app.post('/monitor/run')
    async def monitor_run(bg: BackgroundTasks):
        global _active_job
        busy = _check_busy()
        if busy:
            return busy
        _active_job = 'monitor:run'
        bg.add_task(_run_monitor_due)
        return {'status': 'started', 'job': 'monitor:run'}

    # ── Alert Center (#9) ────────────────────────────────────────────────

    @app.get('/alerts')
    async def alerts_overview():
        return JSONResponse(_alerts_overview())

    @app.post('/alerts/test')
    async def alerts_test():
        loop = asyncio.get_event_loop()
        out = await loop.run_in_executor(
            None, lambda: alerts.send_test(_alerts_config()))
        if out.get('reason'):
            await _push(f'[alerts] test not sent: {out["reason"]}', 'wn')
            return JSONResponse(out, status_code=400)
        await _push(f'[alerts] test sent to {out["sent"]} channel(s)', 'ok')
        return out

    @app.get('/results')
    async def results():
        return JSONResponse(_job_results)

    @app.get('/history')
    async def history():
        return JSONResponse(_recent_history(100))

    @app.get('/data')
    async def data():
        return JSONResponse(_registry_data(50))

    # ── Findings Management (F1, T1.6) ───────────────────────────────────

    class StatusRequest(BaseModel):
        status: str
        note: Optional[str] = None

    class AssignRequest(BaseModel):
        assignee: str = ''

    class CommentRequest(BaseModel):
        text: str
        author: Optional[str] = None

    @app.get('/findings')
    async def findings(project: Optional[str] = None,
                       status: Optional[str] = None,
                       severity: Optional[str] = None):
        return JSONResponse(_findings_list(project, status, severity))

    @app.get('/findings.sarif')
    async def findings_sarif_route(project: Optional[str] = None):
        return Response(_findings_sarif(project),
                        media_type='application/sarif+json')

    @app.get('/report.md')
    async def report_md_route(project: Optional[str] = None):
        return Response(_report_markdown_view(project),
                        media_type='text/markdown; charset=utf-8')

    @app.post('/findings/{finding_id}/status')
    async def findings_set_status(finding_id: str, body: StatusRequest):
        out = _findings_set_status(finding_id, body.status, body.note)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[findings] {finding_id[:8]} → {body.status}', 'ok')
        return out

    @app.get('/findings/{finding_id}/triage')
    async def finding_triage(finding_id: str):
        out = _finding_triage(finding_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.post('/findings/{finding_id}/assign')
    async def finding_assign(finding_id: str, body: AssignRequest):
        out = _finding_assign(finding_id, body.assignee)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[findings] {finding_id[:8]} assigned → '
                    f'{out["assignee"] or "—"}', 'ok')
        return out

    @app.post('/findings/{finding_id}/comment')
    async def finding_comment(finding_id: str, body: CommentRequest):
        out = _finding_comment(finding_id, body.text, body.author)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[findings] {finding_id[:8]} commented', 'ok')
        return out

    @app.get('/assets')
    async def assets(project: Optional[str] = None,
                     type: Optional[str] = None,
                     status: Optional[str] = None):
        return JSONResponse(_assets_list(project, type, status))

    @app.get('/overview')
    async def overview():
        return JSONResponse(_overview_summary())

    # ── Company / Workspace tier (F-C4) ──────────────────────────────────
    class CompanyRequest(BaseModel):
        name: Optional[str] = None        # empty/absent → unassign

    @app.get('/companies')
    async def companies():
        return JSONResponse(_company_view())

    @app.post('/projects/{slug}/company')
    async def project_set_company(slug: str, body: CompanyRequest):
        out = _company_assign(slug, body.name)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[company] {slug} → {body.name or "Unassigned"}', 'ok')
        return out

    @app.get('/correlation')
    async def correlation(project: Optional[str] = None):
        return JSONResponse(_correlation_view(project))

    @app.get('/timeline')
    async def timeline(project: Optional[str] = None):
        return JSONResponse(_timeline_view(project))

    @app.get('/tool-runs.csv')
    async def tool_runs_csv_route(project: Optional[str] = None):
        from core.report_export import tool_runs_csv
        tl = _timeline_view(project)
        return Response(tool_runs_csv(tl.get('tool_runs') or []),
                        media_type='text/csv; charset=utf-8')

    @app.get('/retest-runs.csv')
    async def retest_runs_csv_route(project: Optional[str] = None):
        from core.report_export import retest_runs_csv
        tl = _timeline_view(project)
        return Response(retest_runs_csv(tl.get('retest_runs') or []),
                        media_type='text/csv; charset=utf-8')

    @app.get('/audit-runs')
    async def audit_runs(project: Optional[str] = None):
        return JSONResponse(_audit_runs_list(project))

    @app.get('/audit-runs/{run_id}')
    async def audit_run(run_id: str):
        out = _audit_run_view(run_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.get('/audit-compare')
    async def audit_compare(baseline: str, candidate: str):
        out = _audit_compare_view(baseline, candidate)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    class MissionRequest(BaseModel):
        project: str
        objective: str
        template: Optional[str] = None
        roe: Optional[dict] = None
        allowed_actions: Optional[list] = None

    @app.get('/missions')
    async def missions(project: Optional[str] = None):
        return JSONResponse(_missions_list(project))

    @app.get('/missions/overview')
    async def missions_overview(project: Optional[str] = None):
        return JSONResponse(_missions_overview(project))

    @app.get('/missions.csv')
    async def missions_csv_route(project: Optional[str] = None):
        return Response(_missions_csv(project), media_type='text/csv; charset=utf-8')

    @app.post('/missions')
    async def mission_create(body: MissionRequest):
        out = _mission_create(body.project, body.objective, template=body.template,
                              roe=body.roe, allowed_actions=body.allowed_actions)
        if 'error' in out:
            return JSONResponse(out, status_code=400)
        await _push(f'[mission] created {out["mission_id"][:16]}', 'ok')
        return out

    class ScheduleRequest(BaseModel):
        interval: str = 'weekly'
        enabled: bool = True

    class MissionToolRequest(BaseModel):
        tool: str
        evidence: Optional[dict] = None
        from_scan: bool = False
        scan_id: Optional[str] = None

    @app.post('/missions/run-due')
    async def missions_run_due():
        out = _missions_run_due()
        ran = len(out.get('results') or [])
        await _push(f'[mission] ran {ran} due mission(s)', 'ok')
        return out

    @app.post('/missions/{mission_id}/schedule')
    async def mission_schedule(mission_id: str, body: ScheduleRequest):
        out = _mission_set_schedule(mission_id, body.interval, body.enabled)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[mission] schedule {mission_id[:8]} → '
                    f'{body.interval if body.enabled else "disabled"}', 'ok')
        return out

    @app.get('/missions/{mission_id}')
    async def mission(mission_id: str):
        out = _mission_view(mission_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.post('/missions/{mission_id}/run')
    async def mission_run(mission_id: str):
        out = _mission_run(mission_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[mission] {mission_id[:8]} ran → {out["run_id"]}', 'ok')
        return out

    @app.post('/missions/{mission_id}/tools/run')
    async def mission_tool_run(mission_id: str, body: MissionToolRequest):
        out = _mission_run_tool(mission_id, body.tool, body.evidence,
                                from_scan=body.from_scan, scan_id_src=body.scan_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[mission] {mission_id[:8]} tool {out["tool"]} → '
                    f'{out["status"]}', 'ok')
        return out

    @app.post('/missions/{mission_id}/links/prune')
    async def mission_prune_links(mission_id: str):
        out = _mission_prune_links(mission_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        removed = len(out['removed_runs']) + len(out['removed_findings'])
        await _push(f'[mission] {mission_id[:8]} pruned {removed} stale link(s)', 'ok')
        return out

    @app.get('/missions/{mission_id}/runs')
    async def mission_runs(mission_id: str):
        out = _mission_runs(mission_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.get('/missions/{mission_id}/report')
    async def mission_report_json(mission_id: str):
        out = _mission_report(mission_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.get('/missions/{mission_id}/report.md')
    async def mission_report_md(mission_id: str):
        from core import mission_report as _mr
        out = _mission_report(mission_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return Response(out['error'], media_type='text/plain; charset=utf-8',
                            status_code=code)
        return Response(_mr.render_markdown(out['report']),
                        media_type='text/markdown; charset=utf-8')

    # ── Engagements ──────────────────────────────────────────────────────
    class EngagementRequest(BaseModel):
        client: str
        project: str
        scope: Optional[dict] = None
        roe: Optional[dict] = None
        authorization: Optional[dict] = None

    class EngagementAdvanceRequest(BaseModel):
        status: str

    class EngagementLinkRequest(BaseModel):
        kind: str          # mission | audit_run | finding
        ref_id: str

    class EngagementMissionRequest(BaseModel):
        objective: str
        allowed_actions: Optional[list] = None

    @app.get('/engagements')
    async def engagements(project: Optional[str] = None):
        return JSONResponse(_engagements_list(project))

    @app.get('/engagements/overview')
    async def engagements_overview(project: Optional[str] = None):
        return JSONResponse(_engagements_overview(project))

    @app.get('/engagements.csv')
    async def engagements_csv_route(project: Optional[str] = None):
        return Response(_engagements_csv(project),
                        media_type='text/csv; charset=utf-8')

    @app.post('/engagements')
    async def engagement_create(body: EngagementRequest):
        out = _engagement_create(body.client, body.project, scope=body.scope,
                                 roe=body.roe, authorization=body.authorization)
        if 'error' in out:
            return JSONResponse(out, status_code=400)
        await _push(f'[engagement] created {out["engagement_id"][:16]}', 'ok')
        return out

    @app.get('/engagements/{engagement_id}')
    async def engagement(engagement_id: str):
        out = _engagement_view(engagement_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.post('/engagements/{engagement_id}/advance')
    async def engagement_advance(engagement_id: str,
                                 body: EngagementAdvanceRequest):
        out = _engagement_advance(engagement_id, body.status)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[engagement] {engagement_id[:8]} → {out["status"]}', 'ok')
        return out

    @app.post('/engagements/{engagement_id}/link')
    async def engagement_link(engagement_id: str, body: EngagementLinkRequest):
        out = _engagement_link(engagement_id, body.kind, body.ref_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[engagement] {engagement_id[:8]} linked '
                    f'{body.kind} {body.ref_id}', 'ok')
        return out

    @app.post('/engagements/{engagement_id}/links/prune')
    async def engagement_prune_links(engagement_id: str):
        out = _engagement_prune_links(engagement_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        removed = (len(out['removed_missions']) + len(out['removed_runs'])
                   + len(out['removed_findings']))
        await _push(f'[engagement] {engagement_id[:8]} pruned {removed} stale', 'ok')
        return out

    @app.get('/engagements/{engagement_id}/report')
    async def engagement_report_json(engagement_id: str):
        out = _engagement_report(engagement_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.get('/engagements/{engagement_id}/report.md')
    async def engagement_report_md(engagement_id: str):
        from core import engagement_report as _er
        out = _engagement_report(engagement_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return Response(out['error'], media_type='text/plain; charset=utf-8',
                            status_code=code)
        return Response(_er.render_markdown(out['report']),
                        media_type='text/markdown; charset=utf-8')

    @app.get('/engagements/{engagement_id}/retest')
    async def engagement_retest(engagement_id: str):
        out = _engagement_retest(engagement_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.post('/engagements/{engagement_id}/missions')
    async def engagement_create_mission(engagement_id: str,
                                        body: EngagementMissionRequest):
        out = _engagement_create_mission(engagement_id, body.objective,
                                         body.allowed_actions)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[engagement] {engagement_id[:8]} → mission '
                    f'{out["mission_id"][:16]}', 'ok')
        return out

    @app.post('/engagements/{engagement_id}/retest/run')
    async def engagement_retest_run_route(engagement_id: str):
        out = _engagement_retest_run(engagement_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[retest] {engagement_id[:8]} → '
                    f'{out["retest_run_id"][:16]}', 'ok')
        return out

    @app.get('/engagements/{engagement_id}/retest-runs')
    async def engagement_retest_runs_route(engagement_id: str):
        return JSONResponse(_engagement_retest_runs(engagement_id))

    @app.get('/retest-runs/{run_id}')
    async def retest_run_view_route(run_id: str):
        out = _retest_run_view(run_id)
        code = 404 if out.get('error') and 'not found' in out['error'] else 200
        return JSONResponse(out, status_code=code)

    @app.get('/retest-runs/{run_id}/report.md')
    async def retest_run_report_md(run_id: str):
        from core import retest_run as _rr
        out = _retest_run_view(run_id)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return Response(out['error'], media_type='text/plain; charset=utf-8',
                            status_code=code)
        return Response(_rr.render_markdown(out['retest_run']),
                        media_type='text/markdown; charset=utf-8')

    @app.get('/intelligence')
    async def intelligence(project: Optional[str] = None):
        return JSONResponse(_intelligence_view(project))

    @app.get('/criticality')
    async def criticality(project: Optional[str] = None):
        return JSONResponse(_criticality_view(project))

    @app.get('/attack-paths')
    async def attack_paths(project: Optional[str] = None):
        return JSONResponse(_attack_paths_view(project))

    @app.get('/remediation')
    async def remediation(project: Optional[str] = None):
        return JSONResponse(_remediation_view(project))

    @app.get('/exposure')
    async def exposure(project: Optional[str] = None):
        return JSONResponse(_exposure_view(project))

    @app.get('/related-assets')
    async def related_assets(project: Optional[str] = None):
        return JSONResponse(_related_assets_view(project))

    @app.get('/accuracy')
    async def accuracy(project: Optional[str] = None):
        return JSONResponse(_accuracy_view(project))

    @app.get('/technology-risk')
    async def technology_risk(project: Optional[str] = None):
        return JSONResponse(_technology_risk_view(project))

    @app.get('/osint-catalog')
    async def osint_catalog(project: Optional[str] = None):
        return JSONResponse(_osint_catalog_view(project))

    @app.get('/report')
    async def report(file: str):
        path = _safe_report_path(file)
        if path is None:
            return JSONResponse({'error': 'report not found'}, status_code=404)
        return FileResponse(str(path), media_type='text/html')

else:
    # Stub so import never crashes even without fastapi installed
    class _StubApp:
        def get(self, *a, **kw): return lambda f: f
        def post(self, *a, **kw): return lambda f: f
    app = _StubApp()  # type: ignore


# ── Local network URL helper ──────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def print_access_url(port: int = 5000):
    ip = get_local_ip()
    print('\n  Advanced Site Analyzer — Web Console')
    print(f'  Local   : http://localhost:{port}')
    print(f'  Network : http://{ip}:{port}  (phone / tablet on same Wi-Fi)')
    print()


def resolve_web_console(host: Optional[str] = None) -> tuple:
    """Resolve (host, token) for the console from settings / env / explicit host.

    Safe by default: host is loopback unless ``web_console.allow_lan`` (or an
    explicit non-loopback ``host``) opts into a LAN bind. The token comes from
    ``ASA_WEB_TOKEN`` or ``web_console.token``; a LAN bind with no token gets a
    generated one so the console is never reachable from the LAN unauthenticated.
    Loopback with no token stays open (single-user desktop)."""
    cfg = load_settings().get('web_console') or {}
    if host is None:
        host = '0.0.0.0' if cfg.get('allow_lan') else str(cfg.get('host') or '127.0.0.1')
    token = (os.environ.get('ASA_WEB_TOKEN') or str(cfg.get('token') or '')).strip()
    if not token and not _is_loopback(host):
        token = secrets.token_urlsafe(24)
        print('\n  [web] LAN bind without a configured token — generated one:')
        print(f'  [web]   token: {token}')
        print('  [web] Send it as "Authorization: Bearer <token>" or ?token=<token>.\n')
    return host, token


def start_server(host: Optional[str] = None, port: int = 5000,
                 log_level: str = 'warning'):
    if not _FASTAPI_OK:
        print('[web] fastapi/uvicorn not installed.')
        print('[web] Run: pip install fastapi "uvicorn[standard]"')
        return
    global _AUTH_TOKEN
    host, _AUTH_TOKEN = resolve_web_console(host)
    print(f"  [web] bind: {host}:{port}  ·  auth: "
          f"{'token required' if _AUTH_TOKEN else 'none (loopback)'}")
    print_access_url(port)
    uvicorn.run(app, host=host, port=port, log_level=log_level)


if __name__ == '__main__':
    start_server()
