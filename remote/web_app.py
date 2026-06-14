"""
remote/web_app.py
Local Wi-Fi management console for Advanced Site Analyzer.
Exposes http://0.0.0.0:5000 — accessible from any device on the LAN.

Requires:  pip install fastapi uvicorn[standard]
Run alone: python remote/web_app.py
"""

import asyncio
import json
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
    from fastapi import BackgroundTasks, FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import (
        FileResponse, HTMLResponse, JSONResponse, StreamingResponse,
    )
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False

from core import alerts, monitor
from core.api_key_extractor import ApiKeyExtractor
from core.collection_runner import CollectionRunner
from core.config import OPERATIONS_DB, REGISTRY_DB, load_settings
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
from utils.image_processor import ImageExtractor
from utils.operation_registry import OperationRegistry
from utils.video_processor import VideoDownloader

# Reports/output live under here; report serving is restricted to this tree.
_REPORT_BASE = (Path.home() / 'SiteAnalyzer').resolve()

# ── Global state ──────────────────────────────────────────────────────────────
_log_queue: asyncio.Queue = asyncio.Queue()
_job_results: Dict[str, dict] = {}
_active_job: Optional[str] = None
# The currently running job's cancellable engine, if it exposes ``cancel()``
# (e.g. a CollectionRunner). Long jobs register one so /cancel can stop them.
_active_cancellable: Optional[object] = None


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
    await _log_queue.put(payload)


# ── Job registry ──────────────────────────────────────────────────────────────
# One synchronous runner per GUI-equivalent feature. Each takes (url, push) and
# returns a result dict; ``push(msg, level)`` streams progress to the console.
# JOBS is the single source of truth for what the console can do (mirrors the
# GUI tabs) and is introspectable via the /jobs endpoint.

def _out_dir(url: str, suffix: str) -> Path:
    domain = urlparse(url if '://' in url else 'https://' + url).netloc.replace('www.', '') or 'site'
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Path.home() / 'SiteAnalyzer' / f'{domain}_{stamp}_{suffix}'


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


def _run_images(url: str, push: Callable) -> dict:
    out = _out_dir(url, 'images')
    ex = ImageExtractor()
    ex.set_progress_callback(lambda m: push(m))
    result = ex.extract_images(url, str(out))
    result['output_dir'] = str(out)
    return result


def _run_video(url: str, push: Callable) -> dict:
    out = _out_dir(url, 'video')
    dl = VideoDownloader()   # default preset 'best'; degrades if yt-dlp absent
    dl.set_progress_callback(lambda m: push(m))
    result = dl.download_video(url, str(out))
    result['output_dir'] = str(out)
    return result


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
    res = runner.run(url, str(Path.home() / 'SiteAnalyzer'))
    # Compact summary (full per-phase data is on disk in report.json).
    return {
        'status': res.get('status'),
        'project_dir': res.get('project_dir'),
        'report_html': res.get('report_html'),
        'phases': {k: v.get('status') for k, v in res.get('phases', {}).items()},
    }


def _run_scandiff(url: str, push: Callable) -> dict:
    """Diff the two most recent scans of the target's project (Scan Diff / P8).

    The job framework hands a single URL, so this defaults to the most useful
    comparison — previous scan vs latest — for that project. Needs at least two
    scans; otherwise it reports cleanly rather than failing."""
    store = ProjectStore(Path.home() / 'SiteAnalyzer')
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
    'images':     {'label': 'Images',          'fn': _run_images},
    'video':      {'label': 'Video Download',  'fn': _run_video},
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
        store = FindingsStore()
        return {'projects': store.projects(),
                'findings': store.list_findings(project=project, status=status,
                                                severity=severity),
                'summary': store.summary(project)}
    except Exception as e:
        return {'projects': [], 'findings': [], 'summary': {}, 'error': str(e)}


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


# ── Continuous Monitoring (#8) ─────────────────────────────────────────────────
# Thin wrappers over core.monitor (single source of truth, shared with the CLI
# and GUI). All bound to the same project store the jobs use.

def _monitor_store() -> ProjectStore:
    return ProjectStore(Path.home() / 'SiteAnalyzer')


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
  es=new EventSource('/events');
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
      log('#'+o.id+' '+o.phase+' ['+o.status+'] '+(o.target||''),
          o.status==='failed'?'er':(o.status==='success'?'ok':'info'));
    });
  }catch(ex){log('History failed: '+ex.message,'er');}
}

async function showData(){
  try{
    const r=await fetch('/data'); const d=await r.json();
    const s=d.summary||{};
    log('Registry: '+(s.total||0)+' records · '+(s.subdomains||0)+' subdomains · '
        +(s.api_endpoints||0)+' endpoints · '+(s.images||0)+' images','data');
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
        +' · active findings: '+(t.active_findings||0),'data');
    (d.rows||[]).slice(0,20).forEach(p=>{
      const d2=(p.risk_delta==null)?'':(p.risk_delta>0?' ▲':(p.risk_delta<0?' ▼':''));
      log('  '+p.slug+' — '+(p.risk_level||'—')
          +' ('+(p.risk_score==null?'?':p.risk_score)+')'+d2
          +' · findings: '+(p.active_findings||0),'info');
    });
  }catch(ex){log('Overview failed: '+ex.message,'er');}
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
    app = FastAPI(title='Advanced Site Analyzer', docs_url=None, redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_methods=['*'],
        allow_headers=['*'],
    )

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
            _job_results[job_id] = compact
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

    @app.get('/findings')
    async def findings(project: Optional[str] = None,
                       status: Optional[str] = None,
                       severity: Optional[str] = None):
        return JSONResponse(_findings_list(project, status, severity))

    @app.post('/findings/{finding_id}/status')
    async def findings_set_status(finding_id: str, body: StatusRequest):
        out = _findings_set_status(finding_id, body.status, body.note)
        if 'error' in out:
            code = 404 if 'not found' in out['error'] else 400
            return JSONResponse(out, status_code=code)
        await _push(f'[findings] {finding_id[:8]} → {body.status}', 'ok')
        return out

    @app.get('/assets')
    async def assets(project: Optional[str] = None,
                     type: Optional[str] = None,
                     status: Optional[str] = None):
        return JSONResponse(_assets_list(project, type, status))

    @app.get('/overview')
    async def overview():
        return JSONResponse(_overview_summary())

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


def start_server(host: str = '0.0.0.0', port: int = 5000, log_level: str = 'warning'):
    if not _FASTAPI_OK:
        print('[web] fastapi/uvicorn not installed.')
        print('[web] Run: pip install fastapi "uvicorn[standard]"')
        return
    print_access_url(port)
    uvicorn.run(app, host=host, port=port, log_level=log_level)


if __name__ == '__main__':
    start_server()
