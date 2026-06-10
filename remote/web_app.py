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
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import uvicorn
    from fastapi import BackgroundTasks, FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False

from core.api_key_extractor import ApiKeyExtractor
from core.collection_runner import CollectionRunner
from core.content_capture import SiteContentCapture
from core.cookie_auditor import CookieAuditor
from core.paywall_bypass import PaywallBypass
from core.recon_engine import ReconEngine
from core.subdomain_scanner import SubdomainScanner

# ── Global state ──────────────────────────────────────────────────────────────
_log_queue: asyncio.Queue = asyncio.Queue()
_job_results: Dict[str, dict] = {}
_active_job: Optional[str] = None


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


def _run_collection(url: str, push: Callable) -> dict:
    runner = CollectionRunner(max_pages=20)
    runner.set_progress_callback(lambda m: push(m))
    res = runner.run(url, str(Path.home() / 'SiteAnalyzer'))
    # Compact summary (full per-phase data is on disk in report.json).
    return {
        'status': res.get('status'),
        'project_dir': res.get('project_dir'),
        'report_html': res.get('report_html'),
        'phases': {k: v.get('status') for k, v in res.get('phases', {}).items()},
    }


JOBS: Dict[str, dict] = {
    'recon':      {'label': 'Recon',           'fn': _run_recon},
    'subdomain':  {'label': 'Subdomains',      'fn': _run_subdomain},
    'apikeys':    {'label': 'API Keys',        'fn': _run_apikeys},
    'capture':    {'label': 'Capture',         'fn': _run_capture},
    'paywall':    {'label': 'Bypass Paywall',  'fn': _run_paywall},
    'cookies':    {'label': 'Cookie Audit',    'fn': _run_cookies},
    'collection': {'label': 'Full Collection', 'fn': _run_collection},
}

_HEAVY_KEYS = ('html', 'reader_view', 'body')


def _strip_heavy(result) -> dict:
    """Drop large payloads before sending a result to the browser."""
    if not isinstance(result, dict):
        return {'result': result}
    out = {k: v for k, v in result.items() if k not in _HEAVY_KEYS}
    if isinstance(result.get('html'), str):
        out['html_size'] = len(result['html'])
    return out


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
.btn{background:var(--ac);color:#0d1117;border:none;border-radius:6px;
padding:7px 14px;font-size:.85rem;font-weight:600;cursor:pointer;
white-space:nowrap;transition:opacity .15s}
.btn:hover{opacity:.82}.btn:disabled{opacity:.38;cursor:not-allowed}
.btn.sec{background:var(--sf);color:var(--tx);border:1px solid var(--br)}
.btn.ok{background:var(--ok)}.btn.er{background:var(--er)}
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
      <button class="btn er" id="b-clr" onclick="clr()">Clear</button>
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

function setBusy(v){
  document.querySelectorAll('#jobbtns .btn.sec').forEach(b=>{b.disabled=v;});
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
  if(data.assets_downloaded!==undefined) rows.push(['Assets',data.assets_downloaded]);
  if(data.strategy_used) rows.push(['Strategy',data.strategy_used]);
  if(data.html_size!==undefined) rows.push(['HTML size',(data.html_size/1024).toFixed(1)+' KB']);
  if(data.keys_found!==undefined) rows.push(['Keys found',data.keys_found]);
  if(data.total!==undefined) rows.push(['Total',data.total]);
  if(data.live_count!==undefined) rows.push(['Live',data.live_count]);
  if(data.weak!==undefined) rows.push(['Weak cookies',data.weak]);
  if(data.takeover_candidates&&data.takeover_candidates.length) rows.push(['Takeovers',data.takeover_candidates.length]);
  if(data.report_html) rows.push(['Report',data.report_html]);
  rows.forEach(([l,v])=>{
    mg.innerHTML+=`<div class="met"><div class="mlb">${l}</div><div class="mvl">${v}</div></div>`;
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
      else if(d.type==='result'){log(d.message,'ok');if(d.data)metrics(d.data);}
      else if(d.type==='error') log(d.message,'er');
    }catch(ex){}
  };
}

async function go(name){
  const url=document.getElementById('url').value.trim();
  if(!url){log('Enter a URL first','wn');return;}
  setBusy(true);
  log('Sending '+name+' request for: '+url,'data');
  try{
    const r=await fetch('/run/'+name,{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url})});
    const d=await r.json();
    if(d.error) log(d.error,'er');
    else log('Job started: '+d.job_id,'ok');
  }catch(ex){log('Request failed: '+ex.message,'er');}
  setTimeout(()=>setBusy(false),1500);
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
        global _active_job
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

    @app.get('/results')
    async def results():
        return JSONResponse(_job_results)

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
    print(f'\n  Advanced Site Analyzer — Web Console')
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
