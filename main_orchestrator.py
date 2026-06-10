#!/usr/bin/env python3
"""
main_orchestrator.py
Unified pipeline: Recon -> Paywall Bypass -> Capture -> Dynamic Analysis

Usage:
    python main_orchestrator.py https://example.com
    python main_orchestrator.py https://example.com --dynamic --paywall --web
    python main_orchestrator.py https://example.com --max-pages 10 --output ~/reports
"""

import argparse
import json
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

from core.api_dumper import ApiDumper
from core.config import OPERATIONS_DB
from core.content_capture import SiteContentCapture
from core.dynamic_analyzer import DynamicAnalyzer
from core.paywall_bypass import PaywallBypass
from core.recon_engine import ReconEngine
from core.vuln_scanner import VulnScanner

from utils import OperationRegistry


# ── Helpers ───────────────────────────────────────────────────────────────────

def domain_slug(url: str) -> str:
    netloc = urlparse(url).netloc
    domain = re.sub(r'^www\.', '', netloc)
    return re.sub(r'[^\w.-]', '_', domain) or 'site'


def section(title: str, width: int = 62):
    bar = '=' * width
    print(f'\n{bar}')
    print(f'  {title}')
    print(bar)


def progress(msg: str):
    print(f'  {msg}')


def run_phase(registry: OperationRegistry, url: str, phase: str,
              base_dir: Path, fn):
    """Execute a pipeline phase while recording its lifecycle in the registry.

    Logs a 'running' row on entry, marks 'success' on return, and 'failed'
    (with the exception text) before re-raising so existing control flow is
    preserved.
    """
    op_id = registry.start(target=url, phase=phase, output_dir=str(base_dir))
    try:
        result = fn()
        registry.finish(op_id, status='success')
        return result
    except Exception as e:
        registry.finish(op_id, status='failed', error=str(e))
        raise


# ── Pipeline phases ───────────────────────────────────────────────────────────

def phase_recon(url: str, base_dir: Path) -> dict:
    section('Phase 1: Reconnaissance')
    engine = ReconEngine()
    engine.configure(output_dir=str(base_dir / 'recon'))
    result = engine.run_recon(url)

    if result.get('status') == 'Success':
        if result.get('ip'):
            print(f'  IP        : {result["ip"]}')
        geo = result.get('geo', {})
        if geo.get('country'):
            print(f'  Location  : {geo.get("city","?")}, {geo["country"]}')
            print(f'  ISP / AS  : {geo.get("isp","")}  {geo.get("as","")}')
        cms = result.get('cms', [])
        print(f'  CMS/Stack : {", ".join(cms) if cms else "unknown"}')
        icons = result.get('favicons', [])
        print(f'  Favicons  : {len(icons)} found')
        manifest = result.get('pwa_manifest', {})
        if manifest:
            name = manifest.get('data', {}).get('name', 'PWA manifest')
            print(f'  Manifest  : {name}')
        hdrs = result.get('server_headers', {})
        if hdrs:
            for k, v in hdrs.items():
                print(f'  {k:<12}: {v}')
    else:
        print(f'  [!] Recon failed: {result.get("error","")}')

    return result


def phase_paywall(url: str, base_dir: Path) -> dict:
    section('Phase 2: Paywall Bypass')
    bypass = PaywallBypass()
    bypass.configure(timeout=25)
    result = bypass.extract(url)

    print(f'  Status   : {result["status"]}')
    print(f'  Strategy : {result["strategy_used"] or "none"}')
    print(f'  Paywalled: {result["paywalled"]}')

    if result.get('html'):
        out = base_dir / 'paywall_content.html'
        out.write_text(result['html'], encoding='utf-8')
        size = len(result['html'].encode('utf-8'))
        print(f'  Saved    : {out.name}  ({size:,} bytes)')

    return {k: v for k, v in result.items() if k != 'html'}


def phase_capture(url: str, base_dir: Path, max_pages: int) -> dict:
    section('Phase 3: Content Capture')
    cap_dir = base_dir / 'capture'
    capturer = SiteContentCapture()
    capturer.configure(url, str(cap_dir), max_pages=max_pages)
    capturer.set_progress_callback(progress)
    result = capturer.run_capture()

    pages = result.get('pages_captured', 0)
    errors = len(result.get('errors', []))
    print(f'  Captured : {pages} pages')
    if errors:
        print(f'  Errors   : {errors} URLs failed')
    if result.get('files'):
        print(f'  Output   : {cap_dir}')

    return result


def phase_dynamic(url: str, base_dir: Path) -> dict:
    section('Phase 4: Dynamic Traffic Analysis')
    analyzer = DynamicAnalyzer()
    analyzer.configure(timeout_ms=25000, wait_ms=3000)
    analyzer.set_progress_callback(progress)
    result = analyzer.analyze_dynamic_traffic(url)

    if result.get('status') == 'Success':
        print(f'  API calls  : {result["total_api_calls"]}')
        print(f'  Unique hosts: {result["unique_hosts"]}')
        print(f'  Auth headers: {len(result["auth_headers"])}')
        print(f'  JSON structs: {len(result["json_structures"])}')

        if result['auth_headers']:
            print('  Auth headers found:')
            for ah in result['auth_headers'][:5]:
                print(f'    {ah["header"]}: {ah["preview"]}  ({ah["url"][:60]})')

        if result['json_structures']:
            print('  Sample JSON keys:')
            for js in result['json_structures'][:3]:
                keys = js.get('top_keys') or js.get('item_keys', [])
                print(f'    {js["url"][-50:]} -> {keys[:8]}')

        # Save full report
        out = base_dir / 'dynamic_report.json'
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding='utf-8',
        )
        print(f'  Report   : {out.name}')
    else:
        print(f'  [!] {result.get("error","")}')

    return result


def phase_vuln_scan(recon: dict, dynamic: dict) -> list:
    section('Phase 5: Vulnerability Scan')
    scanner = VulnScanner()
    findings = scanner.scan(recon, dynamic)

    highs   = [f for f in findings if f['severity'] == 'High']
    mediums = [f for f in findings if f['severity'] == 'Medium']
    infos   = [f for f in findings if f['severity'] == 'Info']
    print(f'  High: {len(highs)}  Medium: {len(mediums)}  Info: {len(infos)}')
    for f in highs:
        print(f'  [HIGH]   {f["title"]}')
        if f.get('detail'):
            print(f'           {f["detail"][:100]}')
    for f in mediums:
        print(f'  [MEDIUM] {f["title"]}')
        if f.get('detail'):
            print(f'           {f["detail"][:100]}')
    for f in infos:
        print(f'  [INFO]   {f["title"]}')

    return findings


def phase_api_dump(dynamic: dict, url: str, base_dir: Path) -> dict:
    section('Phase 6: API Response Dump')
    dumper = ApiDumper()
    dumper.configure(str(base_dir))
    result = dumper.dump(dynamic, url)

    if result.get('status') == 'Success':
        print(f'  Files    : {result["files_written"]}')
        print(f'  Endpoints: {result["endpoint_count"]}')
        print(f'  Output   : {result["output_dir"]}')
    else:
        print(f'  [!] Dump failed: {result.get("error", "")}')

    return result


# ── Web server thread ─────────────────────────────────────────────────────────

def _web_thread():
    try:
        from remote.web_app import start_server
        start_server(log_level='warning')
    except ImportError:
        print('[web] fastapi/uvicorn not installed. '
              'Run: pip install fastapi "uvicorn[standard]"')
    except Exception as e:
        print(f'[web] Server error: {e}')


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Site Analyzer — Unified Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('url', help='Target URL (e.g. https://example.com)')
    parser.add_argument('--dynamic',   action='store_true',
                        help='Run dynamic traffic analysis (requires playwright)')
    parser.add_argument('--paywall',   action='store_true',
                        help='Attempt paywall bypass before capture')
    parser.add_argument('--vulns',     action='store_true',
                        help='Run vulnerability scan on recon + dynamic results')
    parser.add_argument('--dump-api',  action='store_true',
                        help='Dump all captured API responses to disk (requires --dynamic)')
    parser.add_argument('--web',       action='store_true',
                        help='Start web management console on :5000')
    parser.add_argument('--max-pages', type=int, default=20,
                        help='Pages to capture (default: 20)')
    parser.add_argument('--output',    default=None,
                        help='Base output directory (default: ~/SiteAnalyzer)')
    opts = parser.parse_args()

    url = opts.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    base_root = Path(opts.output).expanduser() if opts.output else Path.home() / 'SiteAnalyzer'
    date_str  = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_dir  = base_root / f'{domain_slug(url)}_{date_str}'
    base_dir.mkdir(parents=True, exist_ok=True)

    print(f'\n  Target : {url}')
    print(f'  Output : {base_dir}')

    # Start web console in background if requested
    if opts.web:
        t = threading.Thread(target=_web_thread, daemon=True)
        t.start()
        time.sleep(1.5)   # let uvicorn bind the port

    pipeline: dict = {
        'url':         url,
        'started_at':  datetime.now().isoformat(),
        'output_dir':  str(base_dir),
        'phases':      {},
    }

    # Operation history is persisted to the canonical operations DB.
    registry = OperationRegistry(db_path=str(OPERATIONS_DB))

    try:
        # ── 1. Recon (always) ────────────────────────────────────────────
        pipeline['phases']['recon'] = run_phase(
            registry, url, 'recon', base_dir,
            lambda: phase_recon(url, base_dir),
        )

        # ── 2. Paywall bypass (optional) ─────────────────────────────────
        if opts.paywall:
            pipeline['phases']['paywall'] = run_phase(
                registry, url, 'paywall', base_dir,
                lambda: phase_paywall(url, base_dir),
            )

        # ── 3. Capture (always) ──────────────────────────────────────────
        pipeline['phases']['capture'] = run_phase(
            registry, url, 'capture', base_dir,
            lambda: phase_capture(url, base_dir, opts.max_pages),
        )

        # ── 4. Dynamic analysis (optional) ───────────────────────────────
        if opts.dynamic:
            pipeline['phases']['dynamic'] = run_phase(
                registry, url, 'dynamic', base_dir,
                lambda: phase_dynamic(url, base_dir),
            )

        # ── 5. Vulnerability scan (optional) ─────────────────────────────
        if opts.vulns:
            pipeline['phases']['vulns'] = run_phase(
                registry, url, 'vulns', base_dir,
                lambda: phase_vuln_scan(
                    pipeline['phases'].get('recon', {}),
                    pipeline['phases'].get('dynamic', {}),
                ),
            )

        # ── 6. API response dump (optional) ──────────────────────────────
        if opts.dump_api:
            dyn = pipeline['phases'].get('dynamic', {})
            if dyn.get('status') == 'Success':
                pipeline['phases']['api_dump'] = run_phase(
                    registry, url, 'api_dump', base_dir,
                    lambda: phase_api_dump(dyn, url, base_dir),
                )
            else:
                print('  [!] --dump-api requires --dynamic to have succeeded')

    except KeyboardInterrupt:
        print('\n  [!] Interrupted by user')

    # ── Save pipeline summary ─────────────────────────────────────────────────
    pipeline['finished_at'] = datetime.now().isoformat()
    summary = base_dir / 'pipeline_summary.json'
    summary.write_text(
        json.dumps(pipeline, indent=2, ensure_ascii=False, default=str),
        encoding='utf-8',
    )

    section('Done')
    print(f'  Output : {base_dir}')
    print(f'  Summary: {summary.name}')
    print()

    if opts.web:
        print('  Web console running. Press Ctrl+C to stop.')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
