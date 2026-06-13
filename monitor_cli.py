#!/usr/bin/env python3
"""monitor_cli.py
Command-line surface for Continuous Monitoring (roadmap Phase 8).

Manage a target's watch schedule and run due scans. The console stays a thin
caller (I4): every command delegates to ``core.monitor`` / ``core.project``;
the functions below return plain data so they are unit-testable, and ``main``
only formats and prints.

    python monitor_cli.py enable  https://example.com --interval daily
    python monitor_cli.py disable https://example.com
    python monitor_cli.py status                       # every watched project
    python monitor_cli.py run                          # run all due now (once)
    python monitor_cli.py watch  --every 3600          # scheduler loop (blocks)
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core import alerts, monitor
from core.config import load_settings
from core.project import ProjectStore

DEFAULT_BASE = Path.home() / 'SiteAnalyzer'


def _alert_config():
    """Alert Center config from settings.json (None when disabled/absent)."""
    cfg = load_settings().get('alerts')
    return cfg if isinstance(cfg, dict) and cfg.get('enabled') else None


# ── command functions (thin wrappers over core.monitor: take a store) ─────────

def cmd_enable(store: ProjectStore, url: str, interval: str) -> dict:
    """Turn monitoring on for ``url`` at ``interval`` (creates the project)."""
    return monitor.enable(store, url, interval)


def cmd_disable(store: ProjectStore, url: str) -> dict:
    """Turn monitoring off for ``url`` (keeps the schedule but disabled)."""
    return monitor.disable(store, url)


def cmd_status(store: ProjectStore) -> list:
    """Every monitored project's schedule, for display."""
    return monitor.status(store)


def cmd_run(store: ProjectStore, on_event=None, alert_config=None) -> list:
    """Run every due project once, now (firing alerts if configured)."""
    return monitor.run_due(store, on_event=on_event, alert_config=alert_config)


# ── pretty printing ───────────────────────────────────────────────────────────

def _print_event(ev: dict) -> None:
    kind = ev.get('type')
    slug = ev.get('slug', '')
    if kind == 'scan_start':
        print(f'  [{slug}] scan start ({ev.get("url", "")})')
    elif kind == 'diff':
        print(f'  [{slug}] diff: {ev.get("line", "")}')
    elif kind == 'alerts':
        print(f'  [{slug}] alerts: {ev.get("alerts")} change(s), '
              f'sent {ev.get("sent")}'
              + (f' ({ev.get("reason")})' if ev.get('reason') else ''))
    elif kind == 'scan_done':
        line = ev.get('diff_line')
        print(f'  [{slug}] done — scan {ev.get("scan_id")}'
              + (f' · {line}' if line else ' (first scan, no diff)'))
    elif kind in ('error', 'diff_error'):
        print(f'  [{slug}] {kind}: {ev.get("error", "")}')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Advanced Site Analyzer — Continuous Monitoring')
    parser.add_argument('--output', default=None,
                        help='Base output directory (default: ~/SiteAnalyzer)')
    sub = parser.add_subparsers(dest='command', required=True)

    p_en = sub.add_parser('enable', help='Start monitoring a target')
    p_en.add_argument('url')
    p_en.add_argument('--interval', default='daily', choices=monitor.INTERVALS)

    p_dis = sub.add_parser('disable', help='Stop monitoring a target')
    p_dis.add_argument('url')

    sub.add_parser('status', help='Show every watched project')
    sub.add_parser('run', help='Run all due scans once, now')
    sub.add_parser('test-alert', help='Send a test alert to configured channels')

    p_watch = sub.add_parser('watch', help='Run the scheduler loop (blocks)')
    p_watch.add_argument('--every', type=float, default=3600.0,
                         help='Seconds between checks (default: 3600)')

    opts = parser.parse_args(argv)

    # Diff lines carry '→' and Russian text; a legacy Windows console (cp1251)
    # would otherwise raise UnicodeEncodeError mid-watch. Degrade unencodable
    # glyphs instead of crashing the loop.
    try:
        sys.stdout.reconfigure(errors='replace')   # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

    base = Path(opts.output).expanduser() if opts.output else DEFAULT_BASE
    store = ProjectStore(base)

    if opts.command == 'enable':
        out = cmd_enable(store, opts.url, opts.interval)
        print(f'Monitoring {out["slug"]} every {opts.interval}. '
              f'First run due: {out["schedule"]["next_run"]}')
    elif opts.command == 'disable':
        out = cmd_disable(store, opts.url)
        print(out.get('error') or f'Monitoring disabled for {out["slug"]}')
    elif opts.command == 'status':
        rows = cmd_status(store)
        if not rows:
            print('No monitored projects.')
        for r in rows:
            state = 'on ' if r['enabled'] else 'off'
            print(f'  [{state}] {r["slug"]:<28} {r["interval"]:<8} '
                  f'next: {r["next_run"] or "—"}  last: {r["last_run"] or "—"}')
    elif opts.command == 'run':
        results = cmd_run(store, on_event=_print_event,
                          alert_config=_alert_config())
        print(f'Ran {len(results)} due project(s).')
    elif opts.command == 'test-alert':
        cfg = load_settings().get('alerts')
        out = alerts.send_test(cfg if isinstance(cfg, dict) else None)
        if out.get('reason'):
            print(f'No alert sent: {out["reason"]} '
                  f'(configure "alerts" in settings.json).')
        else:
            print(f'Test alert sent to {out["sent"]} channel(s).')
            for r in out.get('results', []):
                print(f'  {r.get("channel")}: {r.get("status")}'
                      + (f' — {r["error"]}' if r.get('error') else ''))
    elif opts.command == 'watch':
        sched = monitor.MonitorScheduler(store, check_interval=opts.every,
                                         on_event=_print_event,
                                         alert_config=_alert_config())
        print(f'Monitoring scheduler started (check every {opts.every:.0f}s). '
              f'Press Ctrl+C to stop.')
        sched.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('\nStopping…')
            sched.stop()


if __name__ == '__main__':
    main()
