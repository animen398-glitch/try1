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

from core import alerts, ci_gate, monitor
from core.cli_common import configure_stdout, run_main
from core.config import DEFAULT_SETTINGS, load_settings
from core.project import ProjectStore

DEFAULT_BASE = Path(DEFAULT_SETTINGS['output_dir']).expanduser()


def _default_base() -> Path:
    """Default project base from settings.json, falling back to the shipped default."""
    return Path(load_settings().get('output_dir') or DEFAULT_BASE).expanduser()


def _alert_config():
    """Alert Center config from settings.json (None when disabled/absent)."""
    cfg = load_settings().get('alerts')
    return cfg if isinstance(cfg, dict) and cfg.get('enabled') else None


def _github_config():
    """GitHub Issues config from settings.json (None when absent)."""
    cfg = load_settings().get('github')
    return cfg if isinstance(cfg, dict) else None


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


def cmd_run_missions(on_event=None) -> list:
    """Run every due Mission Center mission once, now (M10)."""
    from core.mission_schedule import run_due_missions
    return run_due_missions(on_event=on_event)


def cmd_ci(store: ProjectStore, target: str, base: Path, *, fail_on: str = 'high',
           sarif_out=None, scan: bool = True, run_fn=None) -> dict:
    """CI/CD gate (EPIC 16 F4): optionally run a scan, diff it against the previous
    one, and decide pass/fail when a new finding at/above ``fail_on`` appears.

    Thin orchestration over reusable parts: ``CollectionRunner`` (scan),
    ``timeline`` (change feed), ``ci_gate`` (policy), ``report_export`` (SARIF).
    ``scan`` can be turned off to gate the last two existing scans (e.g. when the
    pipeline ran the scan separately); ``run_fn`` is injectable for tests."""
    from core.timeline import build_timeline
    project = store.get_or_create(target)

    if scan:
        if run_fn is None:
            from core.collection_runner import CollectionRunner
            run_fn = CollectionRunner().run
        run_fn(target, str(base))
        project = store.get_or_create(target)

    ids = [s.get('id') for s in project.scans()
           if isinstance(s, dict) and s.get('id')]
    baseline = ids[-2] if len(ids) >= 2 else None
    current = ids[-1] if ids else None
    events: list = []
    if baseline and current:
        # Canonical "what changed this scan" feed: merges Scan-Diff regressions
        # (takeover / new source map / opened GraphQL / vulnerable dependency …)
        # with the F1 finding lifecycle, so a brand-new high/critical vuln surfaces
        # as a new_finding event carrying its own severity — which raw diff_events
        # does not emit. Filter to the current scan so the gate judges only this run.
        feed = build_timeline(project).get('events', [])
        events = [e for e in feed if e.get('scan_id') == current]

    result = ci_gate.evaluate_gate(events, fail_on=fail_on)

    sarif_written = None
    if sarif_out:
        from core.config import APP_VERSION
        from core.findings_store import FindingsStore
        from core.report_export import findings_sarif
        Path(sarif_out).write_text(
            findings_sarif(FindingsStore().active_findings(project.slug),
                           tool_version=APP_VERSION), encoding='utf-8')
        sarif_written = str(sarif_out)

    return {'gate': result, 'baseline': baseline, 'current': current,
            'sarif_out': sarif_written}


def cmd_issues(store: ProjectStore, target: str, *, config=None,
               min_severity=None, findings_store=None, client=None) -> dict:
    """GitHub Issues sync (EPIC 16 wave 2): open an issue for each not-yet-tracked
    active finding of the target's project at/above ``min_severity`` (idempotent).

    Thin orchestration: resolve the project, then delegate to
    ``github_issues.sync_findings`` over the ``FindingsStore``. ``config`` defaults
    to settings.json ``github``; ``findings_store`` / ``client`` are injectable for
    tests (no network)."""
    from core import github_issues
    from core.findings_store import FindingsStore
    project = store.get_or_create(target)
    cfg = dict(config if config is not None else (_github_config() or {}))
    if min_severity:
        cfg['min_severity'] = min_severity
    fstore = findings_store if findings_store is not None else FindingsStore()
    return github_issues.sync_findings(fstore, project.slug, cfg, client=client)


def cmd_compliance(store: ProjectStore, target: str, *, out=None,
                   findings_store=None) -> dict:
    """OWASP/CWE compliance report (EPIC 16 wave 2, A3): roll the target project's
    active findings up against the OWASP Top 10 2021 and render Markdown.

    Thin orchestration over ``FindingsStore`` (current posture) + ``compliance`` +
    ``report_export.compliance_markdown``. Writes to ``out`` when given. Returns
    ``{markdown, out, summary}``; ``findings_store`` is injectable for tests."""
    from core.compliance import build_compliance
    from core.findings_store import FindingsStore
    from core.report_export import compliance_markdown
    project = store.get_or_create(target)
    fstore = findings_store if findings_store is not None else FindingsStore()
    findings = fstore.active_findings(project.slug)
    md = compliance_markdown(findings)
    written = None
    if out:
        Path(out).write_text(md, encoding='utf-8')
        written = str(out)
    return {'markdown': md, 'out': written,
            'summary': build_compliance(findings)['summary']}


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
    elif kind == 'mission_run':
        print(f'  [{slug}] mission {ev.get("mission_id", "")} ran '
              f'({ev.get("status", "")})'
              + (f' → {ev["run_id"]}' if ev.get('run_id') else ''))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Advanced Site Analyzer — Continuous Monitoring')
    parser.add_argument('--output', default=None,
                        help='Base output directory (default: settings.output_dir)')
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

    p_ci = sub.add_parser(
        'ci', help='CI/CD gate: scan + diff, exit non-zero on new findings')
    p_ci.add_argument('url')
    p_ci.add_argument('--fail-on', default='high',
                      choices=['critical', 'high', 'medium', 'low', 'info'],
                      help='Minimum new-finding severity that fails the build')
    p_ci.add_argument('--sarif-out', default=None,
                      help='Write a SARIF 2.1.0 report of active findings here')
    p_ci.add_argument('--no-scan', action='store_true',
                      help='Skip the scan; gate the two most recent existing scans')

    p_iss = sub.add_parser(
        'issues', help='Open GitHub issues for active findings (idempotent)')
    p_iss.add_argument('url')
    p_iss.add_argument('--min-severity', default=None,
                       choices=['critical', 'high', 'medium', 'low', 'info'],
                       help='Override the min severity from settings (default: high)')

    p_comp = sub.add_parser(
        'compliance', help='OWASP Top 10 / CWE compliance report for active findings')
    p_comp.add_argument('url')
    p_comp.add_argument('--out', default=None,
                        help='Write the Markdown report here (default: print)')

    opts = parser.parse_args(argv)

    # Diff lines carry '→' and Russian text; a legacy Windows console (cp1251)
    # would otherwise raise UnicodeEncodeError mid-watch. Degrade unencodable
    # glyphs instead of crashing the loop.
    configure_stdout()

    base = Path(opts.output).expanduser() if opts.output else _default_base()
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
        mission_results = cmd_run_missions(on_event=_print_event)
        print(f'Ran {len(mission_results)} due mission(s).')
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
    elif opts.command == 'ci':
        out = cmd_ci(store, opts.url, base, fail_on=opts.fail_on,
                     sarif_out=opts.sarif_out, scan=not opts.no_scan)
        gate = out['gate']
        if out['baseline'] is None:
            print(f'CI gate: baseline scan recorded ({out["current"] or "—"}), '
                  f'no previous scan to diff — PASS')
        else:
            print(ci_gate.summary_line(gate))
            for ev in gate['triggers']:
                print(f'  [{ev.get("severity")}] {ev.get("title", "")}')
        if out['sarif_out']:
            print(f'SARIF written: {out["sarif_out"]}')
        sys.exit(ci_gate.exit_code(gate))
    elif opts.command == 'issues':
        out = cmd_issues(store, opts.url, min_severity=opts.min_severity)
        if out.get('reason'):
            print(f'GitHub Issues sync skipped: {out["reason"]} '
                  f'(configure "github" in settings.json).')
        else:
            print(f'GitHub Issues: {len(out["created"])} opened, '
                  f'{out["skipped"]} already tracked, '
                  f'{len(out["errors"])} error(s).')
            for c in out['created']:
                print(f'  #{c.get("number")} {c.get("title", "")} '
                      f'— {c.get("url", "")}')
            for e in out['errors']:
                print(f'  error ({e.get("id")}): {e.get("error")}')
    elif opts.command == 'compliance':
        out = cmd_compliance(store, opts.url, out=opts.out)
        if out['out']:
            s = out['summary']
            print(f'Compliance report written: {out["out"]} '
                  f'({s["categories_with_findings"]}/10 categories with findings, '
                  f'{s["total_findings"]} active).')
        else:
            print(out['markdown'])
    elif opts.command == 'watch':
        sched = monitor.MonitorScheduler(
            store, check_interval=opts.every, on_event=_print_event,
            alert_config=_alert_config(),
            extra_tick=lambda now=None: cmd_run_missions(on_event=_print_event))
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
    raise SystemExit(run_main(main))
