#!/usr/bin/env python3
"""Remediation Tasks management CLI (EPIC NEXT F4).

Thin local wrapper over ``core.remediation``. It edits only the findings store's
``finding_events`` log (no new table, no network). A task tracks the fix work for a
finding: status (open / in_progress / done), optional owner / due / note.

Examples:
    python remediation_cli.py --output ~/SiteAnalyzer list example.com
    python remediation_cli.py auto example.com --top 10
    python remediation_cli.py set example.com <finding_id> --status in_progress --owner alice --due 2026-07-01
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.cli_common import configure_stdout, run_main
from core.findings_store import FindingsStore
from core.project import ProjectStore
from core.remediation import (REMEDIATION_STATUSES, load_remediation,
                              seed_from_intelligence, set_task)

DEFAULT_BASE = Path.home() / "SiteAnalyzer"


def _slug(base, target):
    """Resolve a slug-or-URL target to a project slug (findings are slug-keyed)."""
    try:
        return ProjectStore(Path(base).expanduser()).resolve(target).slug
    except KeyError:
        # Fall back to the bare target — findings may exist for a slug whose
        # Projects/<slug>/ folder is absent (store is independent of the tree).
        return target


def _print(result: dict) -> None:
    s = result.get("summary", {})
    print(f'Remediation: {s.get("total", 0)} task(s) · {s.get("open", 0)} open · '
          f'{s.get("in_progress", 0)} in progress · {s.get("overdue", 0)} overdue')
    for t in result.get("tasks", []):
        tk = t.get("task", {})
        meta = [v for v in (tk.get("owner"), tk.get("due")) if v]
        suffix = (' · ' + ' · '.join(meta)) if meta else ''
        if t.get("overdue"):
            suffix += ' ⚠ overdue'
        print(f'  [{t.get("status_label") or tk.get("status")}] '
              f'{t.get("severity") or ""} {t.get("title") or ""}{suffix}')
        print(f'      id={t.get("finding_id")}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Advanced Site Analyzer - Remediation Tasks management")
    parser.add_argument("--output", default=str(DEFAULT_BASE),
                        help="Base output directory (default: ~/SiteAnalyzer)")
    parser.add_argument("--json", action="store_true", help="Print result as JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List remediation tasks")
    p_list.add_argument("target", help="Project slug or URL")

    p_auto = sub.add_parser("auto", help="Seed tasks for top-priority findings")
    p_auto.add_argument("target", help="Project slug or URL")
    p_auto.add_argument("--top", type=int, default=10, help="How many (default 10)")

    p_set = sub.add_parser("set", help="Create/update a finding's task")
    p_set.add_argument("target", help="Project slug or URL")
    p_set.add_argument("finding_id", help="Stored finding id (see `list`/findings)")
    p_set.add_argument("--status", choices=REMEDIATION_STATUSES, help="Task status")
    p_set.add_argument("--owner", help="Assignee")
    p_set.add_argument("--due", help="Due date (YYYY-MM-DD or ISO datetime)")
    p_set.add_argument("--note", help="Free note")

    opts = parser.parse_args(argv)
    configure_stdout()

    slug = _slug(opts.output, opts.target)
    store = FindingsStore()

    if opts.command == "auto":
        business = None
        proj = ProjectStore(Path(opts.output).expanduser()).get(slug)
        if proj is not None:
            business = proj.get_business_context()
        created = seed_from_intelligence(slug, top_n=opts.top, business=business,
                                         store=store)
        result = {"created": created, **load_remediation(slug, store=store)}
        if not opts.json:
            print(f'Created {len(created)} task(s).')
    elif opts.command == "set":
        task = set_task(store, opts.finding_id, status=opts.status, owner=opts.owner,
                        due=opts.due, note=opts.note)
        result = {"finding_id": opts.finding_id, "task": task,
                  **load_remediation(slug, store=store)}
    else:
        result = load_remediation(slug, store=store)

    if opts.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main))
