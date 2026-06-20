#!/usr/bin/env python3
"""Scope Guard management CLI.

Thin local wrapper over ``core.scope_management``. It edits only project
metadata.json and never launches scans or network operations.

Examples:
    python scope_cli.py --output ~/SiteAnalyzer show example.com
    python scope_cli.py set https://example.com --allow example.com --allow "*.example.com" --active --no-passive-only
    python scope_cli.py clear example.com
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.scope_management import clear_scope, set_scope, show_scope, store_from_base

DEFAULT_BASE = Path.home() / "SiteAnalyzer"


def _print_scope(result: dict) -> None:
    scope = result["scope"]
    marker = "explicit" if result.get("explicit") else "legacy/default"
    print(f'Scope for {result["slug"]} ({marker})')
    print(f'  url: {result.get("url") or ""}')
    print(f'  allowed_domains: {", ".join(scope["allowed_domains"]) or "-"}')
    print(f'  denied_domains: {", ".join(scope["denied_domains"]) or "-"}')
    print(f'  active_scan_enabled: {scope["active_scan_enabled"]}')
    print(f'  passive_only: {scope["passive_only"]}')
    print(f'  rate_limit: {scope["rate_limit"] if scope["rate_limit"] is not None else "-"}')


def cmd_show(base, target, *, create=False):
    return show_scope(store_from_base(base), target, create=create)


def cmd_set(base, target, **kwargs):
    return set_scope(store_from_base(base), target, **kwargs)


def cmd_clear(base, target):
    return clear_scope(store_from_base(base), target)


def _bool_group(parser, yes: str, no: str, dest: str, help_yes: str, help_no: str):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(yes, dest=dest, action="store_true", default=None,
                       help=help_yes)
    group.add_argument(no, dest=dest, action="store_false", help=help_no)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Advanced Site Analyzer - Scope Guard management")
    parser.add_argument("--output", default=str(DEFAULT_BASE),
                        help="Base output directory (default: ~/SiteAnalyzer)")
    parser.add_argument("--json", action="store_true",
                        help="Print result as JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p_show = sub.add_parser("show", help="Show project scope")
    p_show.add_argument("target", help="Project slug or URL")
    p_show.add_argument("--create", action="store_true",
                        help="Create project if target does not exist")

    p_set = sub.add_parser("set", help="Create/update project scope")
    p_set.add_argument("target", help="Project slug or URL")
    p_set.add_argument("--allow", action="append", dest="allowed_domains",
                       help="Allowed domain or wildcard; repeatable")
    p_set.add_argument("--deny", action="append", dest="denied_domains",
                       help="Denied domain or wildcard; repeatable")
    _bool_group(p_set, "--active", "--no-active", "active_scan_enabled",
                "Enable active phases", "Disable active phases")
    _bool_group(p_set, "--passive-only", "--no-passive-only", "passive_only",
                "Force passive-only mode", "Allow active mode when enabled")
    p_set.add_argument("--rate-limit", default=None,
                       help="Operator rate-limit hint")
    p_set.add_argument("--clear-rate-limit", action="store_true",
                       help="Remove rate-limit hint")
    p_set.add_argument("--no-create", action="store_true",
                       help="Fail if project does not already exist")

    p_clear = sub.add_parser("clear", help="Remove explicit project scope")
    p_clear.add_argument("target", help="Project slug or URL")

    opts = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

    try:
        if opts.command == "show":
            result = cmd_show(opts.output, opts.target, create=opts.create)
        elif opts.command == "set":
            result = cmd_set(
                opts.output,
                opts.target,
                create=not opts.no_create,
                allowed_domains=opts.allowed_domains,
                denied_domains=opts.denied_domains,
                active_scan_enabled=opts.active_scan_enabled,
                passive_only=opts.passive_only,
                rate_limit=opts.rate_limit,
                clear_rate_limit=opts.clear_rate_limit,
            )
        else:
            result = cmd_clear(opts.output, opts.target)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if opts.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_scope(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
