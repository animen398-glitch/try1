#!/usr/bin/env python3
"""Business Context Model management CLI (EPIC NEXT F1).

Thin local wrapper over ``core.business_context``. It edits only project
metadata.json and never launches scans or network operations. A project-level
default applies to the whole target; ``--asset-type`` + ``--asset`` set a
per-asset override (joined on the asset's fingerprint).

Examples:
    python business_cli.py --output ~/SiteAnalyzer show example.com
    python business_cli.py set example.com --criticality high --data-sensitivity confidential
    python business_cli.py set example.com --asset-type subdomain --asset api.example.com --criticality critical
    python business_cli.py clear example.com --asset-type subdomain --asset api.example.com
    python business_cli.py clear example.com
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.business_context import (CRITICALITY_TIERS, DATA_SENSITIVITY, describe,
                                   clear_business_context, set_business_context,
                                   show_business_context)
from core.cli_common import configure_stdout, run_main
from core.project import ProjectStore

DEFAULT_BASE = Path.home() / "SiteAnalyzer"


def _asset_fp(asset_type, asset_value):
    """Asset fingerprint from a type+value pair, or None when no asset targeted."""
    if not asset_value:
        return None
    from core.asset_adapter import asset_fingerprint
    return asset_fingerprint(asset_type or '', asset_value)


def _store(base):
    return ProjectStore(Path(base).expanduser())


def _print(result: dict) -> None:
    root = result.get("business_context", {})
    print(f'Business context for {result["slug"]}')
    print(f'  url: {result.get("url") or ""}')
    default = root.get("default") or {}
    print(f'  default: {describe(default) or "-"}')
    assets = root.get("assets") or {}
    if assets:
        print(f'  per-asset overrides: {len(assets)}')
        for fp, ctx in assets.items():
            print(f'    {fp[:12]}…: {describe(ctx) or "-"}')
    else:
        print('  per-asset overrides: -')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Advanced Site Analyzer - Business Context management")
    parser.add_argument("--output", default=str(DEFAULT_BASE),
                        help="Base output directory (default: ~/SiteAnalyzer)")
    parser.add_argument("--json", action="store_true", help="Print result as JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p_show = sub.add_parser("show", help="Show project business context")
    p_show.add_argument("target", help="Project slug or URL")
    p_show.add_argument("--create", action="store_true",
                        help="Create project if target does not exist")

    p_set = sub.add_parser("set", help="Set default or per-asset business context")
    p_set.add_argument("target", help="Project slug or URL")
    p_set.add_argument("--criticality", choices=CRITICALITY_TIERS,
                       help="Business criticality tier")
    p_set.add_argument("--data-sensitivity", dest="data_sensitivity",
                       choices=DATA_SENSITIVITY, help="Data classification tier")
    p_set.add_argument("--asset-type", dest="asset_type",
                       help="Asset type for a per-asset override (e.g. subdomain)")
    p_set.add_argument("--asset", dest="asset_value",
                       help="Asset value for a per-asset override")
    p_set.add_argument("--no-create", action="store_true",
                       help="Fail if project does not already exist")

    p_clear = sub.add_parser("clear", help="Clear an override or the whole context")
    p_clear.add_argument("target", help="Project slug or URL")
    p_clear.add_argument("--asset-type", dest="asset_type", help="Asset type")
    p_clear.add_argument("--asset", dest="asset_value",
                         help="Asset value (clears just this override)")

    opts = parser.parse_args(argv)
    configure_stdout()

    try:
        if opts.command == "show":
            result = show_business_context(_store(opts.output), opts.target,
                                           create=opts.create)
        elif opts.command == "set":
            result = set_business_context(
                _store(opts.output), opts.target, create=not opts.no_create,
                asset_fp=_asset_fp(opts.asset_type, opts.asset_value),
                criticality=opts.criticality,
                data_sensitivity=opts.data_sensitivity)
        else:
            result = clear_business_context(
                _store(opts.output), opts.target,
                asset_fp=_asset_fp(opts.asset_type, opts.asset_value))
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if opts.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main))
