#!/usr/bin/env python3
"""Evidence integrity CLI for scan directories.

Thin command-line wrapper over ``core.evidence``. It never scans the network; it
only verifies files already listed in a scan's evidence_manifest.json.

    python evidence_cli.py verify Projects/example.com/scans/20260619_120000
    python evidence_cli.py json   Projects/example.com/scans/20260619_120000
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.evidence import audit_scan


def cmd_verify(scan_dir: str | Path) -> dict:
    return audit_scan(Path(scan_dir).expanduser())


def cmd_json(scan_dir: str | Path) -> dict:
    return audit_scan(Path(scan_dir).expanduser())


def _print_verify(result: dict) -> None:
    status = result.get("status")
    scan_dir = result.get("scan_dir")
    if result.get("ok"):
        print(f'Evidence OK: {result.get("checked", 0)} artifact(s) verified')
        print(f'  scan: {scan_dir}')
        print(f'  manifest: {result.get("manifest")}')
        return
    print(f'Evidence FAILED: {status}')
    print(f'  scan: {scan_dir}')
    if result.get("error"):
        print(f'  error: {result["error"]}')
    if result.get("missing"):
        print(f'  missing: {", ".join(result["missing"])}')
    if result.get("changed"):
        print(f'  changed: {", ".join(result["changed"])}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Advanced Site Analyzer - evidence integrity")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="Verify a scan evidence manifest")
    p_verify.add_argument("scan_dir")

    p_json = sub.add_parser("json", help="Print verification result as JSON")
    p_json.add_argument("scan_dir")

    opts = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

    if opts.command == "verify":
        result = cmd_verify(opts.scan_dir)
        _print_verify(result)
    else:
        result = cmd_json(opts.scan_dir)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
