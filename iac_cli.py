#!/usr/bin/env python3
"""IaC / container config scanner CLI (EPIC NEXT F7).

Thin local wrapper over ``core.iac_scanner``. Scans a file or directory of
infrastructure-as-code / container config files (Dockerfile, docker-compose,
Kubernetes, CloudFormation, Terraform) for misconfigurations and leaked secrets,
plus the container images used. Local only — no cloud API, no network.

This is an ad-hoc audit (prints / JSON); it does not persist to a project. To run
IaC ingestion inside a project's lifecycle (F1 store / SLA / compliance), use the
CollectionRunner ``iac`` phase with an ``iac_path``.

Examples:
    python iac_cli.py ./infra
    python iac_cli.py ./Dockerfile --json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.cli_common import configure_stdout, run_main
from core.iac_scanner import scan_path


def _print(result: dict) -> None:
    s = result.get('summary', {})
    print(f"IaC scan: {s.get('files', 0)} file(s) · {s.get('findings', 0)} "
          f"finding(s) · {s.get('technologies', 0)} image(s)"
          + ('' if s.get('yaml_available') else ' · YAML parser unavailable'))
    for f in result.get('findings', []):
        print(f"  [{f.get('severity')}] {f.get('title')} — {f.get('location')}")
    techs = result.get('technologies', [])
    if techs:
        print('Images:')
        for t in techs:
            ver = f":{t['version']}" if t.get('version') else ''
            print(f"  {t.get('name')}{ver}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Advanced Site Analyzer - IaC / container config scanner")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Print result as JSON")
    opts = parser.parse_args(argv)
    configure_stdout()

    if not Path(opts.path).exists():
        print(f"path not found: {opts.path}", file=sys.stderr)
        return 1
    result = scan_path(opts.path)
    if opts.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main))
