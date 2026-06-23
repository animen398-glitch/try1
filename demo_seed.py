#!/usr/bin/env python3
"""demo_seed.py — build a self-contained demo workspace.

Populates ONE portable directory with a realistic ASM/CSM portfolio so the app
can be shown as a platform (findings lifecycle, asset inventory, criticality,
remediation, timeline/drift, company roll-up, portfolio) rather than a bag of
scanners — without touching the user's real ``data/`` or output workspace.

Everything (lifecycle DBs, company registry, settings, project scans) lands
under ``<demo-dir>``; the layout mirrors exactly what a frozen/source run would
read when pointed there via the ``ASA_DATA_ROOT`` env override:

    <demo-dir>/
      configs/settings.json          # output_dir -> <demo-dir>
      data/{findings,assets,operations}.db, companies.json
      Projects/<slug>/scans/.../report.json, metadata.json

Run, then launch the app against it (nothing else needs configuring):

    python demo_seed.py --dir ./demo_workspace
    ASA_DATA_ROOT=./demo_workspace python main.py            # bash / git-bash
    $env:ASA_DATA_ROOT="./demo_workspace"; python main.py    # PowerShell

The seeder writes to explicit paths derived from ``PathManager(data_root=...)``
(the same SSOT the app uses), so it stays faithful without importing the global
config singleton.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List


# ── report.json builder (record_scan contract) ────────────────────────────────
def _report(sid: str, score: int, *, secrets: int, high: int, medium: int,
            cms: List[str]) -> Dict:
    level = 'High' if score >= 60 else ('Medium' if score >= 35 else 'Low')
    return {
        'scan_id': sid, 'finished_at': sid, 'warnings': [],
        'executive_summary': {
            'risk_level': level, 'risk_score': score, 'risk_100': score,
            'metrics': {'risk_100': score, 'attack_surface_score': score // 2,
                        'secrets': secrets, 'high': high, 'medium': medium},
        },
        'phases': {'recon': {'status': 'Success', 'data': {'cms': cms}}},
    }


# Each domain: business context + per-scan (sid, score, secrets, high, medium,
# cms, assets, findings). Findings are raw scanner dicts; running them through
# FindingsStore.sync scan-by-scan yields real NEW / RECURRING / RESOLVED
# lifecycle events (drift) for the timeline.
def _portfolio() -> List[Dict]:
    from core.asset_adapter import Asset

    def F(cat, rid, title, sev, loc):
        return {'category': cat, 'rule_id': rid, 'title': title,
                'severity': sev, 'location': loc}

    return [
        {
            'url': 'https://shop.acme.com',
            'business': {'criticality': 'critical', 'data_sensitivity': 'restricted'},
            'assets': [Asset('domain', 'shop.acme.com'),
                       Asset('subdomain', 'checkout.shop.acme.com'),
                       Asset('subdomain', 'cdn.shop.acme.com'),
                       Asset('ip', '203.0.113.10'),
                       Asset('url', 'https://shop.acme.com/api/v1')],
            'scans': [
                ('20260110_090000', 35, 0, 1, 2, ['WordPress', 'WooCommerce'], [
                    F('headers', 'missing-hsts', 'Missing HSTS header', 'medium',
                      'https://shop.acme.com'),
                    F('cookie', 'no-secure-flag', 'Cookie without Secure flag',
                      'medium', 'https://shop.acme.com'),
                    F('vuln', 'idor-cart', 'IDOR on cart endpoint', 'high',
                      'https://shop.acme.com/api/v1/cart'),
                ]),
                ('20260210_090000', 62, 1, 2, 1, ['WordPress', 'WooCommerce'], [
                    F('cookie', 'no-secure-flag', 'Cookie without Secure flag',
                      'medium', 'https://shop.acme.com'),
                    F('vuln', 'idor-cart', 'IDOR on cart endpoint', 'high',
                      'https://shop.acme.com/api/v1/cart'),
                    F('secret', 'stripe-key', 'Exposed Stripe secret key', 'high',
                      'https://shop.acme.com/static/app.js'),
                ]),
                ('20260315_090000', 71, 1, 2, 2, ['WordPress', 'WooCommerce'], [
                    F('vuln', 'idor-cart', 'IDOR on cart endpoint', 'high',
                      'https://shop.acme.com/api/v1/cart'),
                    F('secret', 'stripe-key', 'Exposed Stripe secret key', 'high',
                      'https://shop.acme.com/static/app.js'),
                    F('headers', 'missing-csp', 'Missing Content-Security-Policy',
                      'medium', 'https://shop.acme.com'),
                    F('vuln', 'open-redirect', 'Open redirect in /go', 'medium',
                      'https://shop.acme.com/go'),
                ]),
            ],
            # finding rule_id -> remediation task (status, owner, due)
            'remediation': {
                'idor-cart': ('in_progress', 'alice', '2026-04-15'),
                'stripe-key': ('open', 'bob', '2026-04-01'),
                'missing-csp': ('done', 'carol', '2026-03-25'),
            },
        },
        {
            'url': 'https://api.acme.com',
            'business': {'criticality': 'high', 'data_sensitivity': 'confidential'},
            'assets': [Asset('domain', 'api.acme.com'),
                       Asset('subdomain', 'gql.api.acme.com'),
                       Asset('ip', '203.0.113.20')],
            'scans': [
                ('20260118_120000', 48, 1, 1, 1, ['FastAPI'], [
                    F('graphql', 'introspection-on', 'GraphQL introspection enabled',
                      'medium', 'https://gql.api.acme.com/graphql'),
                    F('secret', 'jwt-hardcoded', 'Hardcoded JWT signing key', 'high',
                      'https://api.acme.com/openapi.json'),
                ]),
                ('20260220_120000', 40, 0, 1, 1, ['FastAPI'], [
                    F('graphql', 'introspection-on', 'GraphQL introspection enabled',
                      'medium', 'https://gql.api.acme.com/graphql'),
                    F('vuln', 'rate-limit', 'No rate limiting on auth', 'high',
                      'https://api.acme.com/auth/login'),
                ]),
            ],
            'remediation': {
                'rate-limit': ('open', 'dave', '2026-03-10'),
            },
        },
        {
            'url': 'https://blog.acme.com',
            'business': {'criticality': 'low', 'data_sensitivity': 'public'},
            'assets': [Asset('domain', 'blog.acme.com'),
                       Asset('ip', '203.0.113.30')],
            'scans': [
                ('20260112_080000', 15, 0, 0, 2, ['Ghost'], [
                    F('headers', 'missing-xfo', 'Missing X-Frame-Options', 'medium',
                      'https://blog.acme.com'),
                    F('headers', 'server-banner', 'Server version disclosure', 'low',
                      'https://blog.acme.com'),
                ]),
                ('20260214_080000', 18, 0, 0, 1, ['Ghost'], [
                    F('headers', 'missing-xfo', 'Missing X-Frame-Options', 'medium',
                      'https://blog.acme.com'),
                ]),
            ],
            'remediation': {},
        },
    ]


def seed(data_root: Path, *, company_name: str = 'Acme Corp') -> Dict:
    """Build the demo workspace under ``data_root`` (must be empty/new). Uses
    explicit, PathManager-derived paths so nothing touches the global config."""
    from core.paths import PathManager
    from core.asset_store import AssetStore
    from core.business_context import set_business_context
    from core.company import CompanyRegistry
    from core.findings_store import FindingsStore
    from core.project import ProjectStore
    from core.remediation import set_task

    pm = PathManager(data_root=data_root)
    findings = FindingsStore(db_path=pm.get_db_path('findings.db'))
    assets = AssetStore(db_path=pm.get_db_path('assets.db'))
    companies = CompanyRegistry(path=pm.get_db_path('companies.json'))
    store = ProjectStore(str(data_root))            # projects -> data_root/Projects

    company_slug = companies.create(company_name)
    n_proj = n_scan = n_find = n_rem = 0

    for spec in _portfolio():
        proj = store.get_or_create(spec['url'])
        slug = proj.slug
        store.assign(slug, company_slug)
        set_business_context(store, slug, **spec['business'])
        n_proj += 1

        last_ids: Dict[str, str] = {}              # rule_id -> finding id (latest scan)
        for sid, score, secrets, high, medium, cms, finds in spec['scans']:
            scan_dir = proj.start_scan(sid)
            report = _report(sid, score, secrets=secrets, high=high,
                             medium=medium, cms=cms)
            (scan_dir / 'report.json').write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
            proj.record_scan(scan_dir, report)
            assets.sync(slug, sid, spec['assets'])
            diff = findings.sync(slug, sid, finds)
            for row in diff.get('new', []) + diff.get('recurring', []):
                last_ids[row.get('rule_id', '')] = row['id']
            n_scan += 1
            n_find += len(finds)

        for rule_id, (status, owner, due) in spec['remediation'].items():
            fid = last_ids.get(rule_id)
            if fid:
                set_task(findings, fid, status=status, owner=owner, due=due)
                n_rem += 1

    # settings.json so the app reads this workspace verbatim when launched with
    # ASA_DATA_ROOT pointed here (output_dir == data_root -> Projects/ below it).
    from core import config
    settings = dict(config.DEFAULT_SETTINGS)
    settings['output_dir'] = str(data_root)
    settings['gui_theme'] = 'dark'
    cfg_dir = data_root / 'configs'
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / 'settings.json').write_text(
        json.dumps(settings, ensure_ascii=False, indent=2), encoding='utf-8')

    return {'company': company_name, 'projects': n_proj, 'scans': n_scan,
            'findings': n_find, 'remediation': n_rem, 'data_root': str(data_root)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Seed a self-contained demo workspace.')
    ap.add_argument('--dir', default='demo_workspace',
                    help='target directory (default: ./demo_workspace)')
    ap.add_argument('--force', action='store_true',
                    help='wipe the target directory first if it exists')
    args = ap.parse_args(argv)

    root = Path(args.dir).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        if not args.force:
            print(f'error: {root} exists and is not empty (use --force to wipe)',
                  file=sys.stderr)
            return 1
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    summary = seed(root)
    print('Demo workspace seeded:')
    for k in ('company', 'projects', 'scans', 'findings', 'remediation'):
        print(f'  {k:12}: {summary[k]}')
    print(f'  location    : {summary["data_root"]}')
    print('\nLaunch the app against it:')
    print(f'  bash : ASA_DATA_ROOT="{root}" python main.py')
    print(f'  pwsh : $env:ASA_DATA_ROOT="{root}"; python main.py')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
