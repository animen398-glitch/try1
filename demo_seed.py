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
      data/{findings,assets,audit_runs,operations}.db, companies.json
      Projects/<slug>/scans/.../report.json, metadata.json
      demo_iac/                     # small local IaC sample for the IaC tab

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


def _seed_audit_run(store, project: str, active_findings: List[Dict]) -> str:
    """Persist one completed client-safe audit run for the demo project."""
    from core.audit_workflow import advance_audit_phase, create_audit_run

    slug = project.replace('.', '-')
    run = create_audit_run(
        project,
        template='light_client_safe',
        run_id=f'audit-demo-{slug}',
    )
    findings = [
        {
            'finding_id': row['id'],
            'title': row.get('title', ''),
            'severity': row.get('severity', 'info'),
            'validation_status': 'verified',
            'quality_gate': 'passed' if row.get('severity') in {'critical', 'high'} else 'failed',
            'client_facing': row.get('severity') in {'critical', 'high'},
            'confidence': 86 if row.get('severity') in {'critical', 'high'} else 68,
            'evidence_refs': [f'findings/{row["id"]}.json'],
        }
        for row in active_findings[:3]
    ]
    phase_results = {
        'recon_snapshot': {
            'active_findings': len(active_findings),
            'scope': {'project': project, 'profile': 'client_safe'},
        },
        'finding_hunt': {
            'candidates': len(active_findings),
            'sources': ['findings_store', 'latest_scan'],
        },
        'validation': {'validated_findings': findings},
        'structured_output': {
            'client_findings': sum(1 for item in findings if item['client_facing']),
            'review_findings': sum(1 for item in findings if not item['client_facing']),
        },
    }
    for phase in [item['name'] for item in run['phases']]:
        run = advance_audit_phase(run, phase, phase_results.get(phase, {}))
    store.save_run(run, now='2026-06-28T10:00:00')
    for item in findings:
        store.record_event(
            run['run_id'],
            'finding_verified',
            phase='validation',
            finding_id=item['finding_id'],
            at='2026-06-28T10:05:00',
        )
        if item['quality_gate'] == 'passed':
            store.record_event(
                run['run_id'],
                'quality_gate_passed',
                phase='structured_output',
                finding_id=item['finding_id'],
                at='2026-06-28T10:06:00',
            )
    return run['run_id']


def _seed_missions(missions_store, slug: str, audit_run_id: str,
                   finding_id: str) -> int:
    """Seed a few Mission Center missions on the demo project so the whole
    M1-M11 lifecycle is visible: one ready+scheduled, one executed (linked run +
    finding), one carrying a stale link (the M11 flag)."""
    from core import pentest_mission as pm
    from core.mission_schedule import set_mission_schedule

    # 1) ready + scheduled weekly — shows the schedule controls / auto-tick.
    scheduled = pm.advance_mission_status(
        pm.create_mission(slug, 'Weekly authorized external review',
                          allowed_actions=['headers_check', 'cookie_flags_check']),
        'ready')
    missions_store.save_mission(scheduled, now='2026-06-28T09:00:00')
    set_mission_schedule(scheduled['mission_id'], 'weekly',
                         store=missions_store, now='2026-06-28T09:00:00')

    # 2) executed — completed, with a linked audit run + finding (drives the
    #    report + overview last-run outcome).
    executed = pm.create_mission(slug, 'Quarterly checkout deep audit',
                                 template='light_client_safe',
                                 allowed_actions=['headers_check'])
    for status in ('ready', 'running', 'completed'):
        executed = pm.advance_mission_status(executed, status)
    executed = pm.link_audit_run(executed, audit_run_id)
    executed = pm.link_finding(executed, finding_id)
    missions_store.save_mission(executed, now='2026-06-28T10:30:00')

    # 3) stale link — references a run that no longer exists (M11 surfaces it).
    legacy = pm.link_audit_run(
        pm.create_mission(slug, 'Legacy vendor portal review',
                          allowed_actions=['headers_check']),
        'audit-demo-removed')
    missions_store.save_mission(legacy, now='2026-06-20T08:00:00')
    return 3


def _seed_engagement(engagements_store, slug: str, company: str, *,
                     mission_id: str, audit_run_id: str, finding_id: str,
                     retest_store=None, findings_store=None) -> int:
    """Seed one authorized engagement on the demo project, mid-flight in
    'reporting', linking the demo mission + audit run + finding — so the whole
    F1–F4 engagement backend (contract / store / links / report) is populated.
    When a ``retest_store`` is given, also take one persisted retest snapshot so
    the Retest Run lifecycle (R1–R4) surfaces (history / timeline / CSV) show
    data."""
    from core import engagement as eng

    e = eng.create_engagement(
        company, slug,
        scope={'allowed_domains': [slug]},
        roe={'passive_only': False, 'active_scan_enabled': True,
             'rate_limit': '1 rps', 'window': '09:00-17:00 UTC',
             'emergency_contact': 'soc@example.com'},
        authorization={'accepted': True, 'authorized_by': 'Client CISO',
                       'reference': 'SOW-2026-001', 'notes': 'Authorized scope'})
    e = eng.advance_engagement_status(e, 'authorized')
    e = eng.advance_engagement_status(e, 'active')
    e = eng.link_mission(e, mission_id)
    e = eng.link_audit_run(e, audit_run_id)
    e = eng.link_finding(e, finding_id)
    e = eng.advance_engagement_status(e, 'reporting')
    engagements_store.save_engagement(e, now='2026-06-28T11:00:00')
    if retest_store is not None:
        from core.retest_runner import run_retest
        run_retest(e, now='2026-06-28T12:00:00', findings_store=findings_store,
                   retest_store=retest_store)
    return 1


def _seed_iac_sample(data_root: Path) -> Path:
    sample = data_root / 'demo_iac'
    sample.mkdir(parents=True, exist_ok=True)
    (sample / 'main.tf').write_text(
        '\n'.join([
            'resource "aws_security_group" "web" {',
            '  ingress {',
            '    from_port   = 443',
            '    to_port     = 443',
            '    protocol    = "tcp"',
            '    cidr_blocks = ["0.0.0.0/0"]',
            '  }',
            '}',
            '',
            'resource "aws_s3_bucket_acl" "logs" {',
            '  bucket = "acme-demo-logs"',
            '  acl    = "public-read"',
            '}',
            '',
        ]),
        encoding='utf-8',
    )
    (sample / 'Dockerfile').write_text(
        '\n'.join([
            'FROM python:latest',
            'WORKDIR /app',
            'COPY . .',
            'CMD ["python", "app.py"]',
            '',
        ]),
        encoding='utf-8',
    )
    return sample


def seed(data_root: Path, *, company_name: str = 'Acme Corp') -> Dict:
    """Build the demo workspace under ``data_root`` (must be empty/new). Uses
    explicit, PathManager-derived paths so nothing touches the global config."""
    from core.paths import PathManager
    from core.asset_store import AssetStore
    from core.business_context import set_business_context
    from core.company import CompanyRegistry
    from core.audit_store import AuditRunStore
    from core.findings_store import FindingsStore
    from core.findings_store import INACTIVE_STATUSES
    from core.engagement_store import EngagementStore
    from core.mission_store import MissionStore
    from core.project import ProjectStore
    from core.remediation import set_task
    from core.retest_run_store import RetestRunStore

    pm = PathManager(data_root=data_root)
    findings = FindingsStore(db_path=pm.get_db_path('findings.db'))
    assets = AssetStore(db_path=pm.get_db_path('assets.db'))
    audits = AuditRunStore(db_path=pm.get_db_path('audit_runs.db'))
    missions = MissionStore(pm.get_db_path('missions.db'))
    engagements = EngagementStore(pm.get_db_path('engagements.db'))
    retests = RetestRunStore(pm.get_db_path('retest_runs.db'))
    companies = CompanyRegistry(path=pm.get_db_path('companies.json'))
    store = ProjectStore(str(data_root))            # projects -> data_root/Projects

    company_slug = companies.create(company_name)
    n_proj = n_scan = n_find = n_rem = n_audit = n_mission = n_engagement = 0

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
        active_rows = [
            row for row in findings.list_findings(slug)
            if row.get('status') not in INACTIVE_STATUSES
        ]
        if active_rows:
            run_id = _seed_audit_run(audits, slug, active_rows)
            n_audit += 1
            # Showcase the Mission Center + Engagement on the first (richest)
            # project only.
            if n_mission == 0:
                n_mission += _seed_missions(missions, slug, run_id,
                                            active_rows[0]['id'])
                seeded = missions.list_missions(slug)
                if seeded:
                    n_engagement += _seed_engagement(
                        engagements, slug, company_name,
                        mission_id=seeded[0]['id'], audit_run_id=run_id,
                        finding_id=active_rows[0]['id'],
                        retest_store=retests, findings_store=findings)

    _seed_iac_sample(data_root)

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
            'findings': n_find, 'remediation': n_rem, 'audit_runs': n_audit,
            'missions': n_mission, 'engagements': n_engagement,
            'retest_runs': len(retests.list_retest_runs()),
            'data_root': str(data_root)}


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
    for k in ('company', 'projects', 'scans', 'findings', 'remediation',
              'audit_runs', 'missions', 'engagements', 'retest_runs'):
        print(f'  {k:12}: {summary[k]}')
    print(f'  location    : {summary["data_root"]}')
    print('\nLaunch the app against it:')
    print(f'  bash : ASA_DATA_ROOT="{root}" python main.py')
    print(f'  pwsh : $env:ASA_DATA_ROOT="{root}"; python main.py')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
