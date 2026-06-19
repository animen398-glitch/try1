"""collection_runner.py
Runs the analysis modules back-to-back into one structured project directory
and emits an aggregated HTML + JSON report.

Pipeline (each phase is guarded — a failure is recorded and the run continues):
    Recon  ->  API key scan  ->  Capture (frontend)  ->  Clone (frontend)
           ->  Image collection (media)

Layout produced under <base>/<domain>_<timestamp>/:
    recon/recon.json
    api/api_keys.json
    capture/…              (saved HTML pages + site_map.json)
    clone/…                (self-contained offline copy)
    images/…               (downloaded images)
    report.json            (full aggregated result)
    report.html            (human-readable summary)
"""

import html
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

from core.analyzer_plugins import discover_analyzers, run_analyzers
from core.api_key_extractor import ApiKeyExtractor
from core.attack_surface import build_surface
from core.attack_surface import render_interactive as render_surface_graph
from core.cert_info import fetch_certificate
from core.config import PLUGINS_DIR
from core.content_capture import SiteContentCapture
from core.cookie_auditor import CookieAuditor
from core.dependency_audit import render_html as render_dependencies
from core.executive_summary import build_summary
from core.executive_summary import render_html as render_exec_summary
from core.external_tools import KatanaRunner, NucleiRunner
from core.frontend_cloner import FrontendCloner
from core.dns_intel import discover as discover_dns
from core.dns_intel import render_html as render_dns
from core.email_intel import discover as discover_emails
from core.email_intel import render_html as render_emails
from core.employee_intel import discover as discover_employees
from core.employee_intel import render_html as render_employees
from core.ct_history import discover as discover_ct
from core.ct_history import render_html as render_ct
from core.historical_intel import discover as discover_historical
from core.historical_intel import render_html as render_historical
from core.asn_intel import build_asn_intel
from core.asn_intel import related_assets_from_report
from core.asn_intel import render_html as render_asn_intel
from core import cve_intel
from core.infrastructure import render_html as render_infrastructure
from core.llm_summary import DEFAULT_MODEL as _LLM_DEFAULT_MODEL
from core.openapi_discovery import discover as discover_openapi
from core.openapi_discovery import render_html as render_openapi
from core.llm_summary import generate_narrative as generate_llm_narrative
from core.project import ProjectStore, project_slug
from core.recon_engine import ReconEngine
from core.report_charts import stacked_bar
from core.scope_guard import active_phase_decision
from core.screenshot import ScreenshotCapturer
from core.screenshot import select_targets as select_screenshot_targets
from core.subdomain_scanner import SubdomainScanner
from core.site_map import render_html as render_site_map
from core.tech_fingerprint import render_html as render_technologies
from core.vuln_scanner import VulnScanner
from utils.image_processor import ImageExtractor


def _domain_slug(url: str) -> str:
    """Backward-compatible alias — the canonical slug lives in core.project."""
    return project_slug(url)


class CollectionRunner:
    """Sequentially drives every collection module into one project folder."""

    def __init__(self, profile: str = 'chrome_windows', max_pages: int = 20,
                 cookies: Optional[str] = None, capture_delay: float = 0.5,
                 screenshots: bool = False, nuclei: bool = False,
                 katana: bool = False, llm: bool = False,
                 llm_model: Optional[str] = None, subdomains: bool = False,
                 certificate: bool = False, openapi: bool = False,
                 historical: bool = False, dns: bool = False,
                 emails: bool = False, employees: bool = False,
                 ct: bool = False, asn_intel: bool = False,
                 osv: bool = False, security: bool = False):
        self.profile = profile
        self.max_pages = max_pages
        self.cookies = cookies
        self.capture_delay = capture_delay   # seconds between captured pages
        # Opt-in headless screenshot (Playwright) — off by default so the
        # default pipeline stays fast and dependency-free.
        self.screenshots = screenshots
        # Opt-in external nuclei scan (binary), merged into vuln findings.
        self.nuclei = nuclei
        # Opt-in external katana crawl (binary) → endpoints in the graph/report.
        self.katana = katana
        # Opt-in local-Ollama narrative over the deterministic executive summary
        # (off by default — the verdict never depends on a model being present).
        self.llm = llm
        self.llm_model = llm_model
        # Opt-in subdomain enumeration (passive + active takeover detection) —
        # feeds the risk engine's takeover signal and the Scan Diff subdomain
        # section. Off by default (it does extra network).
        self.subdomains = subdomains
        # Opt-in TLS certificate capture — feeds the Scan Diff certificate
        # section (renewal / issuer / SAN changes). Off by default (extra TLS
        # handshake).
        self.certificate = certificate
        # Opt-in OpenAPI/Swagger discovery (#11) — probes for an API spec and
        # maps its endpoints; feeds the report, attack surface, and Scan Diff.
        self.openapi = openapi
        # Opt-in Historical URL intelligence (#12) — archived URLs (Wayback)
        # classified into admin/auth/api/config; feeds report/surface/diff.
        self.historical = historical
        # Opt-in DNS intelligence (#13) — records + email-auth (SPF/DMARC/DKIM/
        # CAA); its findings fold into the risk engine.
        self.dns = dns
        # Opt-in Email intelligence (#13) — harvest + group exposed addresses
        # (homepage/robots/sitemap); feeds report + Scan Diff.
        self.emails = emails
        # Opt-in Employee intelligence (#13) — named people from team/about
        # pages + inferred corporate e-mail scheme; feeds report + Scan Diff.
        self.employees = employees
        # Opt-in CT history (#13) — certificate-transparency timeline (crt.sh):
        # issuers/validity/first-last-seen; feeds report + Scan Diff (new certs).
        self.ct = ct
        # Opt-in active ASN/netblock recon — RDAP CIDR + RIPEstat ASN prefixes +
        # reverse-IP co-hosted hosts (extra network; off by default).
        self.asn_intel = asn_intel
        # Opt-in CVE correlation via OSV.dev — live advisory set per detected JS
        # library; supersedes the bundled dependency-audit table (extra network;
        # off by default).
        self.osv = osv
        # Opt-in security audit (SecurityAuditor) — secrets in served JS,
        # leaking source maps, and reachable GraphQL endpoints. Feeds the risk
        # engine (source-map leaks + GraphQL introspection) and the attack-
        # surface graph. Off by default (extra network: fetches JS + probes
        # conventional GraphQL paths).
        self.security = security
        self.progress_callback: Optional[Callable] = None
        self._cancel = threading.Event()

    def configure(self, profile: Optional[str] = None,
                  max_pages: Optional[int] = None,
                  cookies: Optional[str] = None,
                  capture_delay: Optional[float] = None,
                  screenshots: Optional[bool] = None,
                  nuclei: Optional[bool] = None,
                  katana: Optional[bool] = None,
                  llm: Optional[bool] = None,
                  llm_model: Optional[str] = None,
                  subdomains: Optional[bool] = None,
                  certificate: Optional[bool] = None,
                  openapi: Optional[bool] = None,
                  historical: Optional[bool] = None,
                  dns: Optional[bool] = None,
                  emails: Optional[bool] = None,
                  employees: Optional[bool] = None,
                  ct: Optional[bool] = None,
                  asn_intel: Optional[bool] = None,
                  osv: Optional[bool] = None,
                  security: Optional[bool] = None):
        if profile:
            self.profile = profile
        if max_pages is not None:
            self.max_pages = max_pages
        if cookies is not None:
            self.cookies = cookies
        if screenshots is not None:
            self.screenshots = screenshots
        if nuclei is not None:
            self.nuclei = nuclei
        if katana is not None:
            self.katana = katana
        if llm is not None:
            self.llm = llm
        if llm_model is not None:
            self.llm_model = llm_model
        if subdomains is not None:
            self.subdomains = subdomains
        if certificate is not None:
            self.certificate = certificate
        if openapi is not None:
            self.openapi = openapi
        if historical is not None:
            self.historical = historical
        if dns is not None:
            self.dns = dns
        if emails is not None:
            self.emails = emails
        if employees is not None:
            self.employees = employees
        if ct is not None:
            self.ct = ct
        if asn_intel is not None:
            self.asn_intel = asn_intel
        if osv is not None:
            self.osv = osv
        if security is not None:
            self.security = security
        if capture_delay is not None:
            self.capture_delay = capture_delay

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def cancel(self):
        """Signal the runner to stop at the next phase boundary."""
        self._cancel.set()

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def _cancelled(self, report: Dict) -> bool:
        if self._cancel.is_set():
            report['cancelled'] = True
            self._log('Сбор отменён пользователем')
            return True
        return False

    # ── pipeline ─────────────────────────────────────────────────────────────

    def _scope_skip_active(self, report: Dict, phase: str, url: str) -> Optional[Dict]:
        """Return a Skipped phase if Scope Guard blocks this active phase."""
        decision = active_phase_decision(phase, url, report.get('scope'))
        if decision.allowed:
            return None
        reason = f'scope guard: {decision.reason}'
        entry = decision.as_dict()
        entry['reason'] = reason
        report.setdefault('scope_guard', {}).setdefault(
            'skipped_active_phases', []).append(entry)
        self._log(f'  {phase} - skipped ({reason})')
        return {'status': 'Skipped', 'reason': reason, 'scope_guard': entry}

    def run(self, url: str, output_base: str) -> Dict:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self._cancel.clear()

        domain = _domain_slug(url)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Project workspace: each run is a timestamped scan inside the target's
        # durable project folder (Projects/<slug>/scans/<stamp>/). The scan's
        # internal layout is unchanged, so every existing reader keeps working.
        project = ProjectStore(output_base).get_or_create(url)
        scan_dir = project.start_scan(stamp)
        scope = project.get_scope()

        report: Dict = {
            'url': url,
            'domain': domain,
            'scan_id': stamp,
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'project_dir': str(scan_dir),       # backward-compatible: scan dir
            'project_root': str(project.root),
            'scope': scope,
            'scope_guard': {
                'rate_limit': scope.get('rate_limit'),
                'skipped_active_phases': [],
            },
            'phases': {},
        }

        self._log(f'Проект: {project.root}')
        self._log(f'Скан:   {scan_dir}')

        # 1. Recon
        if not self._cancelled(report):
            report['phases']['recon'] = self._phase_recon(url, scan_dir)
        # 2. API key scan
        if not self._cancelled(report):
            report['phases']['api'] = self._phase_api(url, scan_dir)
        # 3. Capture (frontend)
        capture_dir = scan_dir / 'capture'
        if not self._cancelled(report):
            report['phases']['capture'] = self._phase_capture(url, capture_dir)
        # 4. Clone (frontend) — only if capture produced pages
        if not self._cancelled(report):
            report['phases']['clone'] = self._phase_clone(capture_dir, scan_dir,
                                                          report['phases'].get('capture', {}))
        # 5. Images (media)
        if not self._cancelled(report):
            report['phases']['images'] = self._phase_images(url, scan_dir)
        # 6. Cookie security audit
        if not self._cancelled(report):
            report['phases']['cookies'] = self._phase_cookies(url, scan_dir)
        # 7. Vulnerability scan (aggregates recon + cookie findings)
        if not self._cancelled(report):
            report['phases']['vulns'] = self._phase_vulns(report, scan_dir)
            # Fold leaked secrets (the always-on api phase) into the vuln phase as
            # first-class High findings — so they persist through Findings
            # Management (lifecycle / SLA / triage) and are counted once via their
            # severity, not a second time as a dedicated risk factor. A high-value
            # key still forces a Critical verdict via executive_summary._risk_level
            # (same pattern as takeovers / security-audit exposures).
            added = self._secret_findings(report)
            vulns = report['phases'].get('vulns')
            if added and isinstance(vulns, dict):
                vulns['findings'] = vulns.get('findings', []) + added
                vulns['summary'] = VulnScanner.summarize(vulns['findings'])
        # 7a. Security audit (opt-in) → secrets in served JS, leaking source
        # maps, reachable GraphQL endpoints. Feeds the risk engine (source-map
        # leaks + GraphQL introspection) and the attack-surface graph.
        if self.security and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'security', url)
            report['phases']['security'] = skipped or self._phase_security(
                url, scan_dir, report)
        # 7b. Subdomain enumeration (opt-in) → feeds the takeover risk signal
        # and the Scan Diff subdomain section.
        if self.subdomains and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'subdomains', url)
            report['phases']['subdomains'] = skipped or self._phase_subdomains(
                url, scan_dir)
            # Fold each takeover candidate into the vuln phase as a first-class
            # finding (lifecycle / SLA / triage; counted once via its severity,
            # not a second time as a dedicated risk factor — same pattern as the
            # security-audit exposures). The verdict still forces Critical on any
            # takeover via executive_summary._risk_level.
            added = self._takeover_findings(report)
            vulns = report['phases'].get('vulns')
            if added and isinstance(vulns, dict):
                vulns['findings'] = vulns.get('findings', []) + added
                vulns['summary'] = VulnScanner.summarize(vulns['findings'])
        # 7c. TLS certificate (opt-in) → Scan Diff certificate section.
        if self.certificate and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'certificate', url)
            report['phases']['certificate'] = skipped or self._phase_certificate(
                url, scan_dir)
        # 7d. OpenAPI/Swagger discovery (opt-in) → API map for report/surface/diff.
        if self.openapi and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'openapi', url)
            report['phases']['openapi'] = skipped or self._phase_openapi(
                url, scan_dir)
        # 7e. Historical URL intelligence (opt-in) → archived URLs classified.
        if self.historical and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'historical', url)
            report['phases']['historical'] = skipped or self._phase_historical(
                url, scan_dir)
        # 7f. DNS intelligence (opt-in) → records + email-auth; findings fold
        # into the vuln phase so the risk engine accounts for them.
        if self.dns and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'dns', url)
            report['phases']['dns'] = skipped or self._phase_dns(
                url, scan_dir, report)
        # 7g. Email intelligence (opt-in) → harvested + grouped addresses.
        if self.emails and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'emails', url)
            report['phases']['emails'] = skipped or self._phase_emails(
                url, scan_dir)
        # 7h. Employee intelligence (opt-in) → named people + e-mail scheme.
        if self.employees and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'employees', url)
            report['phases']['employees'] = skipped or self._phase_employees(
                url, scan_dir)
        # 7i. CT history (opt-in) → certificate-transparency timeline (crt.sh).
        if self.ct and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'ct', url)
            report['phases']['ct'] = skipped or self._phase_ct(url, scan_dir)
        # 7j. Active ASN/netblock recon (opt-in) → CIDR + ASN prefixes +
        # reverse-IP co-hosted hosts (needs the recon-derived ip/asn).
        if self.asn_intel and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'asn_intel', url)
            report['phases']['asn_intel'] = skipped or self._phase_asn_intel(
                report, scan_dir)
        # 7k. CVE correlation via OSV.dev (opt-in, active) → live advisories per
        # detected JS library; supersedes the bundled dependency-audit table and
        # folds its findings into the vuln phase (so risk/summary account for them).
        if self.osv and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'osv', url)
            report['phases']['osv'] = skipped or self._phase_osv(report, scan_dir)
        # 8. Katana crawl (opt-in, external) → endpoints for the graph/report
        if self.katana and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'katana', url)
            report['phases']['katana'] = skipped or self._phase_katana(url)
        # 8b. Screenshot (opt-in, Playwright) — captured last; non-fatal/skippable
        if self.screenshots and not self._cancelled(report):
            skipped = self._scope_skip_active(report, 'screenshot', url)
            report['phases']['screenshot'] = skipped or self._phase_screenshot(
                url, scan_dir, report)
        # 9. Analyzer plugins (user-supplied) — see the whole report; their
        # findings fold into vulns so the summary/exec/graph reflect them.
        if not self._cancelled(report):
            report['phases']['analyzers'] = self._phase_analyzers(report)

        report['finished_at'] = datetime.now().isoformat(timespec='seconds')

        # Cross-scanner dedup (DefectDojo-style): collapse findings that share an
        # identity (the same CVE from nuclei + OSV + dependency-audit) into one,
        # accumulating their sources — so the risk score counts a CVE once and the
        # store keeps a single merged finding. Done after every findings-producing
        # phase, before the F1 sync + risk summary below.
        self._dedup_vuln_findings(report)

        # Findings Management (F1): persist findings + run the lifecycle, and
        # stamp this scan's findings with their stored status — BEFORE the
        # summary, so inactive (fixed/ignored/false-positive) ones drop out of
        # the risk verdict below.
        self._sync_findings(report, project, scan_dir.name)
        # Asset Inventory: persist this scan's assets + run their lifecycle
        # (CREATED/SEEN/GONE/REAPPEARED) across scans — the head of the chain.
        self._sync_assets(report, project, scan_dir.name)
        # Cross-entity correlation (F-K2): derive findings↔assets↔infra exposure
        # from the two stores just synced (read-only, no new store).
        self._build_correlation(report, project)
        # Asset Correlation Engine (EPIC 5): asset↔asset topology + shared-infra
        # exposure clusters — relationships between assets, finding-independent.
        self._build_asset_graph(report, project)
        # Related Assets (infra-chain tail): co-hosted external domains sharing our
        # IP (reverse-IP from the opt-in asn_intel phase) — a derive-on-read view,
        # never promoted to owned assets.
        self._build_related_assets(report)
        # Asset Criticality (EPIC 9): rank assets by importance (type + blast radius
        # + attached findings + exposure) — a display metric over the correlation /
        # asset-graph just produced; the risk verdict is untouched.
        self._build_asset_criticality(report, project)
        # Asset Exposure (likelihood axis): rank assets by how reachable / attackable
        # they are right now (reachability + open findings + blast radius, no
        # type-weight) — a display metric complementing criticality's impact axis.
        self._build_exposure(report, project)
        # Core Intelligence Framework (EPIC 7): rank findings by priority with a
        # confidence score + explanation — derived from the findings/correlation/
        # asset-graph just produced (no new data).
        self._build_intelligence(report, project)
        # Attack Paths (EPIC 11): lateral routes over shared infrastructure (entry →
        # pivot → co-located targets) — a display metric over the same views.
        self._build_attack_paths(report, project)
        # Scan Accuracy (MODULE 1): unified confidence per entity (technologies /
        # findings / assets / infra / API / secrets) — derived from the report +
        # stores; flags the lowest-confidence detections to verify.
        self._build_accuracy(report, project)

        # Executive summary: deterministic risk verdict + recommendations over
        # the phases above (no model, no network). This stays authoritative.
        report['executive_summary'] = build_summary(report)
        # Optional: enrich it with a local-Ollama narrative (opt-in, graceful —
        # the verdict above is untouched; a missing Ollama just adds nothing).
        if self.llm and not self._cancelled(report):
            self._attach_llm_narrative(report['executive_summary'])

        # Trend series for the HTML report: this project's metric history — prior
        # scans from metadata.json plus this scan (not yet recorded at render
        # time). Derive-on-read, reuses timeline.build_series (I3) and the single
        # scan-entry flatten; best-effort so a failure never sinks the scan.
        try:
            from core import trends as _trends
            from core.timeline import build_series
            entries = list(project.scans()) + [project._scan_entry(scan_dir, report)]
            report['trends'] = build_series(entries)
            # EPIC 4: per-metric trend analytics over that series (direction /
            # baseline / delta-since-first / peak) — derive-on-read, no new data.
            report['trends_summary'] = _trends.trend_summary(report['trends'])
        except Exception as ex:  # noqa: BLE001 — trends are best-effort
            self._log(f'  ! trend series failed: {ex}')
            report['trends'] = []
            report['trends_summary'] = {}

        # Reports
        json_path = scan_dir / 'report.json'
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8',
        )
        html_path = scan_dir / 'report.html'
        html_path.write_text(self._render_html(report), encoding='utf-8')

        report['report_json'] = str(json_path)
        report['report_html'] = str(html_path)
        report['status'] = 'Cancelled' if report.get('cancelled') else 'Success'

        # Index this scan in the project (metadata.json + history snapshot) so
        # the project remembers its verdict/metrics across runs.
        try:
            report['project_scan'] = project.record_scan(scan_dir, report)
        except Exception as e:  # noqa: BLE001 — indexing must not fail the scan
            self._log(f'  ! project index failed: {e}')

        self._log(f'Отчёт: {html_path}')
        return report

    # ── phases ───────────────────────────────────────────────────────────────

    def _phase_recon(self, url: str, project_dir: Path) -> Dict:
        self._log('[1/7] Recon…')
        try:
            engine = ReconEngine()
            engine.configure(profile=self.profile)
            data = engine.run_recon(url)
            out = project_dir / 'recon'
            out.mkdir(exist_ok=True)
            (out / 'recon.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Recon failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_api(self, url: str, project_dir: Path) -> Dict:
        self._log('[2/7] API key scan…')
        try:
            extractor = ApiKeyExtractor()
            extractor.set_target_url(url)
            extractor.set_profile(self.profile)
            data = extractor.run_extraction()
            out = project_dir / 'api'
            out.mkdir(exist_ok=True)
            (out / 'api_keys.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  API scan failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_capture(self, url: str, capture_dir: Path) -> Dict:
        self._log('[3/7] Capture (frontend)…')
        try:
            cap = SiteContentCapture()
            cap.configure(url, str(capture_dir), self.max_pages,
                          profile=self.profile, delay=self.capture_delay)
            cap.set_progress_callback(self._log)
            data = cap.run_capture()
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Capture failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_clone(self, capture_dir: Path, project_dir: Path,
                     capture_phase: Dict) -> Dict:
        pages = capture_phase.get('data', {}).get('pages_captured', 0)
        if pages == 0:
            self._log('[4/7] Clone — пропущено (нет захваченных страниц)')
            return {'status': 'Skipped', 'reason': 'no captured pages'}
        self._log('[4/7] Clone (frontend)…')
        try:
            clone_dir = project_dir / 'clone'
            cloner = FrontendCloner()
            cloner.configure(str(capture_dir), str(clone_dir), profile=self.profile)
            cloner.set_progress_callback(self._log)
            data = cloner.clone()
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Clone failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_images(self, url: str, project_dir: Path) -> Dict:
        self._log('[5/7] Images (media)…')
        try:
            images_dir = project_dir / 'images'
            ex = ImageExtractor(profile=self.profile, cookies=self.cookies)
            ex.set_progress_callback(self._log)
            data = ex.extract_images(url, str(images_dir))
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Images failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_cookies(self, url: str, project_dir: Path) -> Dict:
        self._log('[6/7] Cookie security audit…')
        try:
            data = CookieAuditor(profile=self.profile).audit(url)
            out = project_dir / 'security'
            out.mkdir(exist_ok=True)
            (out / 'cookies.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Cookie audit failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_vulns(self, report: Dict, project_dir: Path) -> Dict:
        self._log('[7/7] Vulnerability scan…')
        try:
            recon = report['phases'].get('recon', {}).get('data', {})
            cookies = report['phases'].get('cookies', {}).get('data', {})
            findings = VulnScanner().scan(recon, {}, cookies)
            # Optionally enrich with external nuclei findings (same shape), so
            # summary / executive summary / attack surface all account for them.
            nuclei_count = self._merge_nuclei(report.get('url', ''), findings,
                                             report)
            summary = VulnScanner.summarize(findings)
            if nuclei_count:
                summary['nuclei'] = nuclei_count
            out = project_dir / 'security'
            out.mkdir(exist_ok=True)
            (out / 'vulns.json').write_text(
                json.dumps({'summary': summary, 'findings': findings},
                           indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  Findings: {summary['high']} High / "
                      f"{summary['medium']} Medium / {summary['info']} Info")
            return {'status': 'Success', 'findings': findings, 'summary': summary}
        except Exception as e:
            self._log(f'  Vuln scan failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_security(self, url: str, project_dir: Path, report: Dict) -> Dict:
        """Opt-in security audit (SecurityAuditor): secrets in served JS, leaking
        source maps, and reachable GraphQL endpoints.

        Stored as ``phases.security.data`` — the shape the attack-surface graph,
        Scan Diff and the heatmap metrics already read (invariant I3, no
        re-probing). The two risk-bearing exposures (leaking source maps + open
        GraphQL) are also **folded into the vuln phase as findings** (same
        pattern as ``_phase_dns``), so they persist through Findings Management
        (lifecycle / SLA / triage) and feed the risk score via their severity —
        the dedicated risk factors were removed to avoid double counting.
        Guarded — a failure never sinks the scan.
        """
        self._log('[+] Security audit (JS secrets / source maps / GraphQL)…')
        try:
            from core.security_auditor import SecurityAuditor
            auditor = SecurityAuditor(profile=self.profile)
            auditor.set_progress_callback(self.progress_callback)
            auditor.set_cancel_event(self._cancel)
            data = auditor.audit(url)
            summary = data.get('summary', {})
            self._log(
                f"  Source maps: {summary.get('maps_with_content', 0)} с исходниками, "
                f"GraphQL: {summary.get('graphql', 0)} "
                f"(introspection: {summary.get('graphql_introspection', 0)})")
            out = project_dir / 'security'
            out.mkdir(exist_ok=True)
            (out / 'audit.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            # Fold the risk-bearing exposures into the vuln phase as findings, so
            # they live through Findings Management and score via their severity.
            added = self._security_findings(data)
            vulns = report['phases'].get('vulns')
            if added and isinstance(vulns, dict):
                findings = vulns.get('findings', []) + added
                vulns['findings'] = findings
                vulns['summary'] = VulnScanner.summarize(findings)
            return {'status': data.get('status', 'Success'), 'data': data}
        except Exception as e:
            self._log(f'  Security audit failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    @staticmethod
    def _security_findings(data: Dict) -> List[Dict]:
        """Turn the audit's risk-bearing exposures into raw finding dicts.

        Leaking source maps (original source served) → High; an open GraphQL
        schema (introspection) → High; a merely reachable GraphQL API → Info.
        The explicit ``category``/``location`` give each a stable Findings
        identity (one per URL) without re-probing."""
        findings: List[Dict] = []
        for m in data.get('source_maps') or []:
            if isinstance(m, dict) and m.get('has_content'):
                loc = str(m.get('url', ''))
                findings.append({
                    'severity': 'High',
                    'title': 'Source map exposes original source',
                    'detail': f'{loc} — served .map leaks original source code.',
                    'source': 'security-audit', 'category': 'sourcemap',
                    'location': loc})
        for g in data.get('graphql') or []:
            if not (isinstance(g, dict) and g.get('graphql')):
                continue
            loc = str(g.get('url', ''))
            if g.get('introspection'):
                findings.append({
                    'severity': 'High',
                    'title': 'GraphQL introspection enabled',
                    'detail': f'{loc} — full schema exposed via introspection.',
                    'source': 'security-audit', 'category': 'graphql',
                    'location': loc})
            else:
                findings.append({
                    'severity': 'Info',
                    'title': 'GraphQL endpoint exposed',
                    'detail': f'{loc} — reachable GraphQL API (introspection off).',
                    'source': 'security-audit', 'category': 'graphql',
                    'location': loc})
        # Secrets the deep-JS audit found (the api phase sees only the initial
        # page). Folded as first-class secret findings — identical shape to the
        # api-phase secrets, so an overlapping key at the same location dedups by
        # fingerprint. ``source='secret-audit'`` so the auto-FIX scope-guard ties
        # them to the opt-in security phase (a skipped audit ≠ "fixed").
        for s in data.get('secrets') or []:
            if isinstance(s, dict) and s.get('match'):
                f = CollectionRunner._secret_finding(
                    s.get('type', ''), s['match'], s.get('source') or '',
                    source='secret-audit')
                if f:
                    findings.append(f)
        return findings

    @staticmethod
    def _secret_finding(key_type, value, location: str,
                        source: str = 'secret') -> Optional[Dict]:
        """One secret finding dict (High), or ``None`` if the value is a clear
        placeholder / false positive (offline structural validation).

        Shared by the api-phase (``_secret_findings``) and the security-audit
        (``_security_findings``) secret folders so they emit identical,
        fingerprint-dedupable findings. Canonical ``category='secret'`` + an
        explicit non-leaking ``discriminator`` (vendor + masked prefix + length,
        never the plaintext) give a stable identity (one per distinct key);
        ``source`` ties the finding's auto-FIX scope-guard to its producing phase."""
        from core.finding_fingerprint import mask_value, secret_discriminator
        from core.secret_validator import INVALID, validate
        if validate(str(key_type), str(value)).get('status') == INVALID:
            return None
        return {
            'severity': 'High',
            'title': f'Leaked secret: {key_type}',
            'detail': f'{location} — exposed {key_type} ({mask_value(str(value))}).',
            'source': source, 'category': 'secret', 'location': str(location),
            'discriminator': secret_discriminator(str(key_type), str(value))}

    @staticmethod
    def _secret_findings(report: Dict) -> List[Dict]:
        """Turn detected API keys / secrets into first-class findings (High).

        The always-on api phase stores ``details`` = {type: [values]}. Each
        *plausible* secret becomes a High finding so it lives through Findings
        Management (lifecycle / SLA / triage) and is counted once via its severity
        in the risk score (the verdict still forces Critical on a high-value key via
        executive_summary._risk_level). Built via the shared ``_secret_finding``."""
        api = (report.get('phases', {}).get('api') or {}).get('data') or {}
        details = api.get('details')
        if not isinstance(details, dict):
            return []
        loc = str(report.get('url') or report.get('domain') or '')
        findings: List[Dict] = []
        for key_type, values in details.items():
            for v in (values if isinstance(values, list) else [values]):
                f = CollectionRunner._secret_finding(key_type, v, loc)
                if f:
                    findings.append(f)
        return findings

    @staticmethod
    def _takeover_findings(report: Dict) -> List[Dict]:
        """Turn subdomain-takeover candidates into raw finding dicts (High).

        A dangling subdomain that CNAMEs to an unclaimed third-party service is a
        clear-cut, host-locatable issue. Canonical ``category='takeover'`` +
        ``location`` = the host give each a stable Findings identity (one per
        host); the explicit severity feeds the risk score once (the dedicated
        takeover risk factor was removed to avoid double counting)."""
        sub = (report.get('phases', {}).get('subdomains') or {}).get('data') or {}
        summary = sub.get('summary', {}) if isinstance(sub, dict) else {}
        candidates = summary.get('takeover_candidates') or []
        findings: List[Dict] = []
        for c in candidates:
            host = (c.get('subdomain', '') if isinstance(c, dict) else str(c)).strip()
            if not host:
                continue
            findings.append({
                'severity': 'High',
                'title': f'Subdomain takeover possible: {host}',
                'detail': f'{host} — dangling DNS to an unclaimed third-party service.',
                'source': 'subdomain-active', 'category': 'takeover',
                'location': host})
        return findings

    def _phase_analyzers(self, report: Dict) -> Dict:
        """Run user-supplied analyzer plugins over the whole report and fold any
        findings into the vuln phase (so summary/exec/graph include them).

        Opt-in by presence: nothing runs unless the user dropped a plugin into
        plugins/analyzers/. Isolated — a broken plugin is reported, not fatal.
        """
        self._log('[9/9] Analyzer plugins…')
        try:
            errs: list = []
            analyzers = discover_analyzers(
                PLUGINS_DIR / 'analyzers',
                on_error=lambda name, e: errs.append({'plugin': name, 'error': str(e)}),
            )
            if not analyzers and not errs:
                return {'status': 'Skipped', 'reason': 'no analyzer plugins'}

            agg = run_analyzers(analyzers, report)
            errs.extend(agg['errors'])
            added = agg['findings']
            vulns = report['phases'].get('vulns')
            if added and isinstance(vulns, dict):
                findings = vulns.get('findings', []) + added
                vulns['findings'] = findings
                vulns['summary'] = VulnScanner.summarize(findings)
            self._log(f'  Analyzers: {len(analyzers)} plugin(s), '
                      f'{len(added)} finding(s), {len(errs)} error(s)')
            return {'status': 'Success', 'plugins': list(agg['results'].keys()),
                    'findings_added': len(added), 'errors': errs}
        except Exception as e:
            self._log(f'  Analyzer plugins failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_subdomains(self, url: str, project_dir: Path) -> Dict:
        """Enumerate subdomains (passive sources + active takeover detection).

        Wraps the scanner result as ``{summary, results}`` so the executive
        summary finds takeover candidates at ``data.summary.takeover_candidates``
        (the shape the unified risk engine already reads) and Scan Diff reads the
        host list at ``data.results``. Guarded — a failure never sinks the scan.
        """
        from urllib.parse import urlparse
        self._log('[+] Subdomain enumeration…')
        try:
            host = urlparse(url).netloc.split(':')[0] or url
            scanner = SubdomainScanner()
            result = scanner.scan(host, passive=True, brute=False, active=True,
                                  use_cache=True)
            data = {
                'summary': {
                    'total': result.get('total', 0),
                    'live_count': result.get('live_count', 0),
                    'takeover_candidates': result.get('takeover_candidates', []),
                },
                'results': result.get('results', []),
            }
            self._log(f"  Subdomains: {data['summary']['total']} found, "
                      f"{len(data['summary']['takeover_candidates'])} takeover candidate(s)")
            out = project_dir / 'subdomains'
            out.mkdir(exist_ok=True)
            (out / 'subdomains.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            return {'status': result.get('status', 'Success'), 'data': data}
        except Exception as e:
            self._log(f'  Subdomain enumeration failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_certificate(self, url: str, project_dir: Path) -> Dict:
        """Capture the served TLS certificate so Scan Diff can show changes
        (renewal / issuer / SAN) between scans. https only; guarded."""
        from urllib.parse import urlparse
        self._log('[+] TLS certificate…')
        parts = urlparse(url)
        if parts.scheme != 'https':
            return {'status': 'Skipped', 'reason': 'not https'}
        try:
            host = parts.hostname or parts.netloc.split(':')[0]
            cert = fetch_certificate(host, parts.port or 443)
            if not cert:
                return {'status': 'Error', 'reason': 'no certificate retrieved'}
            out = project_dir / 'security'
            out.mkdir(exist_ok=True)
            (out / 'certificate.json').write_text(
                json.dumps(cert, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  Cert: {cert.get('subject', '—')} / "
                      f"issuer {cert.get('issuer', '—')}")
            return {'status': 'Success', 'data': cert}
        except Exception as e:
            self._log(f'  Certificate capture failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_openapi(self, url: str, project_dir: Path) -> Dict:
        """Probe for an OpenAPI/Swagger spec and map its endpoints (opt-in).

        Guarded; a missing spec is a clean 'Not found', never an error. Writes
        openapi/openapi.json so Scan Diff can compare the endpoint set."""
        self._log('[+] OpenAPI discovery…')
        try:
            data = discover_openapi(url)
            if data.get('status') == 'Success':
                out = project_dir / 'openapi'
                out.mkdir(exist_ok=True)
                (out / 'openapi.json').write_text(
                    json.dumps(data, indent=2, ensure_ascii=False, default=str),
                    encoding='utf-8',
                )
                self._log(f"  OpenAPI: {data['counts']['endpoints']} эндпоинтов "
                          f"({data.get('spec_url', '')})")
                return {'status': 'Success', 'data': data}
            self._log('  OpenAPI — спека не найдена')
            return {'status': 'Not found', 'data': data}
        except Exception as e:
            self._log(f'  OpenAPI discovery failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_historical(self, url: str, project_dir: Path) -> Dict:
        """Fetch + classify archived URLs (opt-in, Wayback). Guarded; an empty
        archive is a clean 'No history'. Writes historical/historical.json."""
        self._log('[+] Historical URL intelligence (Wayback)…')
        try:
            data = discover_historical(url)
            if data.get('status') == 'Success':
                out = project_dir / 'historical'
                out.mkdir(exist_ok=True)
                (out / 'historical.json').write_text(
                    json.dumps(data, indent=2, ensure_ascii=False, default=str),
                    encoding='utf-8',
                )
                self._log(f"  Historical: {data['total']} URL, "
                          f"{len(data['interesting'])} интересных")
                return {'status': 'Success', 'data': data}
            self._log('  Historical — архив пуст')
            return {'status': 'No history', 'data': data}
        except Exception as e:
            self._log(f'  Historical intel failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_dns(self, url: str, project_dir: Path, report: Dict) -> Dict:
        """Resolve DNS + email-auth (opt-in, DoH). Guarded; folds its findings
        into the vuln phase so the unified risk engine accounts for them."""
        self._log('[+] DNS intelligence (DoH)…')
        try:
            data = discover_dns(url)
            if data.get('status') != 'Success':
                self._log('  DNS — записи не найдены')
                return {'status': data.get('status', 'No records'), 'data': data}
            out = project_dir / 'dns'
            out.mkdir(exist_ok=True)
            (out / 'dns.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            # Fold DNS findings into the vuln phase (same pattern as analyzers),
            # so summary / executive summary / attack surface include them.
            added = data.get('findings') or []
            vulns = report['phases'].get('vulns')
            if added and isinstance(vulns, dict):
                findings = vulns.get('findings', []) + added
                vulns['findings'] = findings
                vulns['summary'] = VulnScanner.summarize(findings)
            ea = data.get('email_auth', {})
            self._log(f"  DNS: SPF={'да' if ea.get('spf') else 'нет'}, "
                      f"DMARC={ea.get('dmarc') or 'нет'}, "
                      f"DKIM={len(ea.get('dkim_selectors') or [])}, "
                      f"findings={len(added)}")
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  DNS intel failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_emails(self, url: str, project_dir: Path) -> Dict:
        """Harvest + group exposed e-mail addresses (opt-in). Guarded; an empty
        harvest is a clean 'No emails'. Writes emails/emails.json."""
        self._log('[+] Email intelligence…')
        try:
            data = discover_emails(url)
            if data.get('status') != 'Success':
                self._log('  Email — адреса не найдены')
                return {'status': data.get('status', 'No emails'), 'data': data}
            out = project_dir / 'emails'
            out.mkdir(exist_ok=True)
            (out / 'emails.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  Email: {data['total']} адресов "
                      f"(на домене {len(data['on_domain'])})")
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Email intel failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_employees(self, url: str, project_dir: Path) -> Dict:
        """Harvest named people + infer the corporate e-mail scheme (opt-in).
        Guarded; an empty harvest is a clean 'No employees'. Writes
        employees/employees.json."""
        self._log('[+] Employee intelligence…')
        try:
            data = discover_employees(url)
            if data.get('status') != 'Success':
                self._log('  Employee — сотрудники не найдены')
                return {'status': data.get('status', 'No employees'),
                        'data': data}
            out = project_dir / 'employees'
            out.mkdir(exist_ok=True)
            (out / 'employees.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  Employee: {data['total']} чел. "
                      f"(с e-mail {data['with_email']}; "
                      f"формат {data.get('format') or '—'})")
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Employee intel failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_ct(self, url: str, project_dir: Path) -> Dict:
        """Pull the domain's CT history from crt.sh (opt-in). Guarded; an empty
        log is a clean 'No certificates'. Writes ct/ct_history.json."""
        self._log('[+] CT history…')
        try:
            data = discover_ct(url)
            if data.get('status') != 'Success':
                self._log('  CT — сертификаты не найдены')
                return {'status': data.get('status', 'No certificates'),
                        'data': data}
            out = project_dir / 'ct'
            out.mkdir(exist_ok=True)
            (out / 'ct_history.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  CT: {data['total_certs']} сертификатов "
                      f"(имён {data['name_count']}, "
                      f"CA {len(data['issuers'])})")
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  CT history failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_asn_intel(self, report: Dict, project_dir: Path) -> Dict:
        """Active ASN/netblock recon over the recon-derived infrastructure
        (opt-in). Needs recon's ip/asn; guarded and never fatal. Writes
        recon/asn_intel.json."""
        self._log('[+] ASN/netblock intel…')
        try:
            rd = report.get('phases', {}).get('recon', {}).get('data', {})
            infra = rd.get('infrastructure') or {}
            if not (infra.get('ip') or infra.get('asn')):
                self._log('  ASN intel — пропущено (нет IP/ASN из recon)')
                return {'status': 'Skipped', 'reason': 'no ip/asn'}
            data = build_asn_intel(infra)
            out = project_dir / 'recon'
            out.mkdir(exist_ok=True)
            (out / 'asn_intel.json').write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            self._log(f"  ASN intel: CIDR {data.get('cidr') or '—'}, "
                      f"префиксов {data.get('prefix_count', 0)}, "
                      f"со-хостов {data.get('neighbor_count', 0)}")
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  ASN intel failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _phase_osv(self, report: Dict, project_dir: Path) -> Dict:
        """CVE correlation via OSV.dev (opt-in, active). Reads the JS libraries
        already detected by recon's dependency audit, asks OSV for the live
        advisory set, and *supersedes* the bundled table for covered libraries:
        enriches the report card (the library's ``vulnerabilities``) and folds the
        findings into the vuln phase (so risk/summary/surface account for them),
        replacing the bundled dependency-audit findings of those same libraries.
        Writes recon/osv.json. Guarded; degrades to the bundled table on failure."""
        self._log('[+] CVE-корреляция (OSV.dev)…')
        try:
            rd = report.get('phases', {}).get('recon', {}).get('data', {})
            dep = rd.get('dependencies') or {}
            libraries = dep.get('libraries') or []
            if not libraries:
                self._log('  OSV — JS-библиотек с версиями нет')
                return {'status': 'No libraries', 'data': {'correlated': {}}}

            correlated = cve_intel.correlate(libraries)
            if not correlated:
                self._log('  CVE — известных уязвимостей не найдено')
                return {'status': 'Success',
                        'data': {'correlated': {}, 'cve_summary': cve_intel.summarize({})}}

            # Enrich covered libraries' display vulns + build OSV findings, and
            # collect the (name, version) of every covered library so the bundled
            # findings of exactly those can be dropped from the vuln phase.
            osv_findings: List[Dict] = []
            covered: set = set()
            for lib in libraries:
                vulns = correlated.get(lib.get('library'))
                if not vulns:
                    continue
                name, version = lib.get('name', lib.get('library')), lib.get('version', '')
                covered.add((name, version))
                lib['vulnerabilities'] = [
                    {'severity': v['severity'],
                     'cve': (v.get('cve') or [None])[0],
                     'cvss': v.get('cvss'), 'published': v.get('published') or '',
                     'detail': f"{v.get('id', '')}: {v.get('summary', '')}".strip(),
                     'fixed_in': None}
                    for v in vulns
                ]
                osv_findings.extend(cve_intel.to_findings(name, version, vulns))

            # Supersede in the vuln phase: drop the bundled dependency-audit
            # findings of covered libraries (their title is exactly the
            # "Уязвимая библиотека: <name> <version>" prefix), then add OSV's and
            # re-summarize — the same fold-in pattern as _phase_dns.
            def _superseded(f: Dict) -> bool:
                if f.get('source') != 'dependency-audit':
                    return False
                title = f.get('title', '')
                return any(title.startswith(f'Уязвимая библиотека: {n} {v}')
                           for (n, v) in covered)

            vulns_phase = report.get('phases', {}).get('vulns')
            if osv_findings and isinstance(vulns_phase, dict):
                kept = [f for f in vulns_phase.get('findings', [])
                        if not _superseded(f)]
                kept.extend(osv_findings)
                vulns_phase['findings'] = kept
                vulns_phase['summary'] = VulnScanner.summarize(kept)
            # Keep the recon dependency object's own findings list consistent too.
            if osv_findings and isinstance(dep.get('findings'), list):
                dep['findings'] = [f for f in dep['findings']
                                   if not _superseded(f)] + osv_findings

            out = project_dir / 'recon'
            out.mkdir(exist_ok=True)
            (out / 'osv.json').write_text(
                json.dumps(correlated, indent=2, ensure_ascii=False, default=str),
                encoding='utf-8',
            )
            cve_summary = cve_intel.summarize(correlated)
            self._log(f"  CVE: {len(correlated)} библиотек(и) с уязвимостями, "
                      f"{cve_summary['total']} CVE (находок +{len(osv_findings)})")
            return {'status': 'Success',
                    'data': {'correlated': correlated, 'cve_summary': cve_summary}}
        except Exception as e:
            self._log(f'  CVE correlation failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _dedup_vuln_findings(self, report: Dict) -> None:
        """Collapse the vuln phase's findings that share an identity (same CVE
        across scanners) into one + recompute the phase summary. Best-effort: a
        failure here must never sink the scan (same contract as the syncs)."""
        try:
            vulns = report.get('phases', {}).get('vulns')
            if not (isinstance(vulns, dict) and vulns.get('findings')):
                return
            from core.findings_adapter import dedup_findings
            before = len(vulns['findings'])
            deduped = dedup_findings(vulns['findings'])
            if len(deduped) != before:
                vulns['findings'] = deduped
                vulns['summary'] = VulnScanner.summarize(deduped)
                self._log(f'  Dedup: {before} → {len(deduped)} находок '
                          f'(объединено по идентичности/CVE)')
        except Exception as e:  # noqa: BLE001 — dedup must not fail a scan
            self._log(f'  Findings dedup failed: {e}')

    def _sync_findings(self, report: Dict, project, scan_id: str) -> None:
        """Persist this scan's findings + run the F1 lifecycle, then stamp each
        finding with its stored status so the risk engine excludes inactive ones.

        Best-effort: a failure here must never sink an otherwise-good scan."""
        vulns = report.get('phases', {}).get('vulns')
        if not isinstance(vulns, dict) or not isinstance(vulns.get('findings'),
                                                          list):
            return
        try:
            from core.finding_fingerprint import scoped_id
            from core.findings_adapter import from_raw
            from core.findings_store import FindingsStore

            phases = report.get('phases', {})

            def phase_ok(name: str) -> bool:
                p = phases.get(name)
                return isinstance(p, dict) and p.get('status') == 'Success'

            def in_scope(source: str) -> bool:
                # Only auto-FIX an absent finding when the phase that produces
                # its source actually ran this scan (skipped opt-in phase ≠ fixed).
                s = (source or '').lower()
                if s == 'secret':
                    # leaked keys come from the always-on api phase.
                    return phase_ok('api')
                if s == 'secret-audit':
                    # deep-JS secrets come from the opt-in security audit — a
                    # skipped audit must not auto-FIX them.
                    return phase_ok('security')
                if s == 'dns':
                    return phase_ok('dns')
                if s == 'nuclei':
                    p = phases.get('nuclei')
                    if isinstance(p, dict):
                        return p.get('status') == 'Success'
                    return bool(self.nuclei) and phase_ok('vulns')
                if s == 'dependency-audit':
                    return phase_ok('recon')
                if s == 'security-audit':
                    # leaked source maps / open GraphQL come from the opt-in
                    # security phase — not 'fixed' just because it was skipped.
                    return phase_ok('security')
                if s == 'subdomain-active':
                    # subdomain-takeover findings come from the opt-in subdomain
                    # phase — a skipped enumeration must not auto-FIX them.
                    return phase_ok('subdomains')
                return phase_ok('vulns')

            store = FindingsStore()
            result = store.sync(project.slug, scan_id, vulns['findings'],
                                in_scope=in_scope)
            # Stamp each finding with its stored status (for the risk engine).
            # Stored rows are keyed by the project-scoped id, so map each raw
            # finding's bare fingerprint through scoped_id to look it up.
            status_by_id = {f['id']: f['status']
                            for f in store.list_findings(project.slug)}
            for raw in vulns['findings']:
                if isinstance(raw, dict):
                    sid = scoped_id(project.slug, from_raw(raw).id)
                    raw['status'] = status_by_id.get(sid, 'OPEN')
            from core.findings_sla import sla_summary
            active = store.active_findings(project.slug)
            sla = sla_summary(active, reopened=store.reopen_dates(project.slug))
            report['findings'] = {
                'project': project.slug, 'summary': result['summary'],
                'new': len(result['new']), 'reopened': len(result['reopened']),
                'resolved': len(result['resolved']),
                'recurring': len(result['recurring']),
                'sla_breached': sla['breached'],
                'sla_due_soon': sla['due_soon'],
                'sla': sla,
            }
            s = result['summary']
            self._log(f"  Findings: {s['active']} активных / {s['total']} "
                      f"(новых {len(result['new'])}, "
                      f"auto-fixed {len(result['resolved'])})")
        except Exception as e:  # noqa: BLE001 — findings sync must not fail a scan
            self._log(f'  Findings sync failed: {e}')

    def _sync_assets(self, report: Dict, project, scan_id: str) -> None:
        """Persist this scan's assets + run their lifecycle (Asset Inventory).

        Best-effort and read-only over the report — a failure here must never
        sink an otherwise-good scan (same contract as ``_sync_findings``). Marks
        an asset GONE only for types whose producing phase actually ran, so a
        skipped opt-in phase never looks like the asset disappeared."""
        try:
            from core.asset_adapter import ASSET_SOURCE_PHASES, derive_assets
            from core.asset_store import AssetStore

            phases = report.get('phases', {})

            def phase_ok(name: str) -> bool:
                p = phases.get(name)
                return isinstance(p, dict) and p.get('status') == 'Success'

            def in_scope(asset_type: str) -> bool:
                sources = ASSET_SOURCE_PHASES.get(asset_type, ('recon',))
                return any(phase_ok(s) for s in sources)

            def source_in_scope(source: str) -> bool:
                # An asset's stored ``source`` is the producing phase name
                # (recon / subdomains / certificate / ct / asn_intel / katana /
                # openapi). Gate GONE on exactly that phase, so a name seen only
                # in the certificate isn't flapped GONE when the cert phase was
                # skipped but the active subdomain phase ran (F-A1 tail).
                return phase_ok(source)

            assets = derive_assets(report)
            if not assets:
                return
            result = AssetStore().sync(project.slug, scan_id, assets,
                                       in_scope=in_scope,
                                       source_in_scope=source_in_scope)
            s = result['summary']
            report['assets'] = {
                'project': project.slug, 'summary': s,
                'new': len(result['new']), 'gone': len(result['gone']),
                'reappeared': len(result['reappeared']),
                'recurring': len(result['recurring']),
            }
            self._log(f"  Assets: {s['active']} активных / {s['total']} "
                      f"(новых {len(result['new'])}, "
                      f"ушло {len(result['gone'])})")
        except Exception as e:  # noqa: BLE001 — asset sync must not fail a scan
            self._log(f'  Asset sync failed: {e}')

    def _build_correlation(self, report: Dict, project) -> None:
        """Derive cross-entity correlation for the report (F-K2, best-effort).

        Read-only over the findings + asset stores already synced this scan; a
        failure must never sink the scan (same contract as the sync steps).
        Stored compactly in ``report['correlation']`` (summary + top exposed
        assets) for the report card."""
        try:
            from core.correlation import load_correlation
            data = load_correlation(project.slug)
            summary = data.get('summary') or {}
            exposure = data.get('exposure') or []
            if data.get('error') or (not exposure and not summary.get('correlated')):
                return
            report['correlation'] = {'summary': summary,
                                     'exposure': exposure[:10],
                                     'infra_exposure': (data.get('infra_exposure')
                                                        or [])[:5]}
            self._log(f"  Correlation: {summary.get('correlated', 0)}/"
                      f"{summary.get('findings', 0)} находок связаны с активами, "
                      f"exposed: {summary.get('exposed_assets', 0)}")
        except Exception as e:  # noqa: BLE001 — correlation must not fail a scan
            self._log(f'  Correlation failed: {e}')

    def _build_asset_graph(self, report: Dict, project) -> None:
        """Derive the asset relationship graph + exposure clusters (EPIC 5,
        best-effort). Read-only over the asset store just synced; a failure must
        never sink the scan. Stored compactly in ``report['asset_graph']`` (summary
        + top shared-infra clusters) for the report card + the exposure metric."""
        try:
            from core.asset_graph import load_asset_graph
            data = load_asset_graph(project.slug)
            summary = data.get('summary') or {}
            clusters = data.get('shared_infra') or []
            if data.get('error') or not summary.get('nodes'):
                return
            report['asset_graph'] = {'summary': summary,
                                     'shared_infra': clusters[:10]}
            self._log(f"  Asset graph: {summary.get('nodes', 0)} активов, "
                      f"{summary.get('edges', 0)} связей, "
                      f"{summary.get('clusters', 0)} кластер(ов) общей инфры")
        except Exception as e:  # noqa: BLE001 — asset graph must not fail a scan
            self._log(f'  Asset graph failed: {e}')

    def _build_related_assets(self, report: Dict) -> None:
        """Derive the co-hosted Related Assets view (infra-chain tail, best-effort):
        external domains sharing our IP, from the opt-in asn_intel reverse-IP lookup,
        minus our own hosts. Read-only over the report; a failure must never sink the
        scan. Stored in ``report['related_assets']`` for the card + web view."""
        try:
            view = related_assets_from_report(report)
            if not view.get('count'):
                return
            report['related_assets'] = view
            self._log(f"  Related assets: {view['count']} co-hosted домен(ов) "
                      f"на {view.get('shared_ip') or '—'}")
        except Exception as e:  # noqa: BLE001 — related assets must not fail a scan
            self._log(f'  Related assets failed: {e}')

    @classmethod
    def _render_related_assets_card(cls, rdata: Dict) -> str:
        """Offline HTML for the Related Assets card: external domains co-hosted on
        our shared IP (a co-hosted neighbour is not our asset — informational)."""
        e = html.escape
        shared_ip = rdata.get('shared_ip') or '—'
        count, total = rdata.get('count', 0), rdata.get('total', 0)
        extra = max(0, int(total) - int(count))
        head = (f'<p style="font-size:13px;">Co-hosted доменов: <b>{e(str(count))}</b>'
                f' на IP <b>{e(str(shared_ip))}</b>'
                + (f' <span style="color:#888;">(+{extra} наших отфильтровано)</span>'
                   if extra else '') + '</p>')
        chips = ''.join(
            f'<span style="display:inline-block;border:1px solid #1565c0;'
            f'border-radius:10px;padding:1px 8px;margin:2px;font-size:11px;'
            f'color:#1565c0;">{e(str(r.get("host") or ""))}</span>'
            for r in rdata.get('related', []))
        return head + (f'<div>{chips}</div>' if chips else '')

    def _build_asset_criticality(self, report: Dict, project) -> None:
        """Derive the Asset Criticality ranking (EPIC 9, best-effort): assets ranked
        by importance. Read-only over the stores / views just produced; a failure
        must never sink the scan. Stored compactly in ``report['asset_criticality']``
        (summary + top assets) for the report card + the display metric."""
        try:
            from core.intelligence import load_asset_criticality
            data = load_asset_criticality(project.slug)
            summary = data.get('summary') or {}
            if data.get('error') or not summary.get('assets'):
                return
            report['asset_criticality'] = {'summary': summary,
                                           'top': (data.get('top') or [])[:10]}
            self._log(f"  Asset criticality: {summary.get('assets', 0)} активов, "
                      f"top {summary.get('top_criticality', 0)}, "
                      f"{summary.get('high_criticality', 0)} критичных")
        except Exception as e:  # noqa: BLE001 — criticality must not fail a scan
            self._log(f'  Asset criticality failed: {e}')

    @classmethod
    def _render_asset_criticality_card(cls, cdata: Dict) -> str:
        """Offline HTML for the Asset Criticality card: the most important assets
        with their criticality score + band (which asset matters most)."""
        e = html.escape
        summary = cdata.get('summary', {})
        head = (f'<p style="font-size:13px;">Активов: '
                f'<b>{e(str(summary.get("assets", 0)))}</b> · критичных: '
                f'<b>{e(str(summary.get("high_criticality", 0)))}</b> · макс. '
                f'criticality: <b>{e(str(summary.get("top_criticality", 0)))}</b></p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;color:#888;">'
            f'{e(str(i.get("criticality", 0)))}</td>'
            f'<td style="color:{cls._CORR_SEV_COLOR.get("high" if i.get("band")=="high" else "medium" if i.get("band")=="medium" else "info", "#666")};'
            f'font-weight:bold;">{e(str(i.get("band") or "—"))}</td>'
            f'<td style="padding:1px 12px;color:#666;">{e(str(i.get("type") or ""))}</td>'
            f'<td>{e(str(i.get("value") or ""))}</td></tr>'
            for i in cdata.get('top', []))
        table = (f'<table style="font-size:12px;"><tr>'
                 f'<td style="padding-right:12px;"><b>Crit</b></td>'
                 f'<td><b>Band</b></td><td style="padding:0 12px;"><b>Тип</b></td>'
                 f'<td><b>Актив</b></td></tr>{rows}</table>' if rows else '')
        return head + table

    def _build_exposure(self, report: Dict, project) -> None:
        """Derive the Asset Exposure ranking (likelihood axis, best-effort): assets
        ranked by how reachable / attackable they are right now. Read-only over the
        stores / views just produced; a failure must never sink the scan. Stored
        compactly in ``report['exposure']`` (summary + top assets) for the report
        card + the display metric."""
        try:
            from core.intelligence import load_exposure
            data = load_exposure(project.slug)
            summary = data.get('summary') or {}
            if data.get('error') or not summary.get('assets'):
                return
            report['exposure'] = {'summary': summary,
                                  'top': (data.get('top') or [])[:10]}
            self._log(f"  Asset exposure: {summary.get('assets', 0)} активов, "
                      f"top {summary.get('top_exposure', 0)}, "
                      f"{summary.get('exposed_assets', 0)} высокой экспозиции")
        except Exception as e:  # noqa: BLE001 — exposure must not fail a scan
            self._log(f'  Asset exposure failed: {e}')

    @classmethod
    def _render_exposure_card(cls, xdata: Dict) -> str:
        """Offline HTML for the Asset Exposure card: the most exposed assets with
        their exposure score + band (which asset is most attackable right now)."""
        e = html.escape
        summary = xdata.get('summary', {})
        head = (f'<p style="font-size:13px;">Активов: '
                f'<b>{e(str(summary.get("assets", 0)))}</b> · высокой экспозиции: '
                f'<b>{e(str(summary.get("exposed_assets", 0)))}</b> · макс. '
                f'exposure: <b>{e(str(summary.get("top_exposure", 0)))}</b></p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;color:#888;">'
            f'{e(str(i.get("exposure", 0)))}</td>'
            f'<td style="color:{cls._CORR_SEV_COLOR.get("high" if i.get("band")=="high" else "medium" if i.get("band")=="medium" else "info", "#666")};'
            f'font-weight:bold;">{e(str(i.get("band") or "—"))}</td>'
            f'<td style="padding:1px 12px;color:#666;">{e(str(i.get("type") or ""))}</td>'
            f'<td>{e(str(i.get("value") or ""))}</td></tr>'
            for i in xdata.get('top', []))
        table = (f'<table style="font-size:12px;"><tr>'
                 f'<td style="padding-right:12px;"><b>Exp</b></td>'
                 f'<td><b>Band</b></td><td style="padding:0 12px;"><b>Тип</b></td>'
                 f'<td><b>Актив</b></td></tr>{rows}</table>' if rows else '')
        return head + table

    def _build_intelligence(self, report: Dict, project) -> None:
        """Derive the Core Intelligence view (EPIC 7, best-effort): findings ranked
        by priority with a confidence score + explanation. Read-only over the stores
        just synced; a failure must never sink the scan. Stored compactly in
        ``report['intelligence']`` (summary + top items) for the report card."""
        try:
            from core.intelligence import load_intelligence
            data = load_intelligence(project.slug)
            summary = data.get('summary') or {}
            if data.get('error') or not summary.get('findings'):
                return
            report['intelligence'] = {'summary': summary,
                                      'top': (data.get('top') or [])[:10]}
            self._log(f"  Intelligence: {summary.get('findings', 0)} находок, "
                      f"top priority {summary.get('top_priority', 0)}, "
                      f"{summary.get('high_confidence', 0)} высокой уверенности")
        except Exception as e:  # noqa: BLE001 — intelligence must not fail a scan
            self._log(f'  Intelligence failed: {e}')

    def _build_attack_paths(self, report: Dict, project) -> None:
        """Derive lateral Attack Paths (EPIC 11, best-effort): entry → pivot →
        co-located targets over shared infrastructure. Read-only over the views just
        produced; a failure must never sink the scan. Stored compactly in
        ``report['attack_paths']`` (summary + top paths) for the card + the metric."""
        try:
            from core.intelligence import load_attack_paths
            data = load_attack_paths(project.slug)
            summary = data.get('summary') or {}
            if data.get('error') or not summary.get('paths'):
                return
            report['attack_paths'] = {'summary': summary,
                                      'top': (data.get('top') or [])[:10]}
            self._log(f"  Attack paths: {summary.get('paths', 0)} путей, "
                      f"top {summary.get('top_score', 0)}, "
                      f"{summary.get('critical_paths', 0)} критичных")
        except Exception as e:  # noqa: BLE001 — attack paths must not fail a scan
            self._log(f'  Attack paths failed: {e}')

    def _build_accuracy(self, report: Dict, project) -> None:
        """Score the scan's detection accuracy (MODULE 1, best-effort): a unified
        confidence per entity (technologies / findings / assets / infra / API /
        secrets). Read-only over the report + stores; a failure must never sink the
        scan. Stored compactly in ``report['accuracy']`` (summary + per-type averages
        + the lowest-confidence detections to double-check) for the card + metric."""
        try:
            from core.asset_store import AssetStore
            from core.findings_store import FindingsStore
            from core.intelligence import accuracy_from_report
            findings = FindingsStore().active_findings(project.slug)
            assets = AssetStore().list_assets(project=project.slug)
            data = accuracy_from_report(report, findings=findings, assets=assets)
            summary = data.get('summary') or {}
            if not summary.get('entities'):
                return
            by_type = {t: {'count': b.get('count', 0),
                           'avg_confidence': b.get('avg_confidence', 0),
                           'high_confidence': b.get('high_confidence', 0)}
                       for t, b in (data.get('by_type') or {}).items()}
            # The least-confident detections are the ones a triager should verify.
            low = [i for i in reversed(data.get('items') or [])
                   if i.get('band') == 'low'][:10]
            report['accuracy'] = {'summary': summary, 'by_type': by_type,
                                  'low_confidence': low}
            self._log(f"  Scan accuracy: {summary.get('entities', 0)} сущностей, "
                      f"avg confidence {summary.get('avg_confidence', 0)}%, "
                      f"{summary.get('high_confidence', 0)} высокой уверенности")
        except Exception as e:  # noqa: BLE001 — accuracy must not fail a scan
            self._log(f'  Scan accuracy failed: {e}')

    @classmethod
    def _render_accuracy_card(cls, adata: Dict) -> str:
        """Offline HTML for the Scan Accuracy card: average confidence per entity
        type + the lowest-confidence detections to double-check."""
        e = html.escape
        summary = adata.get('summary', {})
        head = (f'<p style="font-size:13px;">Сущностей: '
                f'<b>{e(str(summary.get("entities", 0)))}</b> · средняя уверенность: '
                f'<b>{e(str(summary.get("avg_confidence", 0)))}%</b> · высокой '
                f'уверенности: <b>{e(str(summary.get("high_confidence", 0)))}</b></p>')
        by_type = adata.get('by_type') or {}
        type_rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">{e(str(t))}</td>'
            f'<td style="color:#888;">{e(str(b.get("count", 0)))} шт.</td>'
            f'<td style="font-weight:bold;">{e(str(b.get("avg_confidence", 0)))}%'
            f'</td></tr>'
            for t, b in by_type.items())
        type_table = (f'<table style="font-size:12px;margin:4px 0;">{type_rows}'
                      f'</table>' if type_rows else '')
        low = adata.get('low_confidence') or []
        low_rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;color:#888;">'
            f'{e(str(i.get("entity_type", "")))}</td>'
            f'<td style="padding:1px 12px;">{e(str(i.get("label") or ""))}</td>'
            f'<td style="color:#e64a19;">{e(str(i.get("score", 0)))}% '
            f'({e(str(i.get("verification", "")))})</td></tr>'
            for i in low)
        low_table = (f'<p style="font-size:12px;color:#888;margin:8px 0 2px;">'
                     f'Проверить (низкая уверенность):</p>'
                     f'<table style="font-size:12px;">{low_rows}</table>'
                     if low_rows else '')
        return head + type_table + low_table

    @classmethod
    def _render_attack_paths_card(cls, pdata: Dict) -> str:
        """Offline HTML for the Attack Paths card: lateral routes (entry host →
        shared pivot → co-located targets) with the worst at the top."""
        e = html.escape
        summary = pdata.get('summary', {})
        head = (f'<p style="font-size:13px;">Путей: '
                f'<b>{e(str(summary.get("paths", 0)))}</b> · критичных: '
                f'<b>{e(str(summary.get("critical_paths", 0)))}</b> · макс. '
                f'score: <b>{e(str(summary.get("top_score", 0)))}</b></p>')
        rows = []
        for p in pdata.get('top', []):
            n_targets = len(p.get('targets') or [])
            crit = p.get('critical_targets') or 0
            targets_txt = f'{n_targets} targets' + (f' ({crit} crit)' if crit else '')
            sev_color = cls._CORR_SEV_COLOR.get(
                str(p.get('entry_severity', '')).lower(), '#666')
            rows.append(
                f'<tr><td style="padding:1px 12px 1px 0;color:#888;">'
                f'{e(str(p.get("score", 0)))}</td>'
                f'<td style="color:{sev_color};font-weight:bold;">'
                f'{e(str(p.get("entry") or ""))}</td>'
                f'<td style="padding:1px 12px;color:#666;">→ '
                f'{e(str(p.get("pivot_type") or ""))}: '
                f'{e(str(p.get("pivot_node") or ""))} →</td>'
                f'<td>{e(targets_txt)}</td></tr>')
        table = (f'<table style="font-size:12px;"><tr>'
                 f'<td style="padding-right:12px;"><b>Score</b></td>'
                 f'<td><b>Entry</b></td><td style="padding:0 12px;"><b>Pivot</b></td>'
                 f'<td><b>Targets</b></td></tr>{"".join(rows)}</table>'
                 if rows else '')
        return head + table

    @classmethod
    def _render_intelligence_card(cls, idata: Dict) -> str:
        """Offline HTML for the Priorities card: the highest-priority findings with
        their priority + confidence (what to fix first, and how sure)."""
        e = html.escape
        summary = idata.get('summary', {})
        head = (f'<p style="font-size:13px;">Находок: '
                f'<b>{e(str(summary.get("findings", 0)))}</b> · высокой уверенности: '
                f'<b>{e(str(summary.get("high_confidence", 0)))}</b> · макс. '
                f'приоритет: <b>{e(str(summary.get("top_priority", 0)))}</b></p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;color:#888;">'
            f'{e(str(i.get("priority", 0)))}</td>'
            f'<td style="color:{cls._CORR_SEV_COLOR.get(str(i.get("severity","")).lower(), "#666")};'
            f'font-weight:bold;">{e(str(i.get("severity") or "—"))}</td>'
            f'<td style="padding:1px 12px;">{e(str(i.get("title") or ""))}</td>'
            f'<td style="color:#666;">conf {e(str(i.get("confidence", 0)))}% '
            f'({e(str(i.get("confidence_band", "")))})</td></tr>'
            for i in idata.get('top', []))
        table = (f'<table style="font-size:12px;"><tr>'
                 f'<td style="padding-right:12px;"><b>Prio</b></td>'
                 f'<td><b>Sev</b></td><td style="padding:0 12px;"><b>Находка</b></td>'
                 f'<td><b>Confidence</b></td></tr>{rows}</table>' if rows else '')
        return head + table

    @classmethod
    def _render_asset_graph_card(cls, gdata: Dict) -> str:
        """Offline HTML for the Asset Relationships card: graph size + the
        shared-infrastructure exposure clusters (a node many assets depend on)."""
        e = html.escape
        summary = gdata.get('summary', {})
        head = (f'<p style="font-size:13px;">Связей между активами: '
                f'<b>{e(str(summary.get("edges", 0)))}</b> на '
                f'{e(str(summary.get("nodes", 0)))} активов · кластеров общей '
                f'инфраструктуры: <b>{e(str(summary.get("clusters", 0)))}</b></p>')
        clusters = gdata.get('shared_infra') or []
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">{e(str(r.get("type", "")))}: '
            f'<b>{e(str(r.get("node", "")))}</b></td>'
            f'<td style="color:#e64a19;font-weight:bold;">{e(str(r.get("count", 0)))} '
            f'актив.</td>'
            f'<td style="color:#666;">{e(", ".join(map(str, r.get("members", [])[:6])))}'
            f'{"…" if len(r.get("members", [])) > 6 else ""}</td></tr>'
            for r in clusters)
        table = (f'<p style="font-size:12px;color:#888;margin:8px 0 2px;">'
                 f'Single points of exposure (общая инфраструктура):</p>'
                 f'<table style="font-size:12px;">{rows}</table>' if rows else '')
        return head + table

    # Severity → cell colour for the light-background report card.
    _CORR_SEV_COLOR = {'critical': '#c62828', 'high': '#e64a19',
                       'medium': '#f9a825', 'low': '#2e7d32', 'info': '#666'}

    @classmethod
    def _render_correlation_card(cls, cdata: Dict) -> str:
        """Offline HTML for the Exposure-by-Asset card: which assets carry which
        findings (worst severity + count), derived by correlation (F-K2)."""
        e = html.escape
        summary = cdata.get('summary', {})
        head = (f'<p style="font-size:13px;">Находок связано с активами: '
                f'<b>{e(str(summary.get("correlated", 0)))}</b> из '
                f'{e(str(summary.get("findings", 0)))} · затронуто активов: '
                f'<b>{e(str(summary.get("exposed_assets", 0)))}</b></p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">'
            f'{e(str(r.get("label") or r.get("value", "")))}</td>'
            f'<td style="color:{cls._CORR_SEV_COLOR.get(r.get("worst"), "#666")};'
            f'font-weight:bold;">{e(str(r.get("worst") or "—"))}</td>'
            f'<td style="color:#666;">{e(str(r.get("findings_count", 0)))}</td></tr>'
            for r in cdata.get('exposure', []))
        table = (f'<table style="font-size:12px;"><tr>'
                 f'<td style="padding-right:12px;"><b>Актив</b></td>'
                 f'<td><b>Worst</b></td><td><b>Находок</b></td></tr>'
                 f'{rows}</table>' if rows else '')
        # F-K7: infra blast-radius — which ip/asn/netblock concentrates findings.
        infra = cdata.get('infra_exposure') or []
        infra_rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">'
            f'{e(str(r.get("type", "")))}: {e(str(r.get("node", "")))}</td>'
            f'<td style="color:{cls._CORR_SEV_COLOR.get(r.get("worst"), "#666")};'
            f'font-weight:bold;">{e(str(r.get("worst") or "—"))}</td>'
            f'<td style="color:#666;">{e(str(r.get("findings_count", 0)))} '
            f'· {e(str(r.get("host_count", 0)))} хост.</td></tr>'
            for r in infra)
        infra_table = (
            f'<p style="font-size:12px;color:#888;margin:8px 0 2px;">'
            f'Инфраструктура (blast radius):</p>'
            f'<table style="font-size:12px;">{infra_rows}</table>'
            if infra_rows else '')
        return head + table + infra_table

    @staticmethod
    def _render_findings_card(fdata: Dict) -> str:
        """Offline HTML for the Findings Management card: this scan's delta +
        the project's status breakdown."""
        from core.findings_store import STATUS_LABELS as labels
        e = html.escape
        summary = fdata.get('summary', {})
        by_status = summary.get('by_status', {})
        delta = (f'<p style="font-size:13px;">Изменения за скан: '
                 f'<b>+{e(str(fdata.get("new", 0)))}</b> новых, '
                 f'{e(str(fdata.get("reopened", 0)))} переоткрыто, '
                 f'{e(str(fdata.get("resolved", 0)))} авто-исправлено '
                 f'(активных: <b>{e(str(summary.get("active", 0)))}</b> '
                 f'из {e(str(summary.get("total", 0)))})</p>')
        breached = fdata.get('sla_breached', 0)
        if breached:
            delta += (f'<p style="font-size:13px;color:#c62828;">'
                      f'⚠ Просрочено по SLA: <b>{e(str(breached))}</b></p>')
        due_soon = fdata.get('sla_due_soon', 0)
        if due_soon:
            delta += (f'<p style="font-size:13px;color:#ef6c00;">'
                      f'⏳ Скоро срок по SLA: <b>{e(str(due_soon))}</b></p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">{e(labels.get(st, st))}</td>'
            f'<td style="color:#666;">{e(str(by_status.get(st, 0)))}</td></tr>'
            for st in ('OPEN', 'IN_PROGRESS', 'FIXED', 'IGNORED', 'FALSE_POSITIVE')
            if by_status.get(st))
        table = (f'<table style="font-size:12px;">{rows}</table>' if rows else '')
        return delta + table

    @staticmethod
    def _render_assets_card(adata: Dict) -> str:
        """Offline HTML for the Asset Inventory card: this scan's delta +
        the project's active/total and per-type breakdown."""
        e = html.escape
        summary = adata.get('summary', {})
        by_type = summary.get('by_type', {})
        delta = (f'<p style="font-size:13px;">Изменения за скан: '
                 f'<b>+{e(str(adata.get("new", 0)))}</b> новых, '
                 f'{e(str(adata.get("reappeared", 0)))} вернулось, '
                 f'{e(str(adata.get("gone", 0)))} исчезло '
                 f'(активных: <b>{e(str(summary.get("active", 0)))}</b> '
                 f'из {e(str(summary.get("total", 0)))})</p>')
        rows = ''.join(
            f'<tr><td style="padding:1px 12px 1px 0;">{e(str(t))}</td>'
            f'<td style="color:#666;">{e(str(c))}</td></tr>'
            for t, c in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))
            if c)
        table = (f'<table style="font-size:12px;">{rows}</table>' if rows else '')
        return delta + table

    @staticmethod
    def _render_trends_card(trends: list) -> str:
        """Offline HTML for the Trends card: sparklines of the project's metric
        history over its scans (F5). Reuses the offline-SVG ``sparkline`` (the
        dashboard's chart helper, no new deps). Rendered only with ≥2 scans — a
        single point is not a trend."""
        from core.dashboard_charts import sparkline
        e = html.escape
        pts = [p for p in (trends or []) if isinstance(p, dict)]
        if len(pts) < 2:
            return ''

        def _f(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None

        # (label, series-key, line colour) — the metrics build_series exposes.
        metrics = [
            ('Risk score',     'risk_score',     '#c62828'),
            ('Attack surface', 'attack_surface', '#6a1b9a'),
            ('Secrets',        'secrets',        '#ad1457'),
            ('High vulns',     'high',           '#ef6c00'),
        ]
        tiles = []
        for label, key, color in metrics:
            series = [_f(p.get(key)) for p in pts]
            if not any(v is not None for v in series):
                continue
            latest = next((v for v in reversed(series) if v is not None), None)
            latest_txt = ('—' if latest is None else
                          str(int(latest)) if float(latest).is_integer()
                          else f'{latest:.1f}')
            svg = sparkline(series, color=color, width=220, height=44)
            tiles.append(
                f'<figure style="margin:0;width:220px;">'
                f'<figcaption style="font-size:12px;color:#666;'
                f'margin-bottom:2px;">{e(label)}: <b style="color:#222;">'
                f'{e(latest_txt)}</b></figcaption>{svg}</figure>')
        if not tiles:
            return ''
        # EPIC 4: a one-line risk-trend verdict over the same series (direction +
        # change since the first scan) — the analytics next to the sparklines.
        from core import trends as _trends
        rt = _trends.metric_trend(pts, 'risk_score')
        caption = ''
        if rt:
            arrow = {'up': '↑', 'down': '↓', 'flat': '→'}[rt['direction']]
            word = {'up': 'рост', 'down': 'спад', 'flat': 'без изменений'}[rt['direction']]
            color = {'up': '#c62828', 'down': '#2e7d32', 'flat': '#666'}[rt['direction']]
            delta = rt['delta_total']
            sign = '+' if isinstance(delta, (int, float)) and delta > 0 else ''
            caption = (f' Риск: <b style="color:{color};">{arrow} {e(word)}</b> '
                       f'({e(str(rt["baseline"]))} → {e(str(rt["current"]))}, '
                       f'{sign}{e(str(delta))} с первого скана).')
        return (f'<p style="font-size:13px;">История за '
                f'<b>{e(str(len(pts)))}</b> скан(ов) — самые свежие справа.{caption}</p>'
                f'<div style="display:flex;flex-wrap:wrap;gap:16px;">'
                f'{"".join(tiles)}</div>')

    def _phase_katana(self, url: str) -> Dict:
        self._log('[8/8] Katana crawl…')
        if not KatanaRunner.available():
            self._log('  Katana — пропущено (бинарь не установлен)')
            return {'status': 'Skipped', 'reason': 'katana not installed'}
        try:
            runner = KatanaRunner()
            runner.set_progress_callback(self._log)
            data = runner.crawl(url)
            if data.get('status') == 'Success':
                return {'status': 'Success', 'data': data}
            return {'status': data.get('status', 'Error'),
                    'reason': data.get('error', 'katana failed')}
        except Exception as e:
            self._log(f'  Katana failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    def _merge_nuclei(self, url: str, findings: list,
                      report: Optional[Dict] = None) -> int:
        """Run nuclei (if enabled + installed) and append its findings in place.

        Returns the number of nuclei findings added. Opt-in and best-effort: a
        missing binary or any failure is logged and ignored — the native scan
        result still stands.
        """
        if not self.nuclei or not url:
            return 0
        if report is not None:
            skipped = self._scope_skip_active(report, 'nuclei', url)
            if skipped:
                report.setdefault('phases', {})['nuclei'] = skipped
                return 0
        if not NucleiRunner.available():
            self._log('  nuclei — пропущено (бинарь не установлен)')
            return 0
        runner = NucleiRunner()
        runner.set_progress_callback(self._log)
        data = runner.scan(url)
        extra = data.get('findings', [])
        findings.extend(extra)
        if report is not None:
            report.setdefault('phases', {})['nuclei'] = {
                'status': data.get('status', 'Success'),
                'data': {'findings_added': len(extra)},
            }
        return len(extra)

    def _attach_llm_narrative(self, summary: Dict) -> None:
        """Add a local-Ollama narrative to the deterministic summary in place.

        Best-effort: an unavailable/failing Ollama logs and adds nothing, so
        the report is identical to a non-LLM run. The verdict/metrics are never
        modified — only a ``narrative`` (+ model) field is added on success.
        """
        self._log('[LLM] Локальное AI-резюме (Ollama)…')
        model = self.llm_model or _LLM_DEFAULT_MODEL
        result = generate_llm_narrative(summary, model=model, log=self._log)
        if result.get('status') == 'Success':
            summary['narrative'] = result['narrative']
            summary['narrative_model'] = result.get('model', model)
            self._log('  AI-резюме добавлено')
        else:
            self._log(f'  AI-резюме пропущено ({result.get("status")})')

    def _phase_screenshot(self, url: str, project_dir: Path,
                          report: Dict) -> Dict:
        self._log('[8/8] Screenshot…')
        if not ScreenshotCapturer.available():
            self._log('  Screenshot — пропущено (Playwright не установлен)')
            return {'status': 'Skipped', 'reason': 'playwright not installed'}
        try:
            # Multi-page (Aquatone-style): homepage + crawled login/admin/… +
            # a bounded probe of common paths. Targets are chosen from the
            # report the pipeline already built (its site_map), no extra crawl.
            targets = select_screenshot_targets(report, base_url=url)
            cap = ScreenshotCapturer()
            cap.set_progress_callback(self._log)
            shots = cap.capture_many(targets, project_dir / 'screenshots')
            ok = [s for s in shots if s.get('status') == 'Success']
            if not ok:
                return {'status': 'Error', 'data': {'shots': shots},
                        'reason': 'no screenshots captured'}
            # Backward-compatible: keep a top-level rel_path (the homepage shot,
            # or the first success) so older report readers still find an image.
            home = next((s for s in shots
                         if s['label'] == 'home' and s.get('rel_path')), ok[0])
            data = {'shots': shots, 'rel_path': home.get('rel_path')}
            self._log(f'  Screenshots: {len(ok)}/{len(shots)} страниц(ы)')
            return {'status': 'Success', 'data': data}
        except Exception as e:
            self._log(f'  Screenshot failed: {e}')
            return {'status': 'Error', 'error': str(e)}

    # ── HTML report ──────────────────────────────────────────────────────────

    def _render_html(self, report: Dict) -> str:
        e = html.escape
        phases = report.get('phases', {})

        def card(title: str, body: str, status: str) -> str:
            colour = {'Success': '#2e7d32', 'Error': '#c62828',
                      'Skipped': '#f9a825'}.get(status, '#555')
            return (
                f'<section style="border:1px solid #ddd;border-left:5px solid {colour};'
                f'border-radius:6px;margin:12px 0;padding:12px 16px;">'
                f'<h2 style="margin:0 0 8px;font-size:16px;">{e(title)} '
                f'<span style="color:{colour};font-size:13px;">[{e(status)}]</span></h2>'
                f'{body}</section>'
            )

        def kv(d: Dict, keys) -> str:
            rows = []
            for k in keys:
                if k in d and d[k] not in (None, '', [], {}):
                    rows.append(
                        f'<tr><td style="color:#666;padding:2px 12px 2px 0;">{e(str(k))}</td>'
                        f'<td>{e(str(d[k]))}</td></tr>'
                    )
            return f'<table style="font-size:13px;">{"".join(rows)}</table>' if rows else ''

        body_parts = []

        # Recon
        recon = phases.get('recon', {})
        rd = recon.get('data', {})
        body_parts.append(card(
            'Recon & Intel',
            kv(rd, ['ip', 'status']) + (
                f'<p style="font-size:13px;">CMS / Stack: '
                f'{e(", ".join(rd.get("cms", [])) or "—")}<br>'
                f'Favicons: {len(rd.get("favicons", []))}</p>'
            ),
            recon.get('status', '—'),
        ))

        # Infrastructure intelligence — Domain → ASN → IP → Provider chain.
        infra = rd.get('infrastructure')
        if infra and infra.get('chain'):
            body_parts.append(card(
                'Infrastructure', render_infrastructure(infra),
                recon.get('status', '—'),
            ))

        # Active ASN/netblock intel (opt-in) — CIDR + ASN prefixes + co-hosts.
        asn_phase = phases.get('asn_intel')
        if isinstance(asn_phase, dict) and asn_phase.get('status') == 'Success':
            body_parts.append(card(
                'ASN Intelligence', render_asn_intel(asn_phase.get('data')),
                asn_phase.get('status', '—'),
            ))

        # Related Assets (infra-chain tail) — co-hosted external domains on our IP.
        rel = report.get('related_assets')
        if isinstance(rel, dict) and rel.get('count'):
            body_parts.append(card(
                'Related Assets', self._render_related_assets_card(rel),
                f"{rel.get('count', 0)} co-hosted",
            ))

        # Technology fingerprint — CDN / server / backend / analytics + versions.
        technologies = rd.get('technologies')
        if technologies:
            body_parts.append(card(
                'Technology Fingerprint', render_technologies(technologies),
                recon.get('status', '—'),
            ))

        # Dependencies — detected JS libraries + versions, vulnerable ones flagged.
        dependencies = rd.get('dependencies')
        if dependencies and dependencies.get('libraries'):
            body_parts.append(card(
                'Dependencies (JS libraries)', render_dependencies(dependencies),
                recon.get('status', '—'),
            ))

        # API
        api = phases.get('api', {})
        ad = api.get('data', {})
        body_parts.append(card(
            'API Key Scan',
            f'<p style="font-size:13px;">Найдено ключей: '
            f'<b>{e(str(ad.get("keys_found", 0)))}</b></p>',
            api.get('status', '—'),
        ))

        # Capture
        cap = phases.get('capture', {})
        cd = cap.get('data', {})
        body_parts.append(card(
            'Capture (Frontend)',
            f'<p style="font-size:13px;">Страниц захвачено: '
            f'<b>{e(str(cd.get("pages_captured", 0)))}</b>, '
            f'ошибок: {len(cd.get("errors", []))}</p>',
            cap.get('status', '—'),
        ))

        # Site Map — visual tree of crawled paths coloured by HTTP status.
        site_map = cd.get('site_map')
        if site_map:
            body_parts.append(card(
                'Site Map', render_site_map(site_map), cap.get('status', '—'),
            ))

        # Subdomains (opt-in enumeration) — list with takeover candidates flagged.
        subdomains = phases.get('subdomains')
        if subdomains:
            sdata = subdomains.get('data', {})
            results = sdata.get('results', [])
            summ = sdata.get('summary', {})
            takeovers = set(summ.get('takeover_candidates', []))
            if results:
                items = ''.join(
                    f'<li style="margin:1px 0;{"color:#c62828;font-weight:bold;" if h.get("subdomain") in takeovers else ""}">'
                    f'{e(str(h.get("subdomain", "")))}'
                    f'{" ⚠ takeover" if h.get("subdomain") in takeovers else ""}</li>'
                    for h in results[:40])
                sbody = (f'<p style="font-size:13px;">Субдоменов: '
                         f'<b>{e(str(summ.get("total", len(results))))}</b>, '
                         f'takeover-кандидатов: '
                         f'<b>{e(str(len(takeovers)))}</b></p>'
                         f'<ul style="font-size:12px;color:#444;margin:6px 0;'
                         f'max-height:240px;overflow:auto;">{items}</ul>')
            else:
                sbody = (f'<p style="font-size:13px;color:#999;">'
                         f'{e(subdomains.get("reason", "субдомены не найдены"))}</p>')
            body_parts.append(card('Subdomains', sbody,
                                   subdomains.get('status', '—')))

        # TLS certificate (opt-in) — served-cert fields.
        certificate = phases.get('certificate')
        if certificate:
            cdata = certificate.get('data', {})
            if cdata:
                _CERT_LABELS = [
                    ('subject', 'Subject'), ('issuer', 'Issuer'),
                    ('not_before', 'Not before'), ('not_after', 'Not after'),
                    ('serial', 'Serial'), ('sans', 'SANs'),
                    ('fingerprint_sha256', 'SHA-256'),
                ]
                rows = ''.join(
                    f'<tr><td style="color:#666;padding:2px 12px 2px 0;">{e(lbl)}</td>'
                    f'<td style="word-break:break-all;">{e(str(cdata[key]))}</td></tr>'
                    for key, lbl in _CERT_LABELS if cdata.get(key))
                cbody = f'<table style="font-size:13px;">{rows}</table>'
            else:
                cbody = (f'<p style="font-size:13px;color:#999;">'
                         f'{e(certificate.get("reason", "—"))}</p>')
            body_parts.append(card('TLS Certificate', cbody,
                                   certificate.get('status', '—')))

        # Katana endpoints (opt-in external crawl).
        katana = phases.get('katana')
        if katana:
            kd = katana.get('data', {})
            endpoints = kd.get('endpoints', [])
            if endpoints:
                items = ''.join(
                    f'<li style="margin:1px 0;">{e(str(u))}</li>'
                    for u in endpoints[:25])
                kbody = (f'<p style="font-size:13px;">Эндпоинтов найдено: '
                         f'<b>{e(str(len(endpoints)))}</b></p>'
                         f'<ul style="font-size:12px;color:#444;margin:6px 0;'
                         f'max-height:220px;overflow:auto;">{items}</ul>')
            else:
                kbody = (f'<p style="font-size:13px;color:#999;">'
                         f'{e(katana.get("reason", "—"))}</p>')
            body_parts.append(card('Katana Endpoints', kbody,
                                   katana.get('status', '—')))

        # OpenAPI / Swagger (opt-in) — discovered API map.
        openapi = phases.get('openapi')
        if openapi:
            odata = openapi.get('data', {})
            body_parts.append(card('OpenAPI / API Map', render_openapi(odata),
                                   openapi.get('status', '—')))

        # Historical URLs (opt-in) — archived URLs classified (Wayback).
        historical = phases.get('historical')
        if historical:
            hdata = historical.get('data', {})
            body_parts.append(card('Historical URLs', render_historical(hdata),
                                   historical.get('status', '—')))

        # DNS intelligence (opt-in) — records + email-auth posture.
        dns = phases.get('dns')
        if dns:
            ddata = dns.get('data', {})
            body_parts.append(card('DNS / Email Auth', render_dns(ddata),
                                   dns.get('status', '—')))

        # Email intelligence (opt-in) — harvested + grouped addresses.
        emails = phases.get('emails')
        if emails:
            edata = emails.get('data', {})
            body_parts.append(card('Email Intelligence', render_emails(edata),
                                   emails.get('status', '—')))

        # Employee intelligence (opt-in) — named people + e-mail scheme.
        employees = phases.get('employees')
        if employees:
            empdata = employees.get('data', {})
            body_parts.append(card('Employee Intelligence',
                                   render_employees(empdata),
                                   employees.get('status', '—')))

        # CT history (opt-in) — certificate-transparency timeline.
        ct = phases.get('ct')
        if ct:
            ctdata = ct.get('data', {})
            body_parts.append(card('Certificate Transparency',
                                   render_ct(ctdata), ct.get('status', '—')))

        # Clone
        clone = phases.get('clone', {})
        cl = clone.get('data', {})
        clone_body = (
            f'<p style="font-size:13px;">Страниц: '
            f'<b>{e(str(cl.get("pages_processed", 0)))}</b>, '
            f'ассетов: {e(str(cl.get("assets_downloaded", 0)))}</p>'
            if cl else f'<p style="font-size:13px;color:#999;">'
                       f'{e(clone.get("reason", "—"))}</p>'
        )
        body_parts.append(card('Clone (Frontend)', clone_body, clone.get('status', '—')))

        # Images
        img = phases.get('images', {})
        imd = img.get('data', {})
        body_parts.append(card(
            'Images (Media)',
            f'<p style="font-size:13px;">Найдено: {e(str(imd.get("found", 0)))}, '
            f'загружено: <b>{e(str(imd.get("downloaded", 0)))}</b>, '
            f'дубликатов: {e(str(imd.get("duplicates", 0)))}</p>',
            img.get('status', '—'),
        ))

        # Cookie security
        ck = phases.get('cookies', {})
        ckd = ck.get('data', {})
        body_parts.append(card(
            'Cookie Security',
            f'<p style="font-size:13px;">Куки: {e(str(ckd.get("total", 0)))}, '
            f'слабых: <b>{e(str(ckd.get("weak", 0)))}</b></p>',
            ck.get('status', '—'),
        ))

        # Security audit (opt-in) — leaking source maps + reachable GraphQL.
        security = phases.get('security')
        if security:
            secd = security.get('data', {})
            ssum = secd.get('summary', {})
            smaps = [m for m in secd.get('source_maps', [])
                     if isinstance(m, dict) and m.get('has_content')]
            gql = [g for g in secd.get('graphql', [])
                   if isinstance(g, dict) and g.get('graphql')]
            if smaps or gql or ssum:
                map_items = ''.join(
                    f'<li style="margin:1px 0;">{e(str(m.get("url", "")))}</li>'
                    for m in smaps[:25])
                gql_items = ''.join(
                    f'<li style="margin:1px 0;'
                    f'{"color:#c62828;font-weight:bold;" if g.get("introspection") else ""}">'
                    f'{e(str(g.get("url", "")))}'
                    f'{" ⚠ introspection" if g.get("introspection") else ""}</li>'
                    for g in gql[:25])
                secbody = (
                    f'<p style="font-size:13px;">Source maps с исходниками: '
                    f'<b>{e(str(ssum.get("maps_with_content", len(smaps))))}</b>, '
                    f'GraphQL-эндпоинтов: <b>{e(str(ssum.get("graphql", len(gql))))}</b> '
                    f'(introspection: '
                    f'<b>{e(str(ssum.get("graphql_introspection", 0)))}</b>)</p>')
                if map_items:
                    secbody += (f'<p style="font-size:12px;color:#666;margin:6px 0 2px;">'
                                f'Source maps:</p><ul style="font-size:12px;color:#444;'
                                f'margin:0 0 6px;max-height:160px;overflow:auto;">'
                                f'{map_items}</ul>')
                if gql_items:
                    secbody += (f'<p style="font-size:12px;color:#666;margin:6px 0 2px;">'
                                f'GraphQL:</p><ul style="font-size:12px;color:#444;'
                                f'margin:0 0 6px;max-height:160px;overflow:auto;">'
                                f'{gql_items}</ul>')
            else:
                secbody = (f'<p style="font-size:13px;color:#999;">'
                           f'{e(security.get("reason", "ничего не обнаружено"))}</p>')
            body_parts.append(card('Security Audit', secbody,
                                   security.get('status', '—')))

        # Vulnerabilities
        vuln = phases.get('vulns', {})
        vs = vuln.get('summary', {})
        findings = vuln.get('findings', [])
        items = ''.join(
            f'<li style="margin:2px 0;"><b>[{e(f.get("severity",""))}]</b> '
            f'{e(f.get("title",""))}</li>'
            for f in findings[:15]
        )
        sev_bar = stacked_bar([
            ('High', vs.get('high', 0), '#c62828'),
            ('Medium', vs.get('medium', 0), '#f9a825'),
            ('Info', vs.get('info', 0), '#2e7d32'),
        ], empty_note='Уязвимостей не найдено')
        vuln_body = (
            f'<p style="font-size:13px;">risk score: '
            f'<b>{e(str(vs.get("risk_score", 0)))}</b></p>'
            f'{sev_bar}'
            f'<ul style="font-size:12px;color:#444;margin:6px 0;">{items}</ul>'
        )
        body_parts.append(card('Vulnerabilities', vuln_body, vuln.get('status', '—')))

        # Findings Management (F1) — persistent triage state + this scan's delta.
        fdata = report.get('findings')
        if isinstance(fdata, dict) and fdata.get('summary'):
            fsum = fdata['summary']
            body_parts.append(card(
                'Findings Management', self._render_findings_card(fdata),
                f"{fsum.get('active', 0)}/{fsum.get('total', 0)} активных"))

        # Asset Inventory — persistent asset registry + this scan's delta.
        adata = report.get('assets')
        if isinstance(adata, dict) and adata.get('summary'):
            asum = adata['summary']
            body_parts.append(card(
                'Asset Inventory', self._render_assets_card(adata),
                f"{asum.get('active', 0)}/{asum.get('total', 0)} активных"))

        # Exposure by Asset (F-K2) — findings ↔ assets correlation.
        cdata = report.get('correlation')
        if isinstance(cdata, dict) and cdata.get('summary'):
            csum = cdata['summary']
            body_parts.append(card(
                'Exposure by Asset', self._render_correlation_card(cdata),
                f"{csum.get('correlated', 0)}/{csum.get('findings', 0)} связано"))

        # Asset Relationships (EPIC 5) — asset↔asset graph + shared-infra clusters.
        gdata = report.get('asset_graph')
        if isinstance(gdata, dict) and (gdata.get('summary') or {}).get('nodes'):
            gsum = gdata['summary']
            body_parts.append(card(
                'Asset Relationships', self._render_asset_graph_card(gdata),
                f"{gsum.get('edges', 0)} связей · {gsum.get('clusters', 0)} кластер."))

        # Asset Criticality (EPIC 9) — assets ranked by importance.
        crdata = report.get('asset_criticality')
        if isinstance(crdata, dict) and (crdata.get('summary') or {}).get('assets'):
            crsum = crdata['summary']
            body_parts.append(card(
                'Asset Criticality', self._render_asset_criticality_card(crdata),
                f"top {crsum.get('top_criticality', 0)} · "
                f"{crsum.get('high_criticality', 0)} критичных"))

        # Asset Exposure (likelihood axis) — assets ranked by reachability/attackability.
        xdata = report.get('exposure')
        if isinstance(xdata, dict) and (xdata.get('summary') or {}).get('assets'):
            xsum = xdata['summary']
            body_parts.append(card(
                'Asset Exposure', self._render_exposure_card(xdata),
                f"top {xsum.get('top_exposure', 0)} · "
                f"{xsum.get('exposed_assets', 0)} экспонированных"))

        # Priorities (EPIC 7) — Core Intelligence: findings ranked by priority +
        # confidence (what to fix first).
        idata = report.get('intelligence')
        if isinstance(idata, dict) and (idata.get('summary') or {}).get('findings'):
            isum = idata['summary']
            body_parts.append(card(
                'Priorities', self._render_intelligence_card(idata),
                f"top {isum.get('top_priority', 0)} · "
                f"{isum.get('high_confidence', 0)} high-conf"))

        # Attack Paths (EPIC 11) — lateral routes over shared infrastructure.
        pdata = report.get('attack_paths')
        if isinstance(pdata, dict) and (pdata.get('summary') or {}).get('paths'):
            psum = pdata['summary']
            body_parts.append(card(
                'Attack Paths', self._render_attack_paths_card(pdata),
                f"top {psum.get('top_score', 0)} · "
                f"{psum.get('critical_paths', 0)} критичных"))

        # Scan Accuracy (MODULE 1) — unified confidence per entity.
        accdata = report.get('accuracy')
        if isinstance(accdata, dict) and (accdata.get('summary') or {}).get('entities'):
            accsum = accdata['summary']
            body_parts.append(card(
                'Scan Accuracy', self._render_accuracy_card(accdata),
                f"avg {accsum.get('avg_confidence', 0)}% · "
                f"{accsum.get('entities', 0)} сущн."))

        # Screenshot (opt-in) — gallery of the captured page types.
        shot = phases.get('screenshot')
        if shot:
            sd = shot.get('data', {})
            shots = sd.get('shots')
            if shots:
                tiles = []
                for s in shots:
                    label = e(str(s.get('label', '')))
                    rel = s.get('rel_path')
                    if rel:
                        tiles.append(
                            f'<figure style="margin:0;width:240px;">'
                            f'<figcaption style="font-size:12px;font-weight:bold;'
                            f'margin-bottom:4px;">{label}</figcaption>'
                            f'<a href="{e(rel)}"><img src="{e(rel)}" '
                            f'alt="{label}" style="width:240px;border:1px solid '
                            f'#ddd;border-radius:4px;"></a></figure>')
                    else:
                        st = s.get('http_status')
                        note = f'HTTP {st}' if st else e(str(s.get('error', '—')))
                        tiles.append(
                            f'<figure style="margin:0;width:240px;">'
                            f'<figcaption style="font-size:12px;font-weight:bold;'
                            f'margin-bottom:4px;">{label}</figcaption>'
                            f'<div style="width:240px;height:90px;border:1px '
                            f'dashed #ccc;border-radius:4px;color:#999;'
                            f'font-size:12px;display:flex;align-items:center;'
                            f'justify-content:center;">недоступно · {e(str(note))}'
                            f'</div></figure>')
                shot_body = (f'<div style="display:flex;flex-wrap:wrap;gap:12px;">'
                             f'{"".join(tiles)}</div>')
            else:
                # Legacy report shape: a single top-level rel_path.
                rel = sd.get('rel_path')
                shot_body = (
                    f'<img src="{e(rel)}" alt="screenshot" style="max-width:100%;'
                    f'border:1px solid #ddd;border-radius:4px;">'
                    if rel else f'<p style="font-size:13px;color:#999;">'
                                f'{e(shot.get("reason", "—"))}</p>')
            body_parts.append(card('Screenshot', shot_body, shot.get('status', '—')))

        # Executive summary — risk verdict + recommendations, rendered first.
        summary = report.get('executive_summary') or build_summary(report)
        exec_card = card('Executive Summary', render_exec_summary(summary),
                         summary.get('risk_level', '—'))

        # Attack Surface — static offline SVG graph (domain → categories).
        surface = build_surface(report)
        surface_card = (
            card('Attack Surface', render_surface_graph(surface), 'Success')
            if surface.get('categories') else ''
        )

        # Trends — sparklines of the project's metric history (≥2 scans only).
        trends_body = self._render_trends_card(report.get('trends'))
        trends_card = card('Trends', trends_body, 'Success') if trends_body else ''

        return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Collection Report — {e(report.get('domain', ''))}</title></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;
max-width:860px;margin:24px auto;padding:0 16px;color:#222;">
<h1 style="font-size:22px;margin-bottom:4px;">Collection Report</h1>
<p style="color:#666;font-size:13px;margin-top:0;">
  <b>{e(report.get('url', ''))}</b><br>
  Начато: {e(report.get('started_at', ''))} ·
  Завершено: {e(report.get('finished_at', ''))}<br>
  Директория: {e(report.get('project_dir', ''))}
</p>
{exec_card}
{surface_card}
{trends_card}
{''.join(body_parts)}
<p style="color:#aaa;font-size:11px;margin-top:24px;">
  Advanced Site Analyzer · Full Collection
</p>
</body></html>"""
