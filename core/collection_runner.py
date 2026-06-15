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
from core.asn_intel import render_html as render_asn_intel
from core.osv_correlation import correlate as correlate_osv
from core.osv_correlation import to_findings as osv_to_findings
from core.infrastructure import render_html as render_infrastructure
from core.llm_summary import DEFAULT_MODEL as _LLM_DEFAULT_MODEL
from core.openapi_discovery import discover as discover_openapi
from core.openapi_discovery import render_html as render_openapi
from core.llm_summary import generate_narrative as generate_llm_narrative
from core.project import ProjectStore, project_slug
from core.recon_engine import ReconEngine
from core.report_charts import stacked_bar
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
                 osv: bool = False):
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
                  osv: Optional[bool] = None):
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

        report: Dict = {
            'url': url,
            'domain': domain,
            'scan_id': stamp,
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'project_dir': str(scan_dir),       # backward-compatible: scan dir
            'project_root': str(project.root),
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
        # 7b. Subdomain enumeration (opt-in) → feeds the takeover risk signal
        # and the Scan Diff subdomain section.
        if self.subdomains and not self._cancelled(report):
            report['phases']['subdomains'] = self._phase_subdomains(url, scan_dir)
        # 7c. TLS certificate (opt-in) → Scan Diff certificate section.
        if self.certificate and not self._cancelled(report):
            report['phases']['certificate'] = self._phase_certificate(url, scan_dir)
        # 7d. OpenAPI/Swagger discovery (opt-in) → API map for report/surface/diff.
        if self.openapi and not self._cancelled(report):
            report['phases']['openapi'] = self._phase_openapi(url, scan_dir)
        # 7e. Historical URL intelligence (opt-in) → archived URLs classified.
        if self.historical and not self._cancelled(report):
            report['phases']['historical'] = self._phase_historical(url, scan_dir)
        # 7f. DNS intelligence (opt-in) → records + email-auth; findings fold
        # into the vuln phase so the risk engine accounts for them.
        if self.dns and not self._cancelled(report):
            report['phases']['dns'] = self._phase_dns(url, scan_dir, report)
        # 7g. Email intelligence (opt-in) → harvested + grouped addresses.
        if self.emails and not self._cancelled(report):
            report['phases']['emails'] = self._phase_emails(url, scan_dir)
        # 7h. Employee intelligence (opt-in) → named people + e-mail scheme.
        if self.employees and not self._cancelled(report):
            report['phases']['employees'] = self._phase_employees(url, scan_dir)
        # 7i. CT history (opt-in) → certificate-transparency timeline (crt.sh).
        if self.ct and not self._cancelled(report):
            report['phases']['ct'] = self._phase_ct(url, scan_dir)
        # 7j. Active ASN/netblock recon (opt-in) → CIDR + ASN prefixes +
        # reverse-IP co-hosted hosts (needs the recon-derived ip/asn).
        if self.asn_intel and not self._cancelled(report):
            report['phases']['asn_intel'] = self._phase_asn_intel(report, scan_dir)
        # 7k. CVE correlation via OSV.dev (opt-in, active) → live advisories per
        # detected JS library; supersedes the bundled dependency-audit table and
        # folds its findings into the vuln phase (so risk/summary account for them).
        if self.osv and not self._cancelled(report):
            report['phases']['osv'] = self._phase_osv(report, scan_dir)
        # 8. Katana crawl (opt-in, external) → endpoints for the graph/report
        if self.katana and not self._cancelled(report):
            report['phases']['katana'] = self._phase_katana(url)
        # 8b. Screenshot (opt-in, Playwright) — captured last; non-fatal/skippable
        if self.screenshots and not self._cancelled(report):
            report['phases']['screenshot'] = self._phase_screenshot(
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
            from core.timeline import build_series
            entries = list(project.scans()) + [project._scan_entry(scan_dir, report)]
            report['trends'] = build_series(entries)
        except Exception as ex:  # noqa: BLE001 — trends are best-effort
            self._log(f'  ! trend series failed: {ex}')
            report['trends'] = []

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
            nuclei_count = self._merge_nuclei(report.get('url', ''), findings)
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

            correlated = correlate_osv(libraries)
            if not correlated:
                self._log('  OSV — известных уязвимостей не найдено')
                return {'status': 'Success', 'data': {'correlated': {}}}

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
                     'detail': f"OSV/{v.get('id', '')}: {v.get('summary', '')}".strip(),
                     'fixed_in': None}
                    for v in vulns
                ]
                osv_findings.extend(osv_to_findings(name, version, vulns))

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
            n_vulns = sum(len(v) for v in correlated.values())
            self._log(f"  OSV: {len(correlated)} библиотек(и) с уязвимостями, "
                      f"{n_vulns} advisory (находок +{len(osv_findings)})")
            return {'status': 'Success', 'data': {'correlated': correlated}}
        except Exception as e:
            self._log(f'  OSV correlation failed: {e}')
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
                if s == 'dns':
                    return phase_ok('dns')
                if s == 'nuclei':
                    return bool(self.nuclei) and phase_ok('vulns')
                if s == 'dependency-audit':
                    return phase_ok('recon')
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
            from core.findings_sla import breached_count
            report['findings'] = {
                'project': project.slug, 'summary': result['summary'],
                'new': len(result['new']), 'reopened': len(result['reopened']),
                'resolved': len(result['resolved']),
                'recurring': len(result['recurring']),
                'sla_breached': breached_count(store.active_findings(project.slug)),
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

            assets = derive_assets(report)
            if not assets:
                return
            result = AssetStore().sync(project.slug, scan_id, assets,
                                       in_scope=in_scope)
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
                                     'exposure': exposure[:10]}
            self._log(f"  Correlation: {summary.get('correlated', 0)}/"
                      f"{summary.get('findings', 0)} находок связаны с активами, "
                      f"exposed: {summary.get('exposed_assets', 0)}")
        except Exception as e:  # noqa: BLE001 — correlation must not fail a scan
            self._log(f'  Correlation failed: {e}')

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
        return head + table

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
        return (f'<p style="font-size:13px;">История за '
                f'<b>{e(str(len(pts)))}</b> скан(ов) — самые свежие справа.</p>'
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

    def _merge_nuclei(self, url: str, findings: list) -> int:
        """Run nuclei (if enabled + installed) and append its findings in place.

        Returns the number of nuclei findings added. Opt-in and best-effort: a
        missing binary or any failure is logged and ignored — the native scan
        result still stands.
        """
        if not self.nuclei or not url:
            return 0
        if not NucleiRunner.available():
            self._log('  nuclei — пропущено (бинарь не установлен)')
            return 0
        runner = NucleiRunner()
        runner.set_progress_callback(self._log)
        data = runner.scan(url)
        extra = data.get('findings', [])
        findings.extend(extra)
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
