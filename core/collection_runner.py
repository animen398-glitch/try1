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
from typing import Callable, Dict, Optional

from core.analyzer_plugins import discover_analyzers, run_analyzers
from core.api_key_extractor import ApiKeyExtractor
from core.attack_surface import build_surface
from core.attack_surface import render_interactive as render_surface_graph
from core.config import PLUGINS_DIR
from core.content_capture import SiteContentCapture
from core.cookie_auditor import CookieAuditor
from core.dependency_audit import render_html as render_dependencies
from core.executive_summary import build_summary
from core.executive_summary import render_html as render_exec_summary
from core.external_tools import KatanaRunner, NucleiRunner
from core.frontend_cloner import FrontendCloner
from core.infrastructure import render_html as render_infrastructure
from core.llm_summary import DEFAULT_MODEL as _LLM_DEFAULT_MODEL
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
                 llm_model: Optional[str] = None, subdomains: bool = False):
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
                  subdomains: Optional[bool] = None):
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

        # Executive summary: deterministic risk verdict + recommendations over
        # the phases above (no model, no network). This stays authoritative.
        report['executive_summary'] = build_summary(report)
        # Optional: enrich it with a local-Ollama narrative (opt-in, graceful —
        # the verdict above is untouched; a missing Ollama just adds nothing).
        if self.llm and not self._cancelled(report):
            self._attach_llm_narrative(report['executive_summary'])

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
{''.join(body_parts)}
<p style="color:#aaa;font-size:11px;margin-top:24px;">
  Advanced Site Analyzer · Full Collection
</p>
</body></html>"""
