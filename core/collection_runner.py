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
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Optional
from urllib.parse import urlparse

from core.api_key_extractor import ApiKeyExtractor
from core.attack_surface import build_surface, render_svg as render_surface_svg
from core.content_capture import SiteContentCapture
from core.cookie_auditor import CookieAuditor
from core.executive_summary import build_summary
from core.executive_summary import render_html as render_exec_summary
from core.frontend_cloner import FrontendCloner
from core.recon_engine import ReconEngine
from core.report_charts import stacked_bar
from core.screenshot import ScreenshotCapturer
from core.site_map import render_html as render_site_map
from core.vuln_scanner import VulnScanner
from utils.image_processor import ImageExtractor


def _domain_slug(url: str) -> str:
    netloc = urlparse(url).netloc or url.split('/')[0]
    slug = re.sub(r'^www\.', '', netloc)
    return re.sub(r'[^\w.-]', '_', slug) or 'site'


class CollectionRunner:
    """Sequentially drives every collection module into one project folder."""

    def __init__(self, profile: str = 'chrome_windows', max_pages: int = 20,
                 cookies: Optional[str] = None, capture_delay: float = 0.5,
                 screenshots: bool = False):
        self.profile = profile
        self.max_pages = max_pages
        self.cookies = cookies
        self.capture_delay = capture_delay   # seconds between captured pages
        # Opt-in headless screenshot (Playwright) — off by default so the
        # default pipeline stays fast and dependency-free.
        self.screenshots = screenshots
        self.progress_callback: Optional[Callable] = None
        self._cancel = threading.Event()

    def configure(self, profile: Optional[str] = None,
                  max_pages: Optional[int] = None,
                  cookies: Optional[str] = None,
                  capture_delay: Optional[float] = None,
                  screenshots: Optional[bool] = None):
        if profile:
            self.profile = profile
        if max_pages is not None:
            self.max_pages = max_pages
        if cookies is not None:
            self.cookies = cookies
        if screenshots is not None:
            self.screenshots = screenshots
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
        project_dir = Path(output_base).expanduser() / f'{domain}_{stamp}'
        project_dir.mkdir(parents=True, exist_ok=True)

        report: Dict = {
            'url': url,
            'domain': domain,
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'project_dir': str(project_dir),
            'phases': {},
        }

        self._log(f'Проект: {project_dir}')

        # 1. Recon
        if not self._cancelled(report):
            report['phases']['recon'] = self._phase_recon(url, project_dir)
        # 2. API key scan
        if not self._cancelled(report):
            report['phases']['api'] = self._phase_api(url, project_dir)
        # 3. Capture (frontend)
        capture_dir = project_dir / 'capture'
        if not self._cancelled(report):
            report['phases']['capture'] = self._phase_capture(url, capture_dir)
        # 4. Clone (frontend) — only if capture produced pages
        if not self._cancelled(report):
            report['phases']['clone'] = self._phase_clone(capture_dir, project_dir,
                                                          report['phases'].get('capture', {}))
        # 5. Images (media)
        if not self._cancelled(report):
            report['phases']['images'] = self._phase_images(url, project_dir)
        # 6. Cookie security audit
        if not self._cancelled(report):
            report['phases']['cookies'] = self._phase_cookies(url, project_dir)
        # 7. Vulnerability scan (aggregates recon + cookie findings)
        if not self._cancelled(report):
            report['phases']['vulns'] = self._phase_vulns(report, project_dir)
        # 8. Screenshot (opt-in, Playwright) — captured last; non-fatal/skippable
        if self.screenshots and not self._cancelled(report):
            report['phases']['screenshot'] = self._phase_screenshot(url, project_dir)

        report['finished_at'] = datetime.now().isoformat(timespec='seconds')

        # Executive summary: deterministic risk verdict + recommendations over
        # the phases above (no model, no network).
        report['executive_summary'] = build_summary(report)

        # Reports
        json_path = project_dir / 'report.json'
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8',
        )
        html_path = project_dir / 'report.html'
        html_path.write_text(self._render_html(report), encoding='utf-8')

        report['report_json'] = str(json_path)
        report['report_html'] = str(html_path)
        report['status'] = 'Cancelled' if report.get('cancelled') else 'Success'
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
            summary = VulnScanner.summarize(findings)
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

    def _phase_screenshot(self, url: str, project_dir: Path) -> Dict:
        self._log('[8/8] Screenshot…')
        if not ScreenshotCapturer.available():
            self._log('  Screenshot — пропущено (Playwright не установлен)')
            return {'status': 'Skipped', 'reason': 'playwright not installed'}
        try:
            out = project_dir / 'screenshots' / 'home.png'
            cap = ScreenshotCapturer()
            cap.set_progress_callback(self._log)
            data = cap.capture(url, out)
            if data.get('status') == 'Success':
                # URL-style relative path (forward slashes) so the offline HTML
                # <img> resolves on every OS, including Windows.
                data['rel_path'] = 'screenshots/home.png'
                return {'status': 'Success', 'data': data}
            return {'status': data.get('status', 'Error'),
                    'reason': data.get('error', 'screenshot failed')}
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

        # Screenshot (opt-in) — only rendered when the phase ran.
        shot = phases.get('screenshot')
        if shot:
            sd = shot.get('data', {})
            rel = sd.get('rel_path')
            if rel:
                shot_body = (
                    f'<img src="{e(rel)}" alt="screenshot" '
                    f'style="max-width:100%;border:1px solid #ddd;border-radius:4px;">'
                )
            else:
                shot_body = (f'<p style="font-size:13px;color:#999;">'
                             f'{e(shot.get("reason", "—"))}</p>')
            body_parts.append(card('Screenshot', shot_body, shot.get('status', '—')))

        # Executive summary — risk verdict + recommendations, rendered first.
        summary = report.get('executive_summary') or build_summary(report)
        exec_card = card('Executive Summary', render_exec_summary(summary),
                         summary.get('risk_level', '—'))

        # Attack Surface — static offline SVG graph (domain → categories).
        surface = build_surface(report)
        surface_card = (
            card('Attack Surface', render_surface_svg(surface), 'Success')
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
