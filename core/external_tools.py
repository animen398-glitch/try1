"""core/external_tools.py
Optional integration with external security CLIs — run as subprocesses, never a
mandatory dependency.

Design (architectural invariant I1, mirroring scrapy_crawler): a tool is used
only if its binary is on PATH (detected via core.features). When absent the
feature degrades gracefully — ``scan`` returns a status dict instead of raising
— so nothing here is ever required to run the app. We do NOT reimplement these
tools; we shell out and normalise their output into our own model so it flows
through the existing pipeline (VulnScanner findings → summary → executive
summary → attack surface → report).

Currently wired: **nuclei** (projectdiscovery) → vulnerability findings. The
generic ``run_command`` + a small JSONL parser make adding katana/amass/
subfinder a thin, same-shaped addition when needed (see PROJECT_STATUS M3).
"""

import json
import subprocess
from typing import Callable, Dict, List, Optional

from urllib.parse import urlparse

from core.features import has_amass, has_katana, has_nuclei
from core.vuln_scanner import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM


def run_command(cmd: List[str], timeout: int,
                input_text: Optional[str] = None) -> Dict:
    """Run an external command. Never raises — returns a structured result.

    ``{rc, stdout, stderr, timed_out, error?}``. A missing binary or OS error is
    reported via ``error``; a timeout returns ``timed_out=True`` with whatever
    partial stdout was captured.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, input=input_text)
        return {'rc': proc.returncode, 'stdout': proc.stdout or '',
                'stderr': (proc.stderr or '')[-1000:], 'timed_out': False}
    except subprocess.TimeoutExpired as e:
        partial = e.stdout if isinstance(e.stdout, str) else ''
        return {'rc': None, 'stdout': partial or '', 'stderr': '',
                'timed_out': True}
    except FileNotFoundError:
        return {'rc': None, 'stdout': '', 'stderr': '', 'timed_out': False,
                'error': 'binary not found on PATH'}
    except OSError as e:  # noqa: BLE001 — surface, don't crash
        return {'rc': None, 'stdout': '', 'stderr': '', 'timed_out': False,
                'error': str(e)}


# nuclei severities → our three-level model.
_NUCLEI_SEVERITY = {
    'critical': SEVERITY_HIGH, 'high': SEVERITY_HIGH,
    'medium': SEVERITY_MEDIUM,
    'low': SEVERITY_INFO, 'info': SEVERITY_INFO, 'unknown': SEVERITY_INFO,
}


def _map_nuclei_severity(sev: str) -> str:
    return _NUCLEI_SEVERITY.get((sev or '').lower(), SEVERITY_INFO)


def parse_nuclei_jsonl(text: str) -> List[Dict]:
    """Parse ``nuclei -jsonl`` stdout into our finding shape.

    Each output line is one JSON object; malformed lines are skipped. Findings
    are tagged ``source='nuclei'`` so the report can tell them from the native
    VulnScanner rules.
    """
    findings: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get('info') if isinstance(obj.get('info'), dict) else {}
        template = obj.get('template-id') or obj.get('templateID') or ''
        title = info.get('name') or template or 'nuclei finding'
        where = (obj.get('matched-at') or obj.get('matched_at')
                 or obj.get('host') or '')
        detail = ' · '.join(p for p in (template, where) if p)
        findings.append({
            'severity': _map_nuclei_severity(info.get('severity', 'info')),
            'title': str(title),
            'detail': detail,
            'source': 'nuclei',
        })
    return findings


class NucleiRunner:
    """Run nuclei against a URL and return normalised vulnerability findings."""

    def __init__(self, timeout: int = 120,
                 extra_args: Optional[List[str]] = None):
        self.timeout = timeout
        self.extra_args = list(extra_args) if extra_args else []
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        return has_nuclei()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def scan(self, url: str) -> Dict:
        """Scan ``url``; return ``{status, url, findings, truncated?, error?}``.

        ``status`` is ``Unavailable`` when nuclei isn't installed, ``Error`` on
        failure, ``Success`` otherwise (with possibly-partial findings).
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result: Dict = {'status': 'Error', 'url': url, 'findings': []}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = ('nuclei not installed '
                               '(https://github.com/projectdiscovery/nuclei)')
            return result

        cmd = ['nuclei', '-u', url, '-jsonl', '-silent',
               '-disable-update-check', '-timeout', '5'] + self.extra_args
        self._log(f'[nuclei] scanning {url}')
        run = run_command(cmd, self.timeout)
        if run.get('error'):
            result['error'] = run['error']
            self._log(f'[nuclei] failed: {run["error"]}')
            return result

        findings = parse_nuclei_jsonl(run['stdout'])
        result['findings'] = findings
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[nuclei] {len(findings)} findings'
                  + (' (truncated)' if result['truncated'] else ''))
        return result


# ───────────────────────────────── katana ──────────────────────────────────

def parse_katana_lines(text: str) -> List[str]:
    """Parse katana output (``-jsonl`` objects or plain URL lines) → unique URLs,
    in discovery order."""
    seen: set = set()
    out: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        url = None
        if line.startswith('{'):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = {}
            req = obj.get('request') if isinstance(obj.get('request'), dict) else {}
            url = obj.get('endpoint') or req.get('endpoint') or obj.get('url')
        if url is None and line.startswith(('http://', 'https://')):
            url = line
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


class KatanaRunner:
    """Run katana against a URL and return discovered endpoint URLs."""

    def __init__(self, timeout: int = 180, depth: int = 2,
                 extra_args: Optional[List[str]] = None):
        self.timeout = timeout
        self.depth = depth
        self.extra_args = list(extra_args) if extra_args else []
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        return has_katana()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def crawl(self, url: str) -> Dict:
        """Crawl ``url``; return ``{status, url, endpoints, truncated?, error?}``."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result: Dict = {'status': 'Error', 'url': url, 'endpoints': []}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = ('katana not installed '
                               '(https://github.com/projectdiscovery/katana)')
            return result

        cmd = ['katana', '-u', url, '-silent', '-jsonl',
               '-d', str(self.depth)] + self.extra_args
        self._log(f'[katana] crawling {url} (depth {self.depth})')
        run = run_command(cmd, self.timeout)
        if run.get('error'):
            result['error'] = run['error']
            return result
        result['endpoints'] = parse_katana_lines(run['stdout'])
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[katana] {len(result["endpoints"])} endpoints'
                  + (' (truncated)' if result['truncated'] else ''))
        return result


# ───────────────────────────────── amass ───────────────────────────────────

def parse_amass_lines(text: str, domain: str) -> List[str]:
    """Parse amass passive output → unique in-scope subdomains (sorted).

    amass ``enum -passive`` prints one FQDN per line; lines with spaces (graph/
    relation output) and out-of-scope names are dropped.
    """
    domain = (domain or '').strip().lower()
    out: set = set()
    for line in text.splitlines():
        name = line.strip().lower()
        if not name or ' ' in name:
            continue
        name = name.lstrip('*.')
        if name == domain or name.endswith('.' + domain):
            out.add(name)
    return sorted(out)


class AmassRunner:
    """Run amass passive enumeration and return in-scope subdomains."""

    def __init__(self, timeout: int = 180,
                 extra_args: Optional[List[str]] = None):
        self.timeout = timeout
        self.extra_args = list(extra_args) if extra_args else []
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        return has_amass()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def enumerate(self, domain: str) -> Dict:
        """Enumerate ``domain``; return ``{status, domain, subdomains, …}``."""
        domain = urlparse(
            domain if '://' in domain else '//' + domain).netloc or domain
        domain = domain.strip().lower().split('/')[0]
        result: Dict = {'status': 'Error', 'domain': domain, 'subdomains': []}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = 'amass not installed (https://github.com/owasp-amass/amass)'
            return result

        cmd = ['amass', 'enum', '-passive', '-d', domain,
               '-nocolor'] + self.extra_args
        self._log(f'[amass] passive enum {domain}')
        run = run_command(cmd, self.timeout)
        if run.get('error'):
            result['error'] = run['error']
            return result
        result['subdomains'] = parse_amass_lines(run['stdout'], domain)
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[amass] {len(result["subdomains"])} subdomains'
                  + (' (truncated)' if result['truncated'] else ''))
        return result
