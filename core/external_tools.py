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

from utils.subprocess_utils import run_hidden

from core.features import (
    has_amass, has_httpx, has_katana, has_nuclei, has_subfinder,
)
from core.vuln_scanner import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM


# Defensive cap on captured stdout: a misbehaving/compromised tool could emit a
# huge stream that we then hold and parse. The timeout already kills a runaway
# process (subprocess.run); this bounds what flows downstream into our parsers and
# report. We keep the HEAD (earliest JSONL findings) and flag truncation. Note:
# subprocess.run still buffers the tool's full stdout before we cap — a true
# peak-memory bound would need a streaming Popen rewrite, deliberately out of scope
# (stability over a risky cross-platform change for a rare opt-in path).
MAX_OUTPUT = 8_000_000  # characters (~8 MB of text)


def _cap_output(text: Optional[str], limit: int) -> tuple:
    """Return ``(text_capped_to_limit, was_truncated)`` keeping the head."""
    text = text or ''
    if len(text) > limit:
        return text[:limit], True
    return text, False


def command_error(run: Dict, tool: str) -> Optional[str]:
    """Return a concise user-facing error for a failed external tool run."""
    if run.get('error'):
        return str(run['error'])
    rc = run.get('rc')
    if rc not in (None, 0):
        detail = (run.get('stderr') or '').strip()
        if detail:
            return f'{tool} exited with code {rc}: {detail[-500:]}'
        return f'{tool} exited with code {rc}'
    return None


def run_command(cmd: List[str], timeout: int,
                input_text: Optional[str] = None,
                max_output: Optional[int] = None) -> Dict:
    """Run an external command. Never raises — returns a structured result.

    ``{rc, stdout, stderr, timed_out, truncated, error?}``. A missing binary or OS
    error is reported via ``error``; a timeout returns ``timed_out=True`` with
    whatever partial stdout was captured. ``stdout`` is capped to ``max_output``
    (default :data:`MAX_OUTPUT`) characters, with ``truncated`` flagging a cap.
    """
    limit = max_output if max_output is not None else MAX_OUTPUT
    try:
        proc = run_hidden(cmd, capture_output=True, text=True,
                          timeout=timeout, input=input_text)
        stdout, truncated = _cap_output(proc.stdout, limit)
        return {'rc': proc.returncode, 'stdout': stdout,
                'stderr': (proc.stderr or '')[-1000:], 'timed_out': False,
                'truncated': truncated}
    except subprocess.TimeoutExpired as e:
        partial = e.stdout if isinstance(e.stdout, str) else ''
        stdout, truncated = _cap_output(partial, limit)
        return {'rc': None, 'stdout': stdout, 'stderr': '',
                'timed_out': True, 'truncated': truncated}
    except FileNotFoundError:
        return {'rc': None, 'stdout': '', 'stderr': '', 'timed_out': False,
                'truncated': False, 'error': 'binary not found on PATH'}
    except OSError as e:  # noqa: BLE001 — surface, don't crash
        return {'rc': None, 'stdout': '', 'stderr': '', 'timed_out': False,
                'truncated': False, 'error': str(e)}


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
        # Carry the template's knowledge text (F-O2) — the adapter persists it in
        # evidence and it wins over the finding_knowledge catalog at display time.
        remediation = info.get('remediation') or info.get('remediation_steps') or ''
        findings.append({
            'severity': _map_nuclei_severity(info.get('severity', 'info')),
            'title': str(title),
            'detail': detail,
            'source': 'nuclei',
            'description': str(info.get('description') or ''),
            'impact': str(info.get('impact') or ''),
            'remediation': str(remediation),
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
        error = command_error(run, 'nuclei')
        if error:
            result['error'] = error
            self._log(f'[nuclei] failed: {error}')
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
        error = command_error(run, 'katana')
        if error:
            result['error'] = error
            self._log(f'[katana] failed: {error}')
            return result
        result['endpoints'] = parse_katana_lines(run['stdout'])
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[katana] {len(result["endpoints"])} endpoints'
                  + (' (truncated)' if result['truncated'] else ''))
        return result


# ───────────────────────────────── amass ───────────────────────────────────

def parse_fqdn_lines(text: str, domain: str) -> List[str]:
    """Parse one-FQDN-per-line output → unique in-scope subdomains (sorted).

    Shared by the passive subdomain binaries (amass ``enum -passive`` and
    subfinder ``-silent``), which both print one hostname per line; lines with
    spaces (graph/relation output) and out-of-scope names are dropped.
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


# Back-compat alias — amass output is the same one-FQDN-per-line shape.
parse_amass_lines = parse_fqdn_lines


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
        error = command_error(run, 'amass')
        if error:
            result['error'] = error
            self._log(f'[amass] failed: {error}')
            return result
        result['subdomains'] = parse_fqdn_lines(run['stdout'], domain)
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[amass] {len(result["subdomains"])} subdomains'
                  + (' (truncated)' if result['truncated'] else ''))
        return result


# ─────────────────────────────── subfinder ─────────────────────────────────

class SubfinderRunner:
    """Run subfinder passive enumeration and return in-scope subdomains.

    The projectdiscovery counterpart of AmassRunner — same passive-enum shape
    (one FQDN per line under ``-silent``), so it reuses ``parse_fqdn_lines``.
    """

    def __init__(self, timeout: int = 180,
                 extra_args: Optional[List[str]] = None):
        self.timeout = timeout
        self.extra_args = list(extra_args) if extra_args else []
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        return has_subfinder()

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
            result['error'] = ('subfinder not installed '
                               '(https://github.com/projectdiscovery/subfinder)')
            return result

        cmd = ['subfinder', '-d', domain, '-silent',
               '-no-color'] + self.extra_args
        self._log(f'[subfinder] passive enum {domain}')
        run = run_command(cmd, self.timeout)
        error = command_error(run, 'subfinder')
        if error:
            result['error'] = error
            self._log(f'[subfinder] failed: {error}')
            return result
        result['subdomains'] = parse_fqdn_lines(run['stdout'], domain)
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[subfinder] {len(result["subdomains"])} subdomains'
                  + (' (truncated)' if result['truncated'] else ''))
        return result


# ───────────────────────────────── httpx ───────────────────────────────────

def parse_httpx_jsonl(text: str) -> List[Dict]:
    """Parse ``httpx -json`` stdout into per-host probe records.

    Each output line is one JSON object (one probed host). Returns a list of
    ``{host, url, status_code, title, webserver, tech}`` dicts — only hosts that
    httpx actually emitted (httpx prints a line only for a reachable host, so a
    record implies the host is alive). Malformed lines are skipped; field names
    are read defensively across httpx versions.
    """
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get('input') or obj.get('host') or obj.get('url') or '')
        tech = obj.get('tech') or obj.get('technologies') or []
        if not isinstance(tech, list):
            tech = [str(tech)]
        out.append({
            'host': str(host),
            'url': str(obj.get('url') or ''),
            'status_code': obj.get('status_code') or obj.get('status-code'),
            'title': str(obj.get('title') or ''),
            'webserver': str(obj.get('webserver') or obj.get('web-server') or ''),
            'tech': [str(t) for t in tech],
        })
    return out


class HttpxRunner:
    """Probe a list of hosts with httpx and return per-host HTTP metadata.

    Unlike the enumerators this consumes a host list (fed on stdin) rather than a
    single domain — the natural "which of these subdomains are live, and what do
    they run" step. Output normalises to the same shape ``parse_httpx_jsonl``
    yields; a missing binary or failure degrades to an empty result.
    """

    def __init__(self, timeout: int = 180,
                 extra_args: Optional[List[str]] = None):
        self.timeout = timeout
        self.extra_args = list(extra_args) if extra_args else []
        self.progress_callback: Optional[Callable] = None

    @staticmethod
    def available() -> bool:
        return has_httpx()

    def set_progress_callback(self, cb: Callable):
        self.progress_callback = cb

    def _log(self, msg: str):
        if self.progress_callback:
            self.progress_callback(msg)

    def probe(self, hosts: List[str]) -> Dict:
        """Probe ``hosts``; return ``{status, results, truncated?, error?}``.

        ``results`` is the list of live-host records (see ``parse_httpx_jsonl``).
        """
        hosts = [h.strip() for h in (hosts or []) if h and h.strip()]
        result: Dict = {'status': 'Error', 'results': []}
        if not hosts:
            result['status'] = 'Success'
            result.pop('error', None)
            return result
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = ('httpx not installed '
                               '(https://github.com/projectdiscovery/httpx)')
            return result

        cmd = ['httpx', '-json', '-silent', '-no-color',
               '-status-code', '-title', '-web-server',
               '-tech-detect'] + self.extra_args
        self._log(f'[httpx] probing {len(hosts)} host(s)')
        run = run_command(cmd, self.timeout, input_text='\n'.join(hosts) + '\n')
        error = command_error(run, 'httpx')
        if error:
            result['error'] = error
            self._log(f'[httpx] failed: {error}')
            return result
        result['results'] = parse_httpx_jsonl(run['stdout'])
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        self._log(f'[httpx] {len(result["results"])} live host(s)'
                  + (' (truncated)' if result['truncated'] else ''))
        return result
