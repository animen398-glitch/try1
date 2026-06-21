"""core/document_providers/lift_adapter.py
Optional lift provider — schema-constrained document→JSON extraction (EXT-OSINT
F2 T2.4).

lift (datalab-to) extracts structured JSON from PDFs/images using a 9B vision
model. It is **heavy** (torch/vLLM, GPU) and its model is OpenRAIL-M licensed, so
we never bundle it, never require it, and **never import it**: it is run only as a
subprocess via its ``lift_extract`` CLI, and its JSON output is normalised into
our finding shapes. This mirrors the external-tool seam (``external_tools`` /
``bbot_adapter``) — pure parsing split from a never-raising runner, injectable for
offline tests.

Privacy: the model's raw output can contain plaintext secrets, so we run lift into
a **temporary** directory that is deleted after parsing — no plaintext is ever
persisted; findings carry only masked discriminators (via
``document_intelligence.secret_finding``).
"""

import json
import os
import tempfile
from typing import Callable, Dict, List, Optional

from core.document_intelligence import secret_finding
from core.external_tools import run_command
from core.features import has_lift

LIFT_HOMEPAGE = 'https://github.com/datalab-to/lift'

# The default extraction schema = our contract for lift's output. We own it, so we
# own the output shape: a list of secrets (type/value) and a list of sensitive
# data findings. Keep it small and security-focused (T2.1 open question #4).
DEFAULT_SCHEMA: Dict = {
    'type': 'object',
    'properties': {
        'secrets': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'type': {'type': 'string',
                             'description': 'credential kind, e.g. AWS key, '
                                            'password, API token'},
                    'value': {'type': 'string',
                              'description': 'the secret value as written'},
                },
            },
        },
        'sensitive_data': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'title': {'type': 'string'},
                    'detail': {'type': 'string'},
                    'severity': {'type': 'string',
                                 'description': 'low | medium | high'},
                },
            },
        },
    },
}

# lift severity word → the vuln scanner's 3-bucket scale (as nuclei/OSV/bbot fold),
# defaulting to Medium for an unlabelled sensitive-data item.
_SENSITIVE_SEVERITY = {
    'critical': 'High', 'high': 'High', 'medium': 'Medium',
    'low': 'Info', 'info': 'Info',
}


def available() -> bool:
    return has_lift()


def build_command(input_path, out_dir, schema_path) -> List[str]:
    """The ``lift_extract`` invocation: extract ``input_path`` into ``out_dir``
    using ``schema_path``. Extra flags (backend/model) are the user's environment
    concern — we keep the call minimal and documented."""
    return ['lift_extract', str(input_path), str(out_dir),
            '--schema', str(schema_path)]


def _coerce_payload(text: str) -> Optional[Dict]:
    """Best-effort parse of a lift JSON document → dict, or ``None``."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def parse_output(payload: Dict, location: str) -> List[Dict]:
    """Normalise lift's schema-shaped JSON into raw finding dicts.

    ``secrets[]`` → masked secret findings (placeholders dropped via the shared
    ``secret_finding`` validator); ``sensitive_data[]`` → generic
    ``category='vuln'`` findings ("Sensitive data in document"). Defensive: a
    malformed payload yields fewer findings, never an error."""
    findings: List[Dict] = []
    if not isinstance(payload, dict):
        return findings
    for item in payload.get('secrets') or []:
        if not isinstance(item, dict):
            continue
        f = secret_finding(item.get('type') or 'secret', item.get('value'),
                           location)
        if f:
            findings.append(f)
    for item in payload.get('sensitive_data') or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get('title') or '').strip()
        if not title:
            continue
        sev = _SENSITIVE_SEVERITY.get(
            str(item.get('severity') or '').strip().lower(), 'Medium')
        detail = str(item.get('detail') or '').strip()
        findings.append({
            'severity': sev,
            'title': f'Sensitive data in document: {title}',
            'detail': f'{location} — {detail}' if detail else str(location),
            'source': 'document', 'category': 'vuln', 'location': str(location),
        })
    return findings


class LiftRunner:
    """Run lift over a document and return normalised findings.

    Never raises (degrades to a status dict). The subprocess seam (``runner``) and
    availability probe (``detector``) are injectable so the whole thing is tested
    offline with canned output — no real model, GPU or network."""

    def __init__(self, *, timeout: int = 600, schema: Optional[Dict] = None,
                 runner: Optional[Callable] = None,
                 detector: Optional[Callable] = None):
        self.timeout = timeout
        self.schema = schema if schema is not None else DEFAULT_SCHEMA
        self._runner = runner or run_command
        self._detector = detector or has_lift
        self.progress_callback: Optional[Callable] = None

    def available(self) -> bool:
        return bool(self._detector())

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def _read_output(self, out_dir: str, run: Dict) -> Optional[Dict]:
        """Find and parse lift's JSON output: any *.json under ``out_dir``,
        falling back to stdout. Returns the first parseable dict."""
        for root, _dirs, files in os.walk(out_dir):
            for name in sorted(files):
                if name.lower().endswith('.json'):
                    try:
                        with open(os.path.join(root, name), encoding='utf-8') as fh:
                            payload = _coerce_payload(fh.read())
                    except OSError:
                        payload = None
                    if payload is not None:
                        return payload
        return _coerce_payload(run.get('stdout') or '')

    def extract(self, path, *, location: Optional[str] = None) -> Dict:
        """Extract ``path`` with lift; return ``{status, provider, findings,
        error?}``. ``status`` is ``Unavailable`` when lift is absent, ``Error`` on
        a run failure, ``Success`` otherwise (findings possibly empty).

        lift runs into a temp dir that is deleted on exit, so no plaintext output
        is ever persisted."""
        loc = location or str(path)
        result: Dict = {'status': 'Error', 'provider': 'lift', 'findings': []}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = f'lift not installed ({LIFT_HOMEPAGE})'
            return result
        try:
            with tempfile.TemporaryDirectory(prefix='lift_') as tmp:
                schema_path = os.path.join(tmp, 'schema.json')
                out_dir = os.path.join(tmp, 'out')
                os.makedirs(out_dir, exist_ok=True)
                with open(schema_path, 'w', encoding='utf-8') as fh:
                    json.dump(self.schema, fh)
                cmd = build_command(path, out_dir, schema_path)
                self._log(f'[lift] extracting {os.path.basename(str(path))}')
                run = self._runner(cmd, self.timeout)
                if run.get('error'):
                    result['error'] = run['error']
                    self._log(f'[lift] failed: {run["error"]}')
                    return result
                payload = self._read_output(out_dir, run)
            # temp dir (and any plaintext lift wrote) is now deleted.
            findings = parse_output(payload or {}, loc)
            result['findings'] = findings
            result['truncated'] = run.get('timed_out', False)
            result['status'] = 'Success'
            result.pop('error', None)
            self._log(f'[lift] {len(findings)} finding(s)')
            return result
        except Exception as e:   # noqa: BLE001 — extraction must never raise
            result['error'] = str(e)
            return result
