"""core/bbot_adapter.py
Optional BBOT external-recon adapter (EPIC EXT-OSINT, F1 T1.3).

BBOT (blacklanternsecurity) is an external ASM/recon engine. It is **AGPL-3.0**,
so we never copy a line of its code and never import it: it is used *only* as a
separate external tool — run as a subprocess, with its machine-readable JSON
(NDJSON) output normalised into our own models so it flows through the existing
data lifecycle (assets → AssetStore, findings → FindingsStore → risk → Timeline).
This mirrors the proven pattern in ``core/external_tools.py`` (nuclei / katana):
a pure parser plus a thin runner that degrades gracefully when the binary is
absent (architectural invariants I1/I5 — nothing here is ever required to run the
app, and nothing here reaches the network unless the user opts in).

Scope of phase 1 (per the approved T1.1 contract in ROADMAP_ASM_2.0.md):
  * Only event types that feed the EXISTING lifecycle are ingested — hosts, IPs,
    netblocks, ASNs, URLs, technologies (→ assets) and findings/vulnerabilities
    (→ findings). OSINT events (email / social / username / repo / bucket …) are
    intentionally ignored for now (no matching asset/finding type yet).
  * Only **in-scope** events (``scope_distance`` 0 / missing) are kept; affiliates
    (distance ≥ 1) are counted but not ingested — they are not owned assets
    (mirrors the co-hosted decision in ``core/asn_intel.py``).
  * The parser produces a flat, JSON-serialisable intermediate placed at
    ``report['phases']['bbot']['data']``. Apex classification of hostnames
    (domain vs subdomain) and the fold into assets/findings happen in the
    consumer (T1.4: ``asset_adapter`` + ``collection_runner``), which already
    owns the target apex — so this module stays apex-agnostic and pure.

Defensive reading: the BBOT docs do not pin the exact subfields of a
``VULNERABILITY`` / ``FINDING`` ``data`` dict, so every field is read
any-of-with-fallback and malformed lines are skipped (T1.1 open question #1 — to
be confirmed against a real saved ``output.json`` without changing this shape).
"""

import json
from typing import Callable, Dict, List, Optional

from core.external_tools import command_error, run_command
from core.features import has_bbot
from core.vuln_scanner import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM

BBOT_HOMEPAGE = 'https://github.com/blacklanternsecurity/bbot'

# BBOT severity (CRITICAL/HIGH/MEDIUM/LOW) → the vuln scanner's 3-bucket scale,
# matching how external_tools folds nuclei and osv_correlation folds OSV (so a
# BBOT finding counts in VulnScanner.summarize and the risk engine like every
# other vuln-phase finding; Critical collapses into High, Low into Info).
_BBOT_SEVERITY = {
    'critical': SEVERITY_HIGH, 'high': SEVERITY_HIGH,
    'medium': SEVERITY_MEDIUM,
    'low': SEVERITY_INFO, 'info': SEVERITY_INFO,
}


def _map_severity(sev) -> str:
    return _BBOT_SEVERITY.get(str(sev or '').strip().lower(), SEVERITY_INFO)

# Safe default: a passive subdomain-enum preset. The preset is *config*, not a
# contract — it is injectable, so confirming/adjusting it later is a one-line
# default change, not a code restructure.
DEFAULT_PRESET = 'subdomain-enum'

# BBOT event type → the normalized bucket it lands in. Types absent from this map
# are ignored (OSINT/aux events outside phase-1 scope).
_ASSET_EVENT_BUCKET = {
    'DNS_NAME': 'hosts',
    'IP_ADDRESS': 'ips',
    'IP_RANGE': 'netblocks',
    'ASN': 'asns',
    'TECHNOLOGY': 'technologies',
    'URL': 'endpoints',
    'URL_UNVERIFIED': 'endpoints',   # lower confidence → tagged unverified
}
_FINDING_EVENT_TYPES = ('VULNERABILITY', 'FINDING')

# Scalar-ish keys a complex ``data`` dict may use for its primary value, tried in
# order when ``data`` is not already a plain string.
_SCALAR_KEYS = ('host', 'url', 'ip', 'asn', 'number', 'technology', 'name')


def _event_in_scope(obj: Dict) -> bool:
    """Whether a BBOT event is in-scope (an owned asset).

    ``scope_distance == 0`` is in-scope; ``≥ 1`` is an affiliate (skipped). A
    missing/unparseable distance defaults to in-scope — with ``--strict-scope``
    BBOT should not emit out-of-scope events anyway, and dropping un-tagged
    in-scope data would lose real assets."""
    dist = obj.get('scope_distance')
    if isinstance(dist, bool):   # bool is an int subclass — never a distance
        return True
    if isinstance(dist, int):
        return dist <= 0
    return True


def _scalar(obj: Dict) -> str:
    """Primary scalar value of an event (``data`` if a string, else a known key
    of the ``data`` dict, else the top-level ``host``)."""
    data = obj.get('data')
    if isinstance(data, (str, int)) and not isinstance(data, bool):
        return str(data).strip()
    if isinstance(data, dict):
        for key in _SCALAR_KEYS:
            val = data.get(key)
            if isinstance(val, (str, int)) and not isinstance(val, bool) and str(val).strip():
                return str(val).strip()
    host = obj.get('host')
    return str(host).strip() if host else ''


def _technology(obj: Dict) -> Optional[Dict]:
    """Normalise a TECHNOLOGY event to ``{name[, version]}`` (recon-asset shape),
    or ``None`` if no name is present."""
    data = obj.get('data')
    name, version = '', ''
    if isinstance(data, dict):
        name = data.get('technology') or data.get('name') or ''
        version = data.get('version') or ''
    elif isinstance(data, (str, int)) and not isinstance(data, bool):
        name = str(data)
    name = str(name).strip()
    if not name:
        return None
    out: Dict = {'name': name}
    if str(version).strip():
        out['version'] = str(version).strip()
    return out


def _finding(obj: Dict, *, is_vuln: bool) -> Optional[Dict]:
    """Normalise a VULNERABILITY/FINDING event to our raw-finding shape.

    The result flows unchanged through ``findings_adapter.from_raw`` (a CVE in the
    text auto-merges with nuclei/OSV). ``severity`` is mapped to the vuln
    scanner's 3-bucket scale: a VULNERABILITY's BBOT severity
    (CRITICAL/HIGH→High, MEDIUM→Medium, LOW→Info) and a FINDING (less-confirmed)
    is always Info. Returns ``None`` if there is nothing to describe."""
    data = obj.get('data')
    host = str(obj.get('host') or '').strip()
    module = str(obj.get('module') or '').strip()
    if isinstance(data, dict):
        description = str(data.get('description') or data.get('detail')
                          or data.get('name') or '').strip()
        sev = data.get('severity')
        location = data.get('url') or data.get('host') or host
    else:
        description = str(data or '').strip()
        sev = None
        location = host
    sev = sev or obj.get('severity')
    title = description or (host and f'BBOT {"vulnerability" if is_vuln else "finding"} on {host}') \
        or ('BBOT vulnerability' if is_vuln else 'BBOT finding')
    if not (description or host):
        return None
    severity = _map_severity(sev) if is_vuln else SEVERITY_INFO
    detail = ' · '.join(p for p in (
        description if description and description != title else '',
        f'host: {host}' if host else '',
        f'module: {module}' if module else '',
    ) if p)
    out: Dict = {'severity': severity, 'title': title, 'source': 'bbot'}
    if detail:
        out['detail'] = detail
    loc = str(location or '').strip()
    if loc:
        out['location'] = loc
    return out


def _dedup(values: List[str]) -> List[str]:
    """Order-preserving de-dup of scalar strings (case-insensitive)."""
    seen, out = set(), []
    for v in values:
        key = v.lower()
        if v and key not in seen:
            seen.add(key)
            out.append(v)
    return out


def parse_bbot_jsonl(text: str) -> Dict:
    """Parse ``bbot -om json`` NDJSON stdout into our normalized intermediate.

    Each non-empty line is one JSON event; malformed lines are skipped (the same
    tolerance as ``parse_nuclei_jsonl`` / ``parse_katana_lines``, which also lets
    BBOT's non-JSON log noise pass through harmlessly). Returns::

        {hosts, ips, asns, netblocks: [str],
         endpoints: [{url, unverified?}],
         technologies: [{name, version?}],
         findings: [{severity, title, detail?, location?, source}],
         stats: {events, in_scope, affiliates_skipped, ignored}}
    """
    buckets: Dict[str, List] = {k: [] for k in (
        'hosts', 'ips', 'asns', 'netblocks', 'endpoints', 'technologies',
        'findings')}
    stats = {'events': 0, 'in_scope': 0, 'affiliates_skipped': 0, 'ignored': 0}
    seen_endpoints: set = set()

    for line in (text or '').splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or not obj.get('type'):
            continue
        etype = str(obj.get('type'))
        if etype not in _ASSET_EVENT_BUCKET and etype not in _FINDING_EVENT_TYPES:
            continue   # OSINT/aux event outside phase-1 scope — not counted noise
        stats['events'] += 1
        if not _event_in_scope(obj):
            stats['affiliates_skipped'] += 1
            continue
        stats['in_scope'] += 1

        if etype in _FINDING_EVENT_TYPES:
            f = _finding(obj, is_vuln=etype == 'VULNERABILITY')
            if f:
                buckets['findings'].append(f)
            else:
                stats['ignored'] += 1
            continue

        bucket = _ASSET_EVENT_BUCKET[etype]
        if bucket == 'technologies':
            tech = _technology(obj)
            if tech:
                buckets['technologies'].append(tech)
            else:
                stats['ignored'] += 1
        elif bucket == 'endpoints':
            url = _scalar(obj)
            key = url.lower()
            if url and key not in seen_endpoints:
                seen_endpoints.add(key)
                ep: Dict = {'url': url}
                if etype == 'URL_UNVERIFIED':
                    ep['unverified'] = True
                buckets['endpoints'].append(ep)
        else:
            val = _scalar(obj)
            if val:
                buckets[bucket].append(val)
            else:
                stats['ignored'] += 1

    for key in ('hosts', 'ips', 'asns', 'netblocks'):
        buckets[key] = _dedup(buckets[key])
    buckets['stats'] = stats
    return buckets


def build_command(target: str, *, preset: str = DEFAULT_PRESET,
                  passive: bool = True,
                  extra_args: Optional[List[str]] = None) -> List[str]:
    """Build the BBOT CLI command for a safe, NDJSON-emitting scan.

    Default is the passive, strictly-scoped contract from T1.1: ``-rf passive``
    restricts to passive-flagged modules, ``--strict-scope`` keeps BBOT inside the
    target, ``-om json`` streams NDJSON to stdout and ``--silent`` quiets logs.
    No aggressive presets/brute-force by default; anything extra is opt-in via
    ``extra_args``.

    Note (T1.1 open question #2): the flag that suppresses BBOT's first-run
    interactive dependency prompt is intentionally NOT guessed here — it is added
    via ``extra_args`` once confirmed against the real binary, so we never ship an
    invented flag.
    """
    cmd = ['bbot', '-t', str(target), '-p', str(preset)]
    if passive:
        cmd += ['-rf', 'passive']
    cmd += ['--strict-scope', '-om', 'json', '--silent']
    if extra_args:
        cmd += [str(a) for a in extra_args]
    return cmd


class BBOTRunner:
    """Run BBOT against a target and return normalised recon data.

    Never raises (degrades to a status dict). The subprocess seam (``runner``) and
    the availability probe (``detector``) are injectable so the whole thing is
    unit-tested offline with canned NDJSON — no real binary or network needed.
    """

    def __init__(self, *, timeout: int = 600, preset: str = DEFAULT_PRESET,
                 passive: bool = True, extra_args: Optional[List[str]] = None,
                 runner: Optional[Callable] = None,
                 detector: Optional[Callable] = None):
        self.timeout = timeout
        self.preset = preset
        self.passive = passive
        self.extra_args = list(extra_args) if extra_args else []
        self._runner = runner or run_command
        self._detector = detector or has_bbot
        self.progress_callback: Optional[Callable] = None

    def available(self) -> bool:
        return bool(self._detector())

    def set_progress_callback(self, cb: Callable) -> None:
        self.progress_callback = cb

    def _log(self, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(msg)

    def run(self, target: str) -> Dict:
        """Scan ``target``; return ``{status, target, data?, truncated?, error?}``.

        ``status`` is ``Unavailable`` when BBOT is not installed, ``Error`` on a
        run failure, ``Success`` otherwise (with possibly-partial ``data``)."""
        result: Dict = {'status': 'Error', 'target': target}
        if not self.available():
            result['status'] = 'Unavailable'
            result['error'] = f'bbot not installed ({BBOT_HOMEPAGE})'
            return result

        cmd = build_command(target, preset=self.preset, passive=self.passive,
                            extra_args=self.extra_args)
        self._log(f'[bbot] scanning {target} '
                  f'(preset={self.preset}, passive={self.passive})')
        run = self._runner(cmd, self.timeout)
        error = command_error(run, 'bbot')
        if error:
            result['error'] = error
            self._log(f'[bbot] failed: {error}')
            return result

        data = parse_bbot_jsonl(run.get('stdout') or '')
        result['data'] = data
        result['truncated'] = run.get('timed_out', False)
        result['status'] = 'Success'
        result.pop('error', None)
        st = data['stats']
        self._log(f'[bbot] {st["in_scope"]} in-scope events, '
                  f'{len(data["findings"])} findings'
                  + (' (truncated)' if result['truncated'] else ''))
        return result
