"""core/timeline.py
Historical Timeline / Change Events — the project's story over time (roadmap F2).

A project keeps every scan's ``report.json`` plus a ``metadata.json`` index and a
findings event trail (``finding_events``). This module *derives* the timeline
from those existing artifacts on read — there is deliberately NO second store of
events to drift out of sync (architectural invariant I3, and the roadmap's "do
not keep a second risk history"):

  * **series** — per-scan metric points (risk / secrets / attack-surface / high /
    medium), straight from ``metadata.json`` ``scans[]`` (already persisted by
    ``project.record_scan``). This is the data provider for charts.
  * **events** — a typed change feed built from the *shared* classifier
    ``scan_diff.diff_events`` over consecutive scans (one source of truth with
    Alert Center), plus findings lifecycle events (CREATED / RESOLVED_AUTO /
    REOPENED) from the F1 store.

Split for testability (I5): the two builders are pure (no I/O) and take already
loaded data; ``build_timeline`` is the thin loader that reads disk + the findings
DB and delegates. Offline and read-only — call it from a worker (I4).
"""

from typing import Dict, List, Optional, Tuple

from core.scan_diff import diff, diff_events

# finding_events.type → timeline event type. SEEN / STATUS_CHANGED are dropped as
# noise (a finding merely re-observed, or a user re-triage, is not a change event).
_FINDING_EVENT_TYPE = {
    'CREATED':       'new_finding',
    'RESOLVED_AUTO': 'finding_resolved',
    'REOPENED':      'finding_reopened',
}
# Fixed severities for the lifecycle types; ``new_finding`` carries the finding's
# own severity (None here → look it up on the event row).
_FINDING_EVENT_SEVERITY = {
    'new_finding':      None,
    'finding_resolved': 'info',
    'finding_reopened': 'medium',
}

# asset_event.type → timeline event type. SEEN is dropped as noise (an asset
# merely re-observed is not a change). A new/reappeared asset is an attack-surface
# expansion (low); a gone asset is informational.
_ASSET_EVENT_TYPE = {
    'CREATED':    'new_asset',
    'REAPPEARED': 'asset_reappeared',
    'GONE':       'asset_gone',
}
_ASSET_EVENT_SEVERITY = {
    'new_asset':        'low',
    'asset_reappeared': 'low',
    'asset_gone':       'info',
}

_SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def build_series(scan_entries: List[Dict]) -> List[Dict]:
    """Per-scan metric points from ``metadata.json`` ``scans[]`` (pure).

    Reuses the risk/secrets/attack-surface numbers already stored on each scan
    entry — never recomputed. Sorted chronologically by scan id (a timestamp)."""
    out: List[Dict] = []
    for s in scan_entries or []:
        if not isinstance(s, dict):
            continue
        out.append({
            'scan_id': s.get('id'),
            'at': s.get('finished_at'),
            'risk_score': s.get('risk_score'),
            'risk_level': s.get('risk_level'),
            'attack_surface': s.get('attack_surface_score'),
            'secrets': s.get('secrets'),
            'high': s.get('high'),
            'medium': s.get('medium'),
        })
    out.sort(key=lambda p: str(p.get('scan_id') or ''))
    return out


def build_events(scans: List[Tuple[str, Optional[Dict]]],
                 finding_events: Optional[List[Dict]] = None,
                 asset_events: Optional[List[Dict]] = None,
                 sla_events: Optional[List[Dict]] = None) -> List[Dict]:
    """The change feed (pure).

    ``scans`` is ``[(scan_id, report_or_None)]`` ascending by scan id. Structural
    and risk events come from ``diff_events`` of each scan vs the previous one
    that has a usable report (a missing/legacy report is skipped, never faked).
    ``finding_events`` are the F1 store rows (see ``FindingsStore.project_events``);
    ``asset_events`` are the Asset Inventory store rows (see
    ``AssetStore.project_events``); ``sla_events`` are already-shaped SLA-breach
    rows (see ``findings_sla.sla_events``) — time-based, not scan-based. Events
    are de-duplicated by ``(scan_id, type, title)`` and ordered chronologically.
    Each event is ``{scan_id, at, type, title, severity, section}``.
    """
    events: List[Dict] = []

    prev: Optional[Tuple[str, Dict]] = None
    for scan_id, report in scans or []:
        if not isinstance(report, dict):
            continue
        if prev is not None:
            at = report.get('finished_at') or ''
            for ev in diff_events(diff(prev[1], report)):
                events.append({'scan_id': scan_id, 'at': at, 'type': ev['type'],
                               'title': ev['title'], 'severity': ev['severity'],
                               'section': ev['section']})
        prev = (scan_id, report)

    for fe in finding_events or []:
        if not isinstance(fe, dict):
            continue
        etype = _FINDING_EVENT_TYPE.get(fe.get('type'))
        if not etype:
            continue
        # Secrets are first-class findings (F1) AND carry a tier-aware Scan-Diff
        # event (new_secret / new_secret_generic). Their *appearance* is already
        # represented by that diff event above, so drop the F1 'new_finding' for a
        # secret to avoid double-counting it in the timeline; the secret's fix /
        # reopen lifecycle (which the diff has no equivalent for) is kept.
        if etype == 'new_finding' and fe.get('category') == 'secret':
            continue
        severity = _FINDING_EVENT_SEVERITY[etype] or (fe.get('severity') or 'info')
        title = f"[{fe.get('severity', '')}] {fe.get('title', '')}".strip()
        events.append({'scan_id': fe.get('scan_id'), 'at': fe.get('at'),
                       'type': etype, 'title': title, 'severity': severity,
                       'section': 'findings'})

    for ae in asset_events or []:
        if not isinstance(ae, dict):
            continue
        etype = _ASSET_EVENT_TYPE.get(ae.get('type'))
        if not etype:
            continue
        label = ae.get('label') or ae.get('value') or ''
        title = f"[{ae.get('asset_type', '')}] {label}".strip()
        events.append({'scan_id': ae.get('scan_id'), 'at': ae.get('at'),
                       'type': etype, 'title': title,
                       'severity': _ASSET_EVENT_SEVERITY[etype],
                       'section': 'assets'})

    for se in sla_events or []:
        if isinstance(se, dict):
            events.append(se)

    seen = set()
    deduped: List[Dict] = []
    for ev in events:
        key = (ev.get('scan_id'), ev['type'], ev['title'])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ev)

    deduped.sort(key=lambda ev: (str(ev.get('at') or ''),
                                 str(ev.get('scan_id') or ''),
                                 _SEVERITY_RANK.get(ev.get('severity'), 9)))
    return deduped


def build_timeline(project) -> Dict:
    """Derive a project's full timeline (series + events) on read.

    Thin loader: pulls the scan index + each scan's report from disk and the
    findings events from the F1 store, then delegates to the pure builders.
    Offline, read-only — run it off the GUI thread (I4)."""
    from core.findings_store import FindingsStore

    entries = sorted(project.scans(), key=lambda s: str(s.get('id') or ''))
    scans = [(s.get('id'), project.load_scan_report(s.get('id')))
             for s in entries if s.get('id')]
    finding_events: List[Dict] = []
    sla_evts: List[Dict] = []
    try:
        store = FindingsStore()
        finding_events = store.project_events(project.slug)
        # Time-based SLA breaches of the still-active findings (reopen-aware).
        from core import findings_sla
        sla_evts = findings_sla.sla_events(
            store.active_findings(project.slug),
            reopened=store.reopen_dates(project.slug))
    except Exception:   # noqa: BLE001 — timeline must render even if findings fail
        finding_events, sla_evts = finding_events, sla_evts
    try:
        from core.asset_store import AssetStore
        asset_events = AssetStore().project_events(project.slug)
    except Exception:   # noqa: BLE001 — timeline must render even if assets fail
        asset_events = []
    return {
        'project': project.slug,
        'series': build_series(entries),
        'events': build_events(scans, finding_events, asset_events, sla_evts),
    }
