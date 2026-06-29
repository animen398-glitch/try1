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
    entry — never recomputed. Also carries the detection-category counts that
    ``_scan_entry`` denormalizes for cross-scan use (source maps / weak cookies /
    GraphQL exposure), so the trend layer can answer "is our exposure hygiene
    degrading?" over the history. Sorted chronologically by scan id (a timestamp).
    Pre-EPIC metadata without these keys leaves them ``None`` (a gap, not a fake 0)."""
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
            'source_map_leaks': s.get('source_map_leaks'),
            'weak_cookies': s.get('weak_cookies'),
            'graphql': s.get('graphql'),
            'graphql_introspection': s.get('graphql_introspection'),
        })
    out.sort(key=lambda p: str(p.get('scan_id') or ''))
    return out


def build_events(scans: List[Tuple[str, Optional[Dict]]],
                 finding_events: Optional[List[Dict]] = None,
                 asset_events: Optional[List[Dict]] = None,
                 sla_events: Optional[List[Dict]] = None,
                 audit_runs: Optional[List[Dict]] = None,
                 audit_events: Optional[List[Dict]] = None,
                 kev_events: Optional[List[Dict]] = None,
                 missions: Optional[List[Dict]] = None) -> List[Dict]:
    """The change feed (pure).

    ``scans`` is ``[(scan_id, report_or_None)]`` ascending by scan id. Structural
    and risk events come from ``diff_events`` of each scan vs the previous one
    that has a usable report (a missing/legacy report is skipped, never faked).
    ``finding_events`` are the F1 store rows (see ``FindingsStore.project_events``);
    ``asset_events`` are the Asset Inventory store rows (see
    ``AssetStore.project_events``); ``sla_events`` are already-shaped SLA-breach
    rows (see ``findings_sla.sla_events``) and ``kev_events`` already-shaped
    KEV (known-exploited) rows (see ``threat_intel.kev_events``) — both time-based,
    not scan-based. ``missions`` are Mission Center store rows (see
    ``MissionStore.list_missions``); a mission carries no event log, so a created
    event is derived from ``created_at`` and a single status event from
    ``updated_at`` whenever the mission has moved past ``draft``. Events are
    de-duplicated by ``(scan_id, type, title)`` and ordered chronologically.
    Each event is ``{scan_id, at, type, title, severity, section}``.
    """
    events: List[Dict] = []

    # Secrets are first-class findings (api phase + the deep-JS security audit), so
    # the F1 finding events (new_finding / resolved / reopened) are the canonical
    # secret timeline — they cover both producers, the correct first-seen scan, and
    # the lifecycle. When the project has secret findings, drop the Scan-Diff
    # ``secrets`` section from the feed to avoid double-counting a secret's
    # appearance (the tier-aware diff events still drive Alert Center, which reads
    # diff_events directly). Backward-compatible: an old project with no secret
    # findings keeps its Scan-Diff secret events.
    has_secret_findings = any(isinstance(fe, dict) and fe.get('category') == 'secret'
                              for fe in (finding_events or []))

    prev: Optional[Tuple[str, Dict]] = None
    for scan_id, report in scans or []:
        if not isinstance(report, dict):
            continue
        if prev is not None:
            at = report.get('finished_at') or ''
            for ev in diff_events(diff(prev[1], report)):
                if has_secret_findings and ev['section'] == 'secrets':
                    continue
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

    for ke in kev_events or []:
        if isinstance(ke, dict):
            events.append(ke)

    for run in audit_runs or []:
        if not isinstance(run, dict):
            continue
        run_id = str(run.get('id') or run.get('run_id') or '').strip()
        if not run_id:
            continue
        profile = str(run.get('profile') or 'client_safe')
        status = str(run.get('status') or '').strip().lower()
        events.append({'scan_id': None, 'at': run.get('created_at'),
                       'type': 'audit_run_started',
                       'title': f"[{profile}] {run_id} started",
                       'severity': 'info', 'section': 'audit_runs'})
        if status in {'completed', 'failed'}:
            events.append({'scan_id': None, 'at': run.get('updated_at'),
                           'type': f'audit_run_{status}',
                           'title': f"[{profile}] {run_id} {status}",
                           'severity': 'info' if status == 'completed' else 'medium',
                           'section': 'audit_runs'})

    for ae in audit_events or []:
        if not isinstance(ae, dict):
            continue
        event_type = str(ae.get('type') or '').strip()
        run_id = str(ae.get('run_id') or '').strip()
        if not event_type or not run_id:
            continue
        finding = str(ae.get('finding_id') or '').strip()
        phase = str(ae.get('phase') or '').strip()
        suffix = f" finding={finding}" if finding else (f" phase={phase}" if phase else "")
        severity = 'medium' if event_type in {'finding_rejected', 'quality_gate_failed'} else 'info'
        events.append({'scan_id': None, 'at': ae.get('at'),
                       'type': f'audit_{event_type}',
                       'title': f"{run_id} {event_type}{suffix}",
                       'severity': severity, 'section': 'audit_runs'})

    for mission in missions or []:
        if not isinstance(mission, dict):
            continue
        mission_id = str(mission.get('id') or mission.get('mission_id') or '').strip()
        if not mission_id:
            continue
        payload = mission.get('payload')
        objective = payload.get('objective') if isinstance(payload, dict) else None
        label = str(objective or mission_id).strip()
        profile = str(mission.get('profile') or 'client_safe')
        status = str(mission.get('status') or '').strip().lower()
        events.append({'scan_id': None, 'at': mission.get('created_at'),
                       'type': 'mission_created',
                       'title': f"[{profile}] {label} created",
                       'severity': 'info', 'section': 'missions'})
        if status and status != 'draft':
            events.append({'scan_id': None, 'at': mission.get('updated_at'),
                           'type': f'mission_{status}',
                           'title': f"[{profile}] {label} {status}",
                           'severity': 'medium' if status == 'failed' else 'info',
                           'section': 'missions'})

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
    kev_evts: List[Dict] = []
    try:
        store = FindingsStore()
        finding_events = store.project_events(project.slug)
        # Annotate the still-active findings against the offline KEV/EPSS cache
        # once (cold cache = no-op), then derive both time-based feeds from it:
        # SLA breaches on the (tightened) deadline, and KEV known-exploited flags.
        from core import findings_sla, threat_intel
        active = threat_intel.annotate_offline(store.active_findings(project.slug))
        sla_evts = findings_sla.sla_events(
            active, reopened=store.reopen_dates(project.slug))
        kev_evts = threat_intel.kev_events(active)
    except Exception:   # noqa: BLE001 — timeline must render even if findings fail
        finding_events, sla_evts, kev_evts = finding_events, sla_evts, kev_evts
    try:
        from core.asset_store import AssetStore
        asset_events = AssetStore().project_events(project.slug)
    except Exception:   # noqa: BLE001 — timeline must render even if assets fail
        asset_events = []
    try:
        from core.audit_store import AuditRunStore
        audit_store = AuditRunStore()
        audit_runs = audit_store.list_runs(project.slug)
        audit_events = [
            event
            for run in audit_runs
            for event in audit_store.events(run.get('id'))
        ]
    except Exception:   # noqa: BLE001 - timeline must render even if audit store fails
        audit_runs, audit_events = [], []
    try:
        from core.mission_store import MissionStore
        missions = MissionStore().list_missions(project.slug)
    except Exception:   # noqa: BLE001 - timeline must render even if mission store fails
        missions = []
    return {
        'project': project.slug,
        'series': build_series(entries),
        'events': build_events(
            scans,
            finding_events,
            asset_events,
            sla_evts,
            audit_runs,
            audit_events,
            kev_evts,
            missions=missions,
        ),
    }
