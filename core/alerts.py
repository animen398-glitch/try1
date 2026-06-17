"""core/alerts.py
Alert Center — notify on meaningful changes a monitored target picks up
(roadmap Phase 9). Built on Continuous Monitoring (#8): every auto Scan Diff
is the trigger, and the alertable events are derived from that diff.

Design / invariants:
  * Strictly opt-in. Nothing is sent unless an alert config with ``enabled:
    True`` and at least one channel is supplied — the offline-first contract is
    preserved (this is the one phase that egresses, by explicit choice).
  * I1 (no new deps): Telegram/Discord go over ``urllib`` (HTTP webhooks),
    e-mail over ``smtplib`` — all stdlib.
  * I5 (network split from logic): ``extract_alerts`` is a pure function over a
    diff dict; the channels' transport (``_http_post`` / ``_smtp_send``) is
    module-level so tests stub it and never touch the network.
  * Secret values are already masked in the diff (core.scan_diff masks at build
    time), so an alert body never carries a full leaked key.

Config shape (lives in settings.json under "alerts", so tokens stay out of the
per-project metadata files)::

    {
      "enabled": true,
      "types": ["new_secret", "takeover", "cert_change"],   # omit/empty = all
      "telegram": {"token": "...", "chat_id": "..."},
      "discord":  {"webhook_url": "https://discord.com/api/webhooks/..."},
      "email":    {"host": "smtp.example.com", "port": 587,
                   "username": "u", "password": "p",
                   "from": "bot@example.com", "to": "me@example.com",
                   "tls": true}
    }
"""

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import Dict, List, Optional

from core.scan_diff import diff_events

# The change types Alert Center understands. ``new_secret`` (a high-value
# cloud/payment/VCS credential) and ``new_secret_generic`` (a generic/opaque key)
# both come from the diff's secret section, tiered by severity (high vs medium) so
# a generic-key leak does not page at the same level as an AWS key.
# ``new_subdomain`` and ``takeover``
# both come from the diff's subdomain section (takeover is the dangerous subset).
# ``graphql_introspection`` (a schema that turned open between scans) is a
# high-severity signal worth a push; ``new_graphql`` stays timeline-only like
# ``new_endpoint`` (surface discovery, not a regression). ``cert_expired`` (a
# cert that crossed its deadline between scans) is alertable; ``cert_expiring``
# stays timeline-only — a heads-up, not yet a regression. ``new_sourcemap`` (a
# served .map that newly leaks original source between scans) is alertable —
# like an opened GraphQL schema, a clear regression. ``cookie_weakened`` (a
# cookie that lost Secure/HttpOnly/SameSite between scans) is alertable too;
# ``weak_cookie`` (a newly-served weak cookie) stays timeline-only — discovery,
# not a regression. ``new_vulnerable_dependency`` (a known-vulnerable JS library
# newly present) and ``dependency_vulnerable`` (an existing library that turned
# vulnerable between scans) are both alertable — a matched CVE is a clear new
# risk, like a newly-leaking source map. ``security_header_removed`` (a dropped
# HSTS / CSP / X-Frame-Options … between scans) is alertable too — a protection
# that regressed, like a degraded cookie.
ALERT_TYPES = ('new_secret', 'new_secret_generic', 'new_subdomain', 'takeover',
               'new_technology', 'cert_change', 'cert_expired', 'risk_increase',
               'graphql_introspection', 'new_sourcemap', 'cookie_weakened',
               'new_vulnerable_dependency', 'dependency_vulnerable',
               'security_header_removed', 'sla_breach')


# ── pure: derive alert events from a Scan Diff ────────────────────────────────

def extract_alerts(diff: Dict, types: Optional[List[str]] = None) -> List[Dict]:
    """Alertable events from a ``core.scan_diff.diff`` dict (pure, no I/O).

    A thin filter over the shared ``scan_diff.diff_events`` classifier (one
    source of truth, shared with the F2 timeline): keep only the alertable types
    (``ALERT_TYPES``), further narrowed by ``types`` when given (falsy = all
    alertable). Each event is ``{type, title, severity}``; secret titles are
    already masked. Timeline-only types (e.g. ``new_endpoint``, ``risk_decrease``)
    are excluded here."""
    want = set(types) if types else set(ALERT_TYPES)
    return [{'type': e['type'], 'title': e['title'], 'severity': e['severity']}
            for e in diff_events(diff)
            if e['type'] in ALERT_TYPES and e['type'] in want]


def format_alerts(slug: str, alerts: List[Dict]) -> tuple:
    """Render ``(subject, body)`` text for an alert batch."""
    subject = f'[Site Analyzer] {slug}: {len(alerts)} change(s) detected'
    lines = [f'• [{a.get("severity", "")}] {a.get("type")}: {a.get("title")}'
             for a in alerts]
    return subject, '\n'.join(lines)


# ── transport (module-level so tests stub it; no network in unit tests) ───────

def _http_post(url: str, data: bytes, headers: Dict, timeout: float = 10.0) -> int:
    """POST ``data`` and return the HTTP status code (raises on transport error)."""
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 — explicit https webhooks
        return getattr(resp, 'status', resp.getcode())


def _smtp_send(cfg: Dict, subject: str, body: str, timeout: float = 15.0) -> None:
    """Send ``body`` as a plain-text e-mail using the cfg's SMTP settings."""
    msg = MIMEText(body, _charset='utf-8')
    msg['Subject'] = subject
    msg['From'] = cfg['from']
    msg['To'] = cfg['to']
    with smtplib.SMTP(cfg['host'], int(cfg.get('port', 587)), timeout=timeout) as s:
        if cfg.get('tls', True):
            s.starttls()
        if cfg.get('username'):
            s.login(cfg['username'], cfg.get('password', ''))
        s.send_message(msg)


# ── channels ──────────────────────────────────────────────────────────────────

class TelegramChannel:
    name = 'telegram'

    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id

    def send(self, subject: str, body: str) -> Dict:
        url = f'https://api.telegram.org/bot{self.token}/sendMessage'
        payload = json.dumps({'chat_id': self.chat_id,
                              'text': f'{subject}\n\n{body}'}).encode('utf-8')
        status = _http_post(url, payload, {'Content-Type': 'application/json'})
        return {'channel': self.name,
                'status': 'ok' if status == 200 else f'http {status}'}


class DiscordChannel:
    name = 'discord'

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, subject: str, body: str) -> Dict:
        payload = json.dumps({'content': f'**{subject}**\n{body}'}).encode('utf-8')
        status = _http_post(self.webhook_url, payload,
                            {'Content-Type': 'application/json'})
        # Discord webhooks return 204 No Content on success.
        return {'channel': self.name,
                'status': 'ok' if status in (200, 204) else f'http {status}'}


class EmailChannel:
    name = 'email'

    def __init__(self, cfg: Dict):
        self.cfg = cfg

    def send(self, subject: str, body: str) -> Dict:
        _smtp_send(self.cfg, subject, body)
        return {'channel': self.name, 'status': 'ok'}


def build_channels(config: Dict) -> List:
    """Construct the channels whose required fields are present in ``config``."""
    channels: List = []
    tg = config.get('telegram') or {}
    if tg.get('token') and tg.get('chat_id'):
        channels.append(TelegramChannel(tg['token'], tg['chat_id']))
    dc = config.get('discord') or {}
    if dc.get('webhook_url'):
        channels.append(DiscordChannel(dc['webhook_url']))
    em = config.get('email') or {}
    if em.get('host') and em.get('from') and em.get('to'):
        channels.append(EmailChannel(em))
    return channels


def dispatch(channels: List, subject: str, body: str) -> List[Dict]:
    """Send to every channel; one failure never blocks the rest."""
    results: List[Dict] = []
    for ch in channels:
        try:
            results.append(ch.send(subject, body))
        except Exception as e:   # noqa: BLE001 — a channel error is reported, not fatal
            results.append({'channel': getattr(ch, 'name', '?'),
                            'status': 'error', 'error': str(e)})
    return results


def _record_delivery(target: str, kind: str, result: Dict) -> None:
    """Log an alert dispatch to the operations registry (the F4 delivery journal,
    surfaced by the History tab and web /history). Best-effort — a journaling
    failure must never affect sending. Secret values are already masked in the
    diff (and thus in ``results``), so nothing sensitive is persisted here."""
    try:
        from utils.operation_registry import OperationRegistry
        results = result.get('results') or []
        sent = result.get('sent', 0)
        attempted = len(results)
        reg = OperationRegistry()
        op = reg.start(target, 'alert', metadata={
            'kind': kind, 'sent': sent, 'attempted': attempted,
            'results': results, 'alerts': result.get('alerts')})
        ok = attempted > 0 and sent == attempted
        reg.finish(op, status='success' if ok else 'failed',
                   error=None if ok else f'{sent}/{attempted} channels delivered')
    except Exception:   # noqa: BLE001 — journaling is best-effort, never fatal
        pass


# ── top-level: notify from a diff ─────────────────────────────────────────────

def _send(config: Dict, slug: str, alerts: List[Dict], kind: str) -> Dict:
    """Send a prepared alert batch over the configured channels (shared tail of
    ``notify`` and ``notify_sla``). ``alerts`` are ``{type,title,severity}``."""
    if not alerts:
        return {'alerts': 0, 'sent': 0}
    channels = build_channels(config)
    if not channels:
        return {'alerts': len(alerts), 'sent': 0, 'reason': 'no channels'}
    subject, body = format_alerts(slug, alerts)
    results = dispatch(channels, subject, body)
    sent = sum(1 for r in results if r.get('status') == 'ok')
    out = {'alerts': len(alerts), 'sent': sent, 'results': results,
           'subject': subject}
    _record_delivery(slug, kind, out)
    return out


def notify(config: Optional[Dict], slug: str, diff: Dict) -> Dict:
    """Extract alerts from ``diff`` and send them over the configured channels.

    Returns ``{alerts, sent, results?, reason?}``. No-ops cleanly when alerts
    are disabled, nothing is alertable, or no channel is configured."""
    if not config or not config.get('enabled'):
        return {'alerts': 0, 'sent': 0, 'reason': 'disabled'}
    alerts = extract_alerts(diff, config.get('types') or None)
    return _send(config, slug, alerts, 'notify')


def collect_sla_alerts(store, project: str, *, now=None) -> List[Dict]:
    """New SLA-breach alert events for a project (one-shot, deduped via ``store``).

    SLA breach is time-triggered, not scan-triggered, so it never shows up in a
    Scan Diff — it is detected here from the persisted findings: the active
    findings past their (reopen-aware) remediation deadline, narrowed to those not
    yet alerted for their current open episode (``FindingsStore.record_sla_breaches``
    logs a one-shot ``SLA_BREACH`` marker and returns only the new ones). Returns
    lean ``{type:'sla_breach', title, severity}`` dicts — empty when nothing newly
    breached. Pure of network; ``store`` is injected so tests use a temp DB."""
    from core.findings_sla import sla_events, sla_status
    active = store.active_findings(project)
    if not active:
        return []
    reopened = store.reopen_dates(project)
    breached = [f for f in active
                if sla_status(f, now, None, reopened.get(f['id'])).get('breached')]
    if not breached:
        return []
    now_iso = now.isoformat(timespec='seconds') if now is not None else None
    new_ids = set(store.record_sla_breaches(
        project, [f['id'] for f in breached], now=now_iso))
    new_breached = [f for f in breached if f['id'] in new_ids]
    return [{'type': e['type'], 'title': e['title'], 'severity': e['severity']}
            for e in sla_events(new_breached, now=now, reopened=reopened)]


def notify_sla(config: Optional[Dict], slug: str,
               breach_alerts: List[Dict]) -> Dict:
    """Dispatch already-collected SLA-breach alerts (the time-triggered channel).

    ``breach_alerts`` come from :func:`collect_sla_alerts` (already deduped to NEW
    breaches). Honors the same ``types`` filter as diff alerts and shares the send
    tail / delivery journal. No-ops cleanly when disabled or filtered out."""
    if not config or not config.get('enabled'):
        return {'alerts': 0, 'sent': 0, 'reason': 'disabled'}
    want = set(config.get('types') or ALERT_TYPES)
    alerts = [a for a in breach_alerts
              if a.get('type') in want and a.get('type') in ALERT_TYPES]
    return _send(config, slug, alerts, 'sla')


def send_test(config: Optional[Dict]) -> Dict:
    """Send a fixed test message to every configured channel (config check)."""
    if not config:
        return {'sent': 0, 'reason': 'no config'}
    channels = build_channels(config)
    if not channels:
        return {'sent': 0, 'reason': 'no channels'}
    results = dispatch(channels, '[Site Analyzer] test alert',
                       'If you can read this, alerts are configured correctly.')
    out = {'sent': sum(1 for r in results if r.get('status') == 'ok'),
           'results': results}
    _record_delivery('alert-test', 'test', out)
    return out
