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

# The change types Alert Center understands. ``new_subdomain`` and ``takeover``
# both come from the diff's subdomain section (takeover is the dangerous subset).
ALERT_TYPES = ('new_secret', 'new_subdomain', 'takeover', 'new_technology',
               'cert_change', 'risk_increase')


# ── pure: derive alert events from a Scan Diff ────────────────────────────────

def extract_alerts(diff: Dict, types: Optional[List[str]] = None) -> List[Dict]:
    """Alertable events from a ``core.scan_diff.diff`` dict (pure, no I/O).

    ``types`` filters to a subset of ``ALERT_TYPES``; falsy means all. Each
    event is ``{type, title, severity}``; secret titles are already masked."""
    sections = (diff or {}).get('sections', {})
    out: List[Dict] = []

    def want(t: str) -> bool:
        return not types or t in types

    if want('new_secret'):
        for label in sections.get('secrets', {}).get('added', []):
            out.append({'type': 'new_secret', 'title': str(label),
                        'severity': 'high'})

    # Subdomains: a takeover candidate is the dangerous subset (its label carries
    # the takeover marker that core.scan_diff attaches).
    for label in sections.get('subdomains', {}).get('added', []):
        text = str(label)
        if 'takeover' in text.lower():
            if want('takeover'):
                out.append({'type': 'takeover', 'title': text,
                            'severity': 'critical'})
        elif want('new_subdomain'):
            out.append({'type': 'new_subdomain', 'title': text,
                        'severity': 'medium'})

    if want('new_technology'):
        for label in sections.get('technologies', {}).get('added', []):
            out.append({'type': 'new_technology', 'title': str(label),
                        'severity': 'info'})

    if want('cert_change'):
        for ch in sections.get('certificates', {}).get('changed', []):
            if isinstance(ch, dict):
                out.append({
                    'type': 'cert_change',
                    'title': f"{ch.get('key')}: {ch.get('a')} → {ch.get('b')}",
                    'severity': 'medium'})

    if want('risk_increase'):
        risk = (diff or {}).get('risk', {})
        if (risk.get('risk_100_b') or 0) > (risk.get('risk_100_a') or 0):
            out.append({
                'type': 'risk_increase',
                'title': (f"{risk.get('level_a')} {risk.get('risk_100_a')} → "
                          f"{risk.get('level_b')} {risk.get('risk_100_b')}"),
                'severity': 'high'})

    return out


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


# ── top-level: notify from a diff ─────────────────────────────────────────────

def notify(config: Optional[Dict], slug: str, diff: Dict) -> Dict:
    """Extract alerts from ``diff`` and send them over the configured channels.

    Returns ``{alerts, sent, results?, reason?}``. No-ops cleanly when alerts
    are disabled, nothing is alertable, or no channel is configured."""
    if not config or not config.get('enabled'):
        return {'alerts': 0, 'sent': 0, 'reason': 'disabled'}
    alerts = extract_alerts(diff, config.get('types') or None)
    if not alerts:
        return {'alerts': 0, 'sent': 0}
    channels = build_channels(config)
    if not channels:
        return {'alerts': len(alerts), 'sent': 0, 'reason': 'no channels'}
    subject, body = format_alerts(slug, alerts)
    results = dispatch(channels, subject, body)
    sent = sum(1 for r in results if r.get('status') == 'ok')
    return {'alerts': len(alerts), 'sent': sent, 'results': results,
            'subject': subject}


def send_test(config: Optional[Dict]) -> Dict:
    """Send a fixed test message to every configured channel (config check)."""
    if not config:
        return {'sent': 0, 'reason': 'no config'}
    channels = build_channels(config)
    if not channels:
        return {'sent': 0, 'reason': 'no channels'}
    results = dispatch(channels, '[Site Analyzer] test alert',
                       'If you can read this, alerts are configured correctly.')
    return {'sent': sum(1 for r in results if r.get('status') == 'ok'),
            'results': results}
