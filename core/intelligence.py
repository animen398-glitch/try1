"""core/intelligence.py
Core Intelligence Framework — from detection to explanation (Epic 7).

The platform already *detects* well and stores it in first-class models (findings,
assets, correlation, asset graph). This layer adds the *judgement* on top, fully
**derived on read** — no new model, no new table, no second scan:

  * **Confidence** — how sure we are a finding is real, from corroboration (how many
    independent scanners reported it), validation (a structurally-confirmed secret),
    and detection specificity (an exact CVE/takeover vs a generic heuristic).
  * **Priority** — what to fix first: the finding's severity *discounted by its
    confidence* (a high-severity but shaky finding must not outrank a confirmed one),
    amplified by exposure (it sits on a co-hosted / correlated asset — blast radius)
    and urgency (its remediation SLA is breached / due soon).
  * **Explanation** — why it matters: the knowledge catalog's impact/remediation plus
    the named factors that drove each score (so the number is auditable, like the
    risk engine's "why is the risk N").

Reuses, never duplicates: ``findings_store`` (active findings), ``correlation`` +
``asset_graph`` (exposure / blast radius), ``finding_knowledge`` (explanation),
``findings_sla`` (urgency), ``executive_summary.is_high_value_secret`` (secret tier),
and the canonical severity scale. Pure / stdlib / offline (I1/I5).
"""

from typing import Dict, List, Optional

from core.correlation import _host

# Per-category confidence base (0–100): how trustworthy a bare detection in this
# category is before corroboration/validation. Exact-match, actively-probed signals
# start high; a generic heuristic vuln starts lower.
_CONF_BASE = {
    'cve': 85, 'takeover': 85, 'sourcemap': 85, 'graphql': 85,
    'dependency': 80, 'cookie': 75, 'header': 75,
    'secret': 70, 'dns': 70, 'tech': 60, 'vuln': 60,
}
_CONF_MIN, _CONF_MAX = 10, 100
_CONF_HIGH, _CONF_MED = 80, 50      # band thresholds

# Severity → priority base (0–100), canonical lowercase scale.
_SEV_BASE = {'critical': 50, 'high': 35, 'medium': 18, 'low': 6, 'info': 2}


# ── confidence ────────────────────────────────────────────────────────────────

def _sources(finding: Dict) -> List[str]:
    ev = finding.get('evidence') or {}
    srcs = ev.get('sources') or ([ev.get('source')] if ev.get('source') else [])
    return [str(s) for s in srcs if s]


def _base_confidence(finding: Dict):
    """(base points, reason) — a CVE id outranks its bare ``vuln`` category."""
    rule = str(finding.get('rule_id') or '').lower()
    cat = str(finding.get('category') or 'vuln').lower()
    if rule.startswith('cve'):
        return _CONF_BASE['cve'], 'CVE-идентификатор'
    return _CONF_BASE.get(cat, 60), f'категория «{cat}»'


def confidence(finding: Dict) -> Dict:
    """Confidence that a finding is real → ``{score, band, factors}`` (pure).

    ``score`` 0–100; ``band`` is high/medium/low; ``factors`` are the named
    contributions (base + corroboration + validation) so the number is auditable."""
    base, reason = _base_confidence(finding)
    factors = [{'factor': f'Базовая ({reason})', 'points': base}]

    extra_sources = max(0, len(_sources(finding)) - 1)
    corr = min(20, extra_sources * 10)
    if corr:
        factors.append({'factor': f'Корроборация ({extra_sources + 1} источника)',
                        'points': corr})

    valid = 0
    if str(finding.get('category') or '').lower() == 'secret':
        from core.executive_summary import _is_high_value_secret_finding
        if _is_high_value_secret_finding(finding):
            valid = 15
            factors.append({'factor': 'Высокоценный секрет (точный формат)',
                            'points': valid})

    score = max(_CONF_MIN, min(_CONF_MAX, base + corr + valid))
    band = ('high' if score >= _CONF_HIGH
            else 'medium' if score >= _CONF_MED else 'low')
    return {'score': score, 'band': band, 'factors': factors}


# ── priority ──────────────────────────────────────────────────────────────────

def priority(finding: Dict, confidence_score: int, *, exposed: bool = False,
             clustered: bool = False, sla_bucket: Optional[str] = None) -> Dict:
    """Priority score → ``{score, factors}`` (pure).

    ``severity_base × confidence/100`` (confidence discounts severity), plus an
    exposure bonus (blast-radius / correlated asset) and an SLA-urgency bonus."""
    sev = str(finding.get('severity') or 'info').lower()
    base = _SEV_BASE.get(sev, 2)
    sev_pts = round(base * confidence_score / 100)
    factors = [{'factor': f'Severity {sev} × confidence {confidence_score}%',
                'points': sev_pts}]

    exposure_bonus = 10 if clustered else (5 if exposed else 0)
    if exposure_bonus:
        factors.append({'factor': ('Blast radius (общая инфра)' if clustered
                                   else 'На скоррелированном активе'),
                        'points': exposure_bonus})

    sla_bonus = 10 if sla_bucket == 'breached' else (5 if sla_bucket == 'due_soon' else 0)
    if sla_bonus:
        factors.append({'factor': ('SLA просрочен' if sla_bucket == 'breached'
                                   else 'SLA скоро истекает'),
                        'points': sla_bonus})

    score = min(100, sev_pts + exposure_bonus + sla_bonus)
    return {'score': score, 'factors': factors}


# ── explanation ───────────────────────────────────────────────────────────────

def explain(finding: Dict) -> Dict:
    """Why a finding matters — the knowledge catalog's description/impact/
    remediation (reused, F-O)."""
    from core.finding_knowledge import describe
    return describe(str(finding.get('category') or ''),
                    str(finding.get('rule_id') or ''),
                    str(finding.get('title') or ''),
                    finding.get('evidence') or {})


# ── aggregate ─────────────────────────────────────────────────────────────────

def _sla_bucket_of(finding: Dict, now) -> Optional[str]:
    try:
        from core import findings_sla
        return findings_sla.sla_bucket(findings_sla.sla_status(finding, now))
    except Exception:   # noqa: BLE001 — SLA is best-effort context
        return None


def build_intelligence(findings: List[Dict], correlation: Optional[Dict] = None,
                       asset_graph: Optional[Dict] = None, *, now=None) -> Dict:
    """Rank findings by priority, each with confidence + explanation (pure).

    ``correlation`` / ``asset_graph`` are the already-derived views (from
    ``load_correlation`` / ``load_asset_graph``); they provide exposure (a finding on
    a correlated asset) and blast radius (its host is in a shared-infra cluster).
    Returns ``{items (priority desc), top, summary}``."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    chains = (correlation or {}).get('finding_chains') or {}
    cluster_hosts = set()
    for c in (asset_graph or {}).get('shared_infra') or []:
        for m in c.get('members') or []:
            cluster_hosts.add(str(m).strip().lower())

    items: List[Dict] = []
    for f in findings:
        conf = confidence(f)
        chain = chains.get(f.get('id')) or {}
        exposed = bool(chain.get('host') or chain.get('endpoint'))
        host = _host(str((f.get('evidence') or {}).get('location') or ''))
        clustered = bool(host) and host in cluster_hosts
        bucket = _sla_bucket_of(f, now)
        prio = priority(f, conf['score'], exposed=exposed, clustered=clustered,
                        sla_bucket=bucket)
        items.append({
            'id': f.get('id'), 'title': f.get('title'),
            'severity': f.get('severity'), 'category': f.get('category'),
            'confidence': conf['score'], 'confidence_band': conf['band'],
            'confidence_factors': conf['factors'],
            'priority': prio['score'], 'priority_factors': prio['factors'],
            'explanation': explain(f),
        })

    items.sort(key=lambda i: (-i['priority'], -i['confidence'],
                              str(i.get('title') or '')))
    summary = {
        'findings': len(items),
        'high_confidence': sum(1 for i in items if i['confidence'] >= _CONF_HIGH),
        'top_priority': items[0]['priority'] if items else 0,
    }
    return {'items': items, 'top': items[:10], 'summary': summary}


def load_intelligence(project: str, *, now=None) -> Dict:
    """Build a project's intelligence view (thin reader; reuses the F1 store,
    correlation and the asset graph). Offline, read-only, guarded."""
    try:
        from core.asset_graph import load_asset_graph
        from core.correlation import load_correlation
        from core.findings_store import FindingsStore
        findings = FindingsStore().active_findings(project)
        return build_intelligence(findings, load_correlation(project),
                                  load_asset_graph(project), now=now)
    except Exception as e:  # noqa: BLE001 — surface as data, never crash a caller
        return {'items': [], 'top': [], 'summary': {}, 'error': str(e)}
