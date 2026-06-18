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


def _clamp(score) -> int:
    """Confidence score bounded to the valid 0-ish..100 range."""
    try:
        return max(_CONF_MIN, min(_CONF_MAX, int(score)))
    except (TypeError, ValueError):
        return _CONF_MIN


def _band(score: int) -> str:
    """high / medium / low band for a confidence score."""
    return ('high' if score >= _CONF_HIGH
            else 'medium' if score >= _CONF_MED else 'low')


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

    score = _clamp(base + corr + valid)
    return {'score': score, 'band': _band(score), 'factors': factors}


# ── unified scan accuracy (MODULE 1) ────────────────────────────────────────────
#
# The same judgement ``confidence`` makes for a finding — base trust + corroboration
# + verification, as auditable named factors — generalised to EVERY scanned entity:
# technologies, CVEs, assets, infrastructure, API endpoints and secrets. The answer
# to "how sure are we this is real?" for the whole inventory, not just findings.
#
# One engine, no duplication: each entity type reuses an existing verification
# signal (``secret_validator`` for secrets, the ``tech_fingerprint`` evidence method
# for technologies, the CVSS/enrichment source for CVEs, the producing phase for
# assets/infra). Every result has the same shape so any surface renders them
# uniformly: ``{score, band, factors, evidence, source, verification}``. Pure /
# stdlib / offline (I1/I5); derive-on-read, no new model or table.

ENTITY_TYPES = ('finding', 'technology', 'cve', 'asset', 'infrastructure',
                'api', 'secret')

# Base confidence per entity type (before corroboration / verification bonuses).
_ENTITY_BASE = {'cve': 85, 'secret': 70, 'api': 60}

# tech_fingerprint encodes HOW a technology was matched in its evidence prefix
# (``header:…`` / ``cookie:…`` / ``script:…`` / ``html``). An exact header or an
# advertised cookie is a far stronger signal than a bare HTML-body regex.
_TECH_METHOD_CONF = {'header': 80, 'cookie': 78, 'script': 72, 'html': 60}

# Asset source phase → base. Actively observed / probed sources rank above names
# seen only in TLS material (a cert SAN / CT log we never connected to).
_ASSET_SOURCE_CONF = {
    'recon': 78, 'subdomains': 78, 'asn_intel': 78, 'katana': 75,
    'openapi': 75, 'security': 72, 'certificate': 62, 'ct': 58,
}

_EMPTY_ACCURACY = {'score': 0, 'band': 'low', 'factors': [], 'evidence': [],
                   'source': [], 'verification': 'unknown'}


def _result(factors: List[Dict], *, evidence: List, source: List,
            verification: str) -> Dict:
    """Assemble the unified accuracy result from named factors (pure).

    ``score`` is the clamped sum of factor points; ``band`` is derived from it.
    Empty/falsy evidence and source items are dropped so a surface gets clean lists."""
    factors = [f for f in factors if f]
    score = _clamp(sum(int(f.get('points', 0)) for f in factors))
    return {'score': score, 'band': _band(score), 'factors': factors,
            'evidence': [str(e) for e in (evidence or []) if e],
            'source': [str(s) for s in (source or []) if s],
            'verification': verification}


def _acc_finding(f: Dict) -> Dict:
    """Finding accuracy — reuses :func:`confidence` (unchanged) and adds the
    evidence / source / verification the unified shape carries."""
    c = confidence(f)
    cat = str(f.get('category') or '').lower()
    rule = str(f.get('rule_id') or '').lower()
    srcs = _sources(f)
    if cat == 'secret':
        from core.executive_summary import _is_high_value_secret_finding
        verification = ('high-value' if _is_high_value_secret_finding(f)
                        else 'generic')
    elif rule.startswith('cve'):
        verification = 'cve-id'
    elif len(srcs) > 1:
        verification = 'corroborated'
    else:
        verification = 'heuristic'
    ev = f.get('evidence') or {}
    evidence = [e for e in (ev.get('detail'), ev.get('location')) if e]
    return {'score': c['score'], 'band': c['band'], 'factors': c['factors'],
            'evidence': [str(e) for e in evidence], 'source': srcs,
            'verification': verification}


def _evidence_list(value) -> List:
    return value if isinstance(value, list) else ([value] if value else [])


def _acc_technology(t: Dict) -> Dict:
    """Technology accuracy — confidence by detection method, +version, +corroboration."""
    ev_list = _evidence_list(t.get('evidence'))
    method = str(ev_list[0]).split(':', 1)[0] if ev_list else ''
    base = _TECH_METHOD_CONF.get(method, 65)
    factors = [{'factor': f'Признак: {method or "эвристика"}', 'points': base}]
    version = t.get('version') or (t.get('attrs') or {}).get('version')
    if version:
        factors.append({'factor': f'Версия извлечена ({version})', 'points': 15})
    if len(ev_list) > 1:
        factors.append({'factor': f'Несколько признаков ({len(ev_list)})',
                        'points': 10})
    source = [t.get('source') or (t.get('attrs') or {}).get('source') or 'recon']
    verification = ('version-confirmed' if version
                    else 'exact-match' if method in ('header', 'cookie', 'script')
                    else 'heuristic')
    return _result(factors, evidence=ev_list or [t.get('name')], source=source,
                   verification=verification)


def _acc_cve(c: Dict) -> Dict:
    """CVE accuracy — an exact id is high base; CVSS enrichment + multiple advisory
    databases corroborate it."""
    cid = c.get('id') or c.get('cve') or c.get('rule_id') or ''
    factors = [{'factor': 'Точный CVE-идентификатор', 'points': _ENTITY_BASE['cve']}]
    cvss = c.get('cvss')
    if cvss is not None:
        factors.append({'factor': f'CVSS подтверждён ({cvss})', 'points': 10})
    raw = c.get('sources') or ([c.get('source')] if c.get('source') else [])
    dbs = {part for s in raw for part in str(s).split('+') if part}   # 'osv+nvd'
    if len(dbs) > 1:
        factors.append({'factor': f'Несколько баз CVE ({len(dbs)})', 'points': 5})
    evidence = [cid]
    if cvss is not None:
        evidence.append(f'CVSS {cvss}')
    if c.get('published'):
        evidence.append(str(c['published']))
    return _result(factors, evidence=evidence, source=sorted(dbs) or ['osv'],
                   verification='cvss-confirmed' if cvss is not None
                   else 'advisory-listed')


def _acc_asset(a: Dict) -> Dict:
    """Asset accuracy — base by producing phase, +active probe, +resolved IP."""
    attrs = a.get('attrs') or {}
    source = str(attrs.get('source') or '')
    base = _ASSET_SOURCE_CONF.get(source, 65)
    factors = [{'factor': f'Источник: {source or "—"}', 'points': base}]
    probed = attrs.get('http_status') or attrs.get('status') or attrs.get('service')
    if probed:
        factors.append({'factor': 'Активная проба', 'points': 10})
    if attrs.get('ip'):
        factors.append({'factor': 'Разрешается в IP', 'points': 5})
    verification = ('probed' if probed
                    else 'tls-observed' if source in ('certificate', 'ct')
                    else 'derived')
    evidence = [f"{a.get('type')}={a.get('label') or a.get('value')}"]
    evidence += [f'{k}={attrs[k]}' for k in ('ip', 'cname', 'service',
                                             'http_status') if attrs.get(k)]
    return _result(factors, evidence=evidence, source=[source or 'recon'],
                   verification=verification)


def _acc_infrastructure(i: Dict) -> Dict:
    """Infrastructure accuracy — active RDAP/RIPEstat (asn_intel) outranks the
    passive geo derive recon builds from a single lookup."""
    source = str(i.get('source')
                 or ('asn_intel' if i.get('cidr') or i.get('prefixes') else 'recon'))
    base = 78 if source == 'asn_intel' else 60
    factors = [{'factor': f'Источник: {source}', 'points': base}]
    if i.get('asn'):
        factors.append({'factor': 'ASN определён', 'points': 5})
    if i.get('provider'):
        factors.append({'factor': 'Провайдер определён', 'points': 5})
    evidence = [f'{k}={i[k]}' for k in ('ip', 'asn', 'asn_name', 'provider',
                                        'location') if i.get(k)]
    return _result(factors, evidence=evidence, source=[source],
                   verification='active-rdap' if source == 'asn_intel'
                   else 'passive-derive')


def _acc_api(a: Dict) -> Dict:
    """API-endpoint accuracy — a live 2xx response confirms it far more than a
    merely-listed path (OpenAPI map)."""
    factors = [{'factor': 'Обнаруженный API-эндпоинт', 'points': _ENTITY_BASE['api']}]
    status = a.get('status') or a.get('http_status')
    responded = bool(status) and str(status).startswith('2')
    if responded:
        factors.append({'factor': f'Отвечает {status}', 'points': 15})
    if a.get('method'):
        factors.append({'factor': f'Метод {a["method"]}', 'points': 5})
    evidence = [e for e in (a.get('path') or a.get('url'), a.get('method'),
                            f'status={status}' if status else '') if e]
    return _result(factors, evidence=evidence, source=[a.get('source') or 'api'],
                   verification='responded' if responded else 'listed')


def _acc_secret(s: Dict) -> Dict:
    """Secret accuracy — structurally validated offline (``secret_validator``): a
    confirmed format raises confidence, a placeholder collapses it; a high-value
    vendor type adds a tier bonus."""
    stype = str(s.get('type') or s.get('key_type') or '')
    factors = [{'factor': f'Секрет типа «{stype or "—"}»',
                'points': _ENTITY_BASE['secret']}]
    status = s.get('status')
    if status is None and s.get('value') is not None:
        from core.secret_validator import validate
        status = validate(stype, str(s.get('value'))).get('status')
    from core.secret_validator import INVALID, VALID
    if status == VALID:
        factors.append({'factor': 'Формат подтверждён', 'points': 20})
        verification = 'valid_format'
    elif status == INVALID:
        factors.append({'factor': 'Похоже на плейсхолдер', 'points': -35})
        verification = 'invalid_format'
    else:
        verification = 'unverifiable'
    from core.executive_summary import is_high_value_secret
    if stype and is_high_value_secret(stype):
        factors.append({'factor': 'Высокоценный тип', 'points': 10})
    evidence = [e for e in (stype, s.get('preview')) if e]
    return _result(factors, evidence=evidence, source=[s.get('source') or 'secret'],
                   verification=verification)


_ACCURACY_FNS = {
    'finding': _acc_finding, 'technology': _acc_technology, 'cve': _acc_cve,
    'asset': _acc_asset, 'infrastructure': _acc_infrastructure,
    'api': _acc_api, 'secret': _acc_secret,
}


def confidence_for(entity_type: str, entity: Dict) -> Dict:
    """Unified scan-accuracy confidence for ANY scanned entity (pure, MODULE 1).

    ``entity_type`` is one of :data:`ENTITY_TYPES`; ``entity`` is the entity dict
    in its native shape (a Finding row, a ``tech_fingerprint`` tech, a CVE record,
    an ``AssetStore`` row, a recon ``infrastructure`` block, an API endpoint, or a
    detected secret). Returns ``{score, band, factors, evidence, source,
    verification}`` — the same shape for every type. Unknown type / non-dict →
    an empty (zero-confidence) result; a helper that raises degrades to a zeroed
    result with an ``error`` key (degrade-not-raise, F-SR1 ethos)."""
    fn = _ACCURACY_FNS.get(str(entity_type))
    if fn is None or not isinstance(entity, dict):
        return dict(_EMPTY_ACCURACY)
    try:
        return fn(entity)
    except Exception as e:  # noqa: BLE001 — accuracy is best-effort context
        return {**_EMPTY_ACCURACY, 'verification': 'error', 'error': str(e)}


def _entity_label(entity_type: str, entity: Dict) -> str:
    """A short display label for an accuracy row, per entity type."""
    if entity_type == 'finding':
        return str(entity.get('title') or '')
    if entity_type == 'technology':
        ver = entity.get('version')
        return f"{entity.get('name', '')} {ver}".strip() if ver \
            else str(entity.get('name') or '')
    if entity_type == 'cve':
        return str(entity.get('id') or entity.get('cve')
                   or entity.get('rule_id') or '')
    if entity_type == 'asset':
        return str(entity.get('label') or entity.get('value') or '')
    if entity_type == 'infrastructure':
        return str(entity.get('asn') or entity.get('ip') or 'infrastructure')
    if entity_type == 'api':
        return str(entity.get('path') or entity.get('url') or '')
    if entity_type == 'secret':
        return str(entity.get('type') or entity.get('key_type') or '')
    return ''


def build_accuracy(entities_by_type: Dict[str, List[Dict]]) -> Dict:
    """Score a batch of mixed-type entities → a unified accuracy rollup (pure).

    ``entities_by_type`` maps each :data:`ENTITY_TYPES` value to its list of entity
    dicts (collected by the caller — the report/store reader, EPIC 12). Returns
    ``{by_type, items, summary}`` where ``items`` are every scored entity
    (confidence desc) and ``by_type[t]`` is ``{items, count, high_confidence,
    avg_confidence}``. Decoupled from any report shape, so it is trivially testable
    and every surface (report card / GUI / web / CSV) feeds it the same way."""
    items: List[Dict] = []
    by_type: Dict[str, Dict] = {}
    for etype, entities in (entities_by_type or {}).items():
        bucket = by_type.setdefault(
            etype, {'items': [], 'count': 0, 'high_confidence': 0})
        for ent in entities or []:
            acc = confidence_for(etype, ent)
            row = {'entity_type': etype,
                   'label': _entity_label(etype, ent), **acc}
            items.append(row)
            bucket['items'].append(row)
            bucket['count'] += 1
            if acc['score'] >= _CONF_HIGH:
                bucket['high_confidence'] += 1
    for bucket in by_type.values():
        scores = [i['score'] for i in bucket['items']]
        bucket['avg_confidence'] = round(sum(scores) / len(scores)) if scores else 0

    items.sort(key=lambda i: (-i['score'], str(i.get('label') or '')))
    summary = {
        'entities': len(items),
        'high_confidence': sum(1 for i in items if i['score'] >= _CONF_HIGH),
        'avg_confidence': (round(sum(i['score'] for i in items) / len(items))
                           if items else 0),
        'by_type': {t: b['count'] for t, b in by_type.items()},
    }
    return {'by_type': by_type, 'items': items, 'summary': summary}


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
        acc = confidence_for('finding', f)
        chain = chains.get(f.get('id')) or {}
        exposed = bool(chain.get('host') or chain.get('endpoint'))
        host = _host(str((f.get('evidence') or {}).get('location') or ''))
        clustered = bool(host) and host in cluster_hosts
        bucket = _sla_bucket_of(f, now)
        prio = priority(f, acc['score'], exposed=exposed, clustered=clustered,
                        sla_bucket=bucket)
        items.append({
            'id': f.get('id'), 'title': f.get('title'),
            'severity': f.get('severity'), 'category': f.get('category'),
            'confidence': acc['score'], 'confidence_band': acc['band'],
            'confidence_factors': acc['factors'],
            # MODULE 1: the unified accuracy fields (evidence / source / how the
            # finding was verified) ride along with the confidence number.
            'evidence': acc['evidence'], 'source': acc['source'],
            'verification': acc['verification'],
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
