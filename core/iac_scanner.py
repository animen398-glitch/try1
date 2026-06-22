"""core/iac_scanner.py
Cloud / Container / IaC config ingestion — phase 1 (EPIC NEXT F7).

Turn local infrastructure-as-code / container config files into first-class
findings (misconfigurations + leaked secrets) and assets (container images as
technologies), **without any cloud API** — phase 1 reads files on disk only. A
future live-cloud phase would be opt-in and Scope-Guarded (a separate task).

Supported (conservative, high-signal): Dockerfile, docker-compose, Kubernetes
manifests, CloudFormation, Terraform. YAML formats need an optional parser
(``features.has_yaml`` → PyYAML); absent → those files degrade to a soft skip
(stdlib formats — Dockerfile / Terraform / JSON CloudFormation — still run).
Secrets reuse the single SSOT (``secret_scanner.scan_text`` via
``document_intelligence.secret_findings_from_text``), validated and masked.

Pure / offline / never-raise: a malformed file is skipped, not fatal (the F-SR1
degrade-not-raise ethos). Findings are raw dicts (``source='iac'``) that flow
through ``findings_adapter.from_raw`` unchanged — lifecycle / SLA / compliance /
risk via severity come for free.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.document_intelligence import secret_findings_from_text

_MAX_FILE_BYTES = 512 * 1024     # skip anything larger — config files are small
_MAX_FILES = 2000                # bound a huge repo walk

_COMPOSE_NAMES = {'docker-compose.yml', 'docker-compose.yaml',
                  'compose.yml', 'compose.yaml'}
_YAML_EXT = {'.yml', '.yaml'}
_OPEN_CIDR = ('0.0.0.0/0', '::/0')


# ── helpers ───────────────────────────────────────────────────────────────────

def _finding(severity: str, title: str, detail: str, location: str,
             rule_id: str) -> Dict:
    """A raw IaC misconfiguration finding (``findings_adapter.from_raw`` shape)."""
    return {'severity': severity, 'title': title, 'detail': detail,
            'source': 'iac', 'category': 'iac', 'location': location,
            'rule_id': rule_id}


def _image_parts(image: str) -> Optional[Dict[str, str]]:
    """``repo:tag`` → ``{name, version}`` (digest/registry tolerated). None if blank."""
    s = str(image or '').strip()
    if not s:
        return None
    ref = s.split('@', 1)[0]                 # drop @sha256:… digest
    # A ':' after the last '/' is the tag (host:port before a '/' is not).
    tag = ''
    last = ref.rsplit('/', 1)[-1]
    if ':' in last:
        name_tail, tag = last.rsplit(':', 1)
        ref = ref[:len(ref) - len(last)] + name_tail
    return {'name': ref, 'version': tag}


def _unpinned(image: str) -> bool:
    parts = _image_parts(image)
    return bool(parts) and parts['version'] in ('', 'latest')


def _read(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:   # noqa: BLE001 — unreadable file is skipped, never fatal
        return None


# ── per-format parsers (each returns (findings, image strings)) ────────────────

def _scan_dockerfile(text: str, loc: str) -> Tuple[List[Dict], List[str]]:
    findings: List[Dict] = []
    images: List[str] = []
    has_user = False
    user_root = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        low = line.lower()
        if low.startswith('from '):
            img = line.split(None, 1)[1].split(' as ')[0].split(' AS ')[0].strip()
            images.append(img)
            if _unpinned(img):
                findings.append(_finding(
                    'Low', 'Unpinned container base image',
                    f'{loc} — FROM {img} is untagged/:latest (non-reproducible).',
                    loc, 'iac-docker-unpinned'))
        elif low.startswith('user '):
            has_user = True
            if line.split(None, 1)[1].strip().lower() in ('root', '0'):
                user_root = True
        elif low.startswith('add ') and re.search(r'https?://', line):
            findings.append(_finding(
                'Low', 'Dockerfile ADD fetches a remote URL',
                f'{loc} — ADD with a remote URL (use COPY / verified download).',
                loc, 'iac-docker-add-url'))
    if user_root or not has_user:
        findings.append(_finding(
            'Medium', 'Container runs as root',
            f'{loc} — no non-root USER set (drop privileges with USER).',
            loc, 'iac-docker-root'))
    return findings, images


def _scan_compose(doc: Dict, loc: str) -> Tuple[List[Dict], List[str]]:
    findings: List[Dict] = []
    images: List[str] = []
    services = doc.get('services') if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return findings, images
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        img = svc.get('image')
        if img:
            images.append(str(img))
            if _unpinned(str(img)):
                findings.append(_finding(
                    'Low', 'Unpinned container image',
                    f'{loc} — service "{name}" image {img} is untagged/:latest.',
                    loc, 'iac-compose-unpinned'))
        if svc.get('privileged') is True:
            findings.append(_finding(
                'High', 'Privileged container',
                f'{loc} — service "{name}" runs privileged (full host access).',
                loc, 'iac-compose-privileged'))
        if str(svc.get('network_mode') or '').strip().lower() == 'host':
            findings.append(_finding(
                'Medium', 'Container shares the host network',
                f'{loc} — service "{name}" uses network_mode: host.',
                loc, 'iac-compose-host-network'))
    return findings, images


_K8S_KINDS = {'pod', 'deployment', 'daemonset', 'statefulset', 'job',
              'cronjob', 'replicaset', 'replicationcontroller'}


def _k8s_containers(spec: Dict) -> Tuple[List[Dict], Dict]:
    """Containers + the effective pod spec (Pod spec or template.spec)."""
    pod = spec
    tmpl = spec.get('template') if isinstance(spec.get('template'), dict) else None
    if tmpl and isinstance(tmpl.get('spec'), dict):
        pod = tmpl['spec']
    out = []
    for key in ('containers', 'initContainers'):
        for c in (pod.get(key) or []):
            if isinstance(c, dict):
                out.append(c)
    return out, pod


def _scan_k8s(doc: Dict, loc: str) -> Tuple[List[Dict], List[str]]:
    findings: List[Dict] = []
    images: List[str] = []
    kind = str(doc.get('kind') or '').strip().lower()
    if kind not in _K8S_KINDS:
        return findings, images
    spec = doc.get('spec') if isinstance(doc.get('spec'), dict) else {}
    containers, pod = _k8s_containers(spec)
    if pod.get('hostNetwork') is True or pod.get('hostPID') is True \
            or pod.get('hostIPC') is True:
        findings.append(_finding(
            'High', 'Pod shares a host namespace',
            f'{loc} — hostNetwork/hostPID/hostIPC is enabled.',
            loc, 'iac-k8s-host-namespace'))
    for c in containers:
        img = c.get('image')
        if img:
            images.append(str(img))
            if _unpinned(str(img)):
                findings.append(_finding(
                    'Low', 'Unpinned container image',
                    f'{loc} — container "{c.get("name", "?")}" image {img} '
                    f'is untagged/:latest.', loc, 'iac-k8s-unpinned'))
        sc = c.get('securityContext') if isinstance(c.get('securityContext'),
                                                    dict) else {}
        if sc.get('privileged') is True:
            findings.append(_finding(
                'High', 'Privileged container',
                f'{loc} — container "{c.get("name", "?")}" runs privileged.',
                loc, 'iac-k8s-privileged'))
        if sc.get('allowPrivilegeEscalation') is True:
            findings.append(_finding(
                'Medium', 'Container allows privilege escalation',
                f'{loc} — container "{c.get("name", "?")}" allows priv-escalation.',
                loc, 'iac-k8s-priv-escalation'))
    return findings, images


def _scan_cloudformation(doc: Dict, loc: str) -> Tuple[List[Dict], List[str]]:
    findings: List[Dict] = []
    resources = doc.get('Resources') if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return findings, []
    for name, res in resources.items():
        if not isinstance(res, dict):
            continue
        rtype = str(res.get('Type') or '')
        props = res.get('Properties') if isinstance(res.get('Properties'),
                                                    dict) else {}
        if rtype == 'AWS::EC2::SecurityGroup':
            for ing in (props.get('SecurityGroupIngress') or []):
                if isinstance(ing, dict) and str(ing.get('CidrIp') or '') in _OPEN_CIDR:
                    findings.append(_finding(
                        'High', 'Security group open to the internet',
                        f'{loc} — {name} ingress allows {ing.get("CidrIp")}.',
                        loc, 'iac-cfn-open-sg'))
        elif rtype == 'AWS::S3::Bucket':
            acl = str(props.get('AccessControl') or '')
            if acl in ('PublicRead', 'PublicReadWrite'):
                findings.append(_finding(
                    'Medium', 'Public S3 bucket ACL',
                    f'{loc} — bucket {name} AccessControl={acl}.',
                    loc, 'iac-cfn-public-bucket'))
    return findings, []


def _scan_terraform(text: str, loc: str) -> Tuple[List[Dict], List[str]]:
    findings: List[Dict] = []
    if re.search(r'cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0', text) \
            or re.search(r'"0\.0\.0\.0/0"', text):
        findings.append(_finding(
            'High', 'Terraform ingress open to the internet',
            f'{loc} — a rule allows 0.0.0.0/0 (restrict the CIDR).',
            loc, 'iac-tf-open-ingress'))
    if re.search(r'acl\s*=\s*"public-read(-write)?"', text):
        findings.append(_finding(
            'Medium', 'Terraform public bucket ACL',
            f'{loc} — an ACL is set to public-read (make it private).',
            loc, 'iac-tf-public-bucket'))
    return findings, []


# ── dispatch ──────────────────────────────────────────────────────────────────

def _classify(path: Path) -> Optional[str]:
    name = path.name.lower()
    ext = path.suffix.lower()
    if name == 'dockerfile' or name.startswith('dockerfile.') \
            or ext == '.dockerfile':
        return 'dockerfile'
    if name in _COMPOSE_NAMES:
        return 'compose'
    if ext == '.tf':
        return 'terraform'
    if ext == '.json':
        return 'cfn-json'
    if ext in _YAML_EXT:
        return 'yaml'
    return None


def _route_yaml_doc(doc: Dict, loc: str) -> Tuple[List[Dict], List[str]]:
    """Route a parsed YAML/JSON doc to the right parser by its content shape."""
    if not isinstance(doc, dict):
        return [], []
    if doc.get('kind') and doc.get('apiVersion'):
        return _scan_k8s(doc, loc)
    if 'Resources' in doc or doc.get('AWSTemplateFormatVersion'):
        return _scan_cloudformation(doc, loc)
    if 'services' in doc:
        return _scan_compose(doc, loc)
    return [], []


def scan_path(path, *, base: Optional[str] = None) -> Dict:
    """Scan a file or directory of IaC/config files (pure, offline, never-raise).

    Returns ``{findings, technologies, summary}``: ``findings`` are raw dicts
    (misconfigurations ``source='iac'`` + leaked secrets ``source='iac'``);
    ``technologies`` are ``{name, version}`` container images (assets);
    ``summary`` counts files / findings / technologies and notes whether YAML
    parsing was available. ``base`` makes finding locations repo-relative."""
    from core.features import has_yaml
    root = Path(path)
    base_path = Path(base) if base else (root if root.is_dir() else root.parent)
    files = [root] if root.is_file() else (
        sorted(p for p in root.rglob('*') if p.is_file()) if root.is_dir() else [])
    yaml_ok = has_yaml()
    yaml_loader = None
    if yaml_ok:
        import yaml as _yaml
        yaml_loader = _yaml

    findings: List[Dict] = []
    images: List[str] = []
    scanned = skipped_yaml = 0
    for fp in files[:_MAX_FILES]:
        kind = _classify(fp)
        if kind is None:
            continue
        text = _read(fp)
        if text is None:
            continue
        try:
            loc = str(fp.relative_to(base_path)).replace('\\', '/')
        except ValueError:
            loc = fp.name
        scanned += 1
        try:
            if kind == 'dockerfile':
                f, im = _scan_dockerfile(text, loc)
            elif kind == 'terraform':
                f, im = _scan_terraform(text, loc)
            elif kind == 'cfn-json':
                doc = json.loads(text)
                f, im = _scan_cloudformation(doc, loc) if isinstance(doc, dict) \
                    else ([], [])
            else:   # yaml (compose / k8s / cloudformation)
                if not yaml_ok:
                    skipped_yaml += 1
                    f, im = [], []
                else:
                    f, im = [], []
                    for doc in yaml_loader.safe_load_all(text):
                        df, dim = _route_yaml_doc(doc, loc)
                        f += df
                        im += dim
            findings += f
            images += im
            # Secrets in every recognized config file (SSOT, validated, masked).
            findings += secret_findings_from_text(text, loc, source='iac')
        except Exception:   # noqa: BLE001 — a bad file degrades to a skip
            continue

    technologies = []
    seen = set()
    for img in images:
        parts = _image_parts(img)
        if parts and parts['name'] not in seen:
            seen.add(parts['name'])
            technologies.append(parts)

    summary = {'files': scanned, 'findings': len(findings),
               'technologies': len(technologies), 'yaml_available': yaml_ok,
               'skipped_yaml': skipped_yaml}
    return {'findings': findings, 'technologies': technologies, 'summary': summary}
