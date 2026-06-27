import json

import pytest

from core.audit_schema import validate_audit_payload
from core.audit_workflow import advance_audit_phase, audit_run_to_json, create_audit_run


def test_audit_run_schema_rejects_malformed_payload():
    malformed = {
        "run_id": "audit-schema-bad",
        "project": "example.com",
        "status": "completed",
        "phases": "not-a-list",
    }

    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_audit_payload(malformed, "asa_audit_run")


def test_finding_schema_rejects_missing_required_client_safe_fields():
    malformed = {
        "id": "finding-schema-bad",
        "title": "Critical claim without evidence",
        "severity": "critical",
        "validation_status": "verified",
        "confidence": 95,
    }

    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_audit_payload(malformed, "asa_finding")


def test_validation_schema_rejects_unknown_status():
    malformed = {
        "finding_id": "finding-schema-bad",
        "validation_status": "definitely_verified",
        "confidence": 95,
        "evidence_refs": ["evidence/ref.json"],
    }

    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_audit_payload(malformed, "asa_validation")


def test_audit_json_export_is_schema_valid_and_deterministic():
    run = create_audit_run(
        "example.com",
        phases=["recon_snapshot"],
        run_id="audit-schema-deterministic",
    )
    run = advance_audit_phase(run, "recon_snapshot", {"assets": ["example.com"]})

    first = audit_run_to_json(run)
    second = audit_run_to_json(run)

    validate_audit_payload(first, "asa_audit_run")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
