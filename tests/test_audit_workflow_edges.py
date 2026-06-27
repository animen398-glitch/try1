import json

import pytest

from core.audit_workflow import advance_audit_phase, audit_run_to_json, create_audit_run


def test_create_audit_run_rejects_unknown_phase():
    with pytest.raises((ValueError, KeyError)):
        create_audit_run(
            "example.com",
            phases=["recon_snapshot", "totally_invalid_phase"],
            run_id="audit-edge-invalid",
        )


def test_advance_audit_phase_rejects_unknown_phase():
    run = create_audit_run("example.com", run_id="audit-edge-advance-invalid")

    with pytest.raises((ValueError, KeyError)):
        advance_audit_phase(run, "totally_invalid_phase", {"ok": True})


def test_duplicate_phase_update_is_deterministic():
    first = create_audit_run(
        "example.com",
        phases=["recon_snapshot", "finding_hunt"],
        run_id="audit-edge-deterministic",
    )
    second = create_audit_run(
        "example.com",
        phases=["recon_snapshot", "finding_hunt"],
        run_id="audit-edge-deterministic",
    )

    result = {
        "summary": {"assets": 2, "findings": 1},
        "finding_ids": ["finding-existing-1"],
    }
    first = advance_audit_phase(first, "recon_snapshot", result)
    first = advance_audit_phase(first, "recon_snapshot", result)
    second = advance_audit_phase(second, "recon_snapshot", result)
    second = advance_audit_phase(second, "recon_snapshot", result)

    assert json.dumps(audit_run_to_json(first), sort_keys=True) == json.dumps(
        audit_run_to_json(second),
        sort_keys=True,
    )


def test_additive_run_can_reference_existing_finding_without_overwriting_identity():
    run = create_audit_run(
        "example.com",
        phases=["validation"],
        run_id="audit-edge-additive",
    )

    run = advance_audit_phase(
        run,
        "validation",
        {
            "validated_findings": [
                {
                    "finding_id": "finding-existing-1",
                    "validation_status": "verified",
                    "confidence": 88,
                }
            ]
        },
    )

    exported = audit_run_to_json(run)
    encoded = json.dumps(exported, sort_keys=True)
    assert "finding-existing-1" in encoded
    assert "audit-edge-additive" in encoded
