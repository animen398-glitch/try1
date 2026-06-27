from core.finding_quality import apply_quality_gate


def _finding(**overrides):
    base = {
        "id": "finding-quality-1",
        "title": "Exposed source map",
        "severity": "critical",
        "asset": "https://example.com",
        "location": "https://example.com/app.js.map",
        "impact": "Source disclosure can expose implementation details.",
        "remediation": "Remove source maps from production.",
        "reachability": "publicly reachable over HTTPS",
        "confidence": 85,
        "validation_status": "verified",
        "evidence_refs": ["evidence/source-map.json"],
    }
    base.update(overrides)
    return base


def test_finding_without_evidence_fails_quality_gate():
    result = apply_quality_gate(_finding(evidence_refs=[]), min_confidence=70)

    assert result["quality_gate"] == "failed"
    assert result.get("client_facing") is False


def test_rejected_finding_cannot_enter_client_facing_critical_report():
    result = apply_quality_gate(
        _finding(validation_status="rejected", confidence=99),
        min_confidence=70,
    )

    assert result["quality_gate"] == "failed"
    assert result.get("client_facing") is False


def test_low_confidence_finding_fails_quality_gate_even_with_evidence():
    result = apply_quality_gate(_finding(confidence=69), min_confidence=70)

    assert result["quality_gate"] == "failed"
    assert result.get("client_facing") is False


def test_complete_verified_finding_passes_quality_gate():
    result = apply_quality_gate(_finding(), min_confidence=70)

    assert result["quality_gate"] == "passed"
    assert result.get("client_facing") is True
