from core.finding_validation import validate_finding


def _finding(**overrides):
    base = {
        "id": "finding-edge-1",
        "title": "Missing security header",
        "severity": "high",
        "asset": "https://example.com",
        "location": "https://example.com/login",
        "impact": "Session exposure risk.",
        "remediation": "Set the missing security header.",
        "confidence": 80,
        "evidence_refs": ["evidence/http-response-1.json"],
    }
    base.update(overrides)
    return base


def test_validate_finding_rejects_missing_evidence():
    result = validate_finding(_finding(evidence_refs=[]), evidence=None)

    assert result["validation_status"] in {"rejected", "needs_review"}
    assert result["confidence"] < 80


def test_validate_finding_requires_asset_or_location_context():
    result = validate_finding(
        _finding(asset="", location="", evidence_refs=["evidence/http-response-1.json"]),
        evidence={"refs": ["evidence/http-response-1.json"]},
    )

    assert result["validation_status"] in {"rejected", "needs_review"}


def test_validate_finding_keeps_verified_evidence_refs_deterministic():
    finding = _finding(evidence_refs=["z.json", "a.json"])
    evidence = {"refs": ["a.json", "z.json"], "reachable": True}

    first = validate_finding(finding, evidence=evidence)
    second = validate_finding(finding, evidence=evidence)

    assert first == second
    assert first["validation_status"] in {"verified", "needs_review"}
