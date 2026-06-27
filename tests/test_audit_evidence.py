from core.audit_evidence import verify_evidence_refs


def test_verify_finding_inline_evidence_ref():
    out = verify_evidence_refs(
        ["finding:f1:evidence"],
        findings=[{
            "finding_id": "f1",
            "evidence": {"location": "https://shop.com", "impact": "x"},
        }],
    )

    assert out["ok"] is True
    assert out["verified"] == ["finding:f1:evidence"]
    assert out["missing"] == []


def test_verify_safe_check_inline_ref():
    out = verify_evidence_refs(
        ["headers:https://shop.com"],
        safe_checks=[{
            "action": "headers_check",
            "findings": [{
                "evidence": {
                    "evidence_refs": ["headers:https://shop.com"],
                }
            }],
        }],
    )

    assert out["ok"] is True
    assert out["results"][0]["reason"] == "inline safe-check evidence ref matched"


def test_verify_artifact_path_must_stay_inside_root(tmp_path):
    good = tmp_path / "capture" / "headers.json"
    good.parent.mkdir()
    good.write_text("{}", encoding="utf-8")

    out = verify_evidence_refs(
        ["capture/headers.json", "../outside.txt"],
        artifacts_root=tmp_path,
    )

    by_ref = {item["ref"]: item for item in out["results"]}
    assert by_ref["capture/headers.json"]["status"] == "verified"
    assert by_ref["../outside.txt"]["status"] == "missing"
    assert out["ok"] is False
