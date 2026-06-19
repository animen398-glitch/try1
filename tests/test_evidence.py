import json

from core.evidence import (
    MANIFEST_NAME,
    attach_finding_refs,
    build_manifest,
    verify_manifest,
    write_manifest,
)


def test_build_manifest_hashes_scan_artifacts_and_excludes_reports(tmp_path):
    scan = tmp_path / "scan"
    (scan / "api").mkdir(parents=True)
    (scan / "api" / "api_keys.json").write_text('{"keys_found":1}',
                                                 encoding="utf-8")
    (scan / "report.json").write_text("{}", encoding="utf-8")

    manifest = build_manifest(scan, {"scan_id": "s1", "url": "https://x.com"})

    assert manifest["version"] == 1
    assert manifest["scan_id"] == "s1"
    assert manifest["artifact_count"] == 1
    artifact = manifest["artifacts"][0]
    assert artifact["phase"] == "api"
    assert artifact["path"] == "api/api_keys.json"
    assert len(artifact["sha256"]) == 64


def test_write_and_verify_manifest_detects_changed_files(tmp_path):
    scan = tmp_path / "scan"
    (scan / "dns").mkdir(parents=True)
    artifact = scan / "dns" / "dns.json"
    artifact.write_text('{"status":"Success"}', encoding="utf-8")

    result = write_manifest(scan, {"scan_id": "s1"})
    assert (scan / MANIFEST_NAME).exists()
    assert result["artifact_count"] == 1
    assert verify_manifest(scan)["ok"] is True

    artifact.write_text('{"status":"Changed"}', encoding="utf-8")
    checked = verify_manifest(scan)
    assert checked["ok"] is False
    assert checked["changed"] == ["dns/dns.json"]


def test_attach_finding_refs_maps_sources_to_existing_artifacts(tmp_path):
    scan = tmp_path / "scan"
    (scan / "api").mkdir(parents=True)
    (scan / "api" / "api_keys.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(scan)
    report = {"phases": {"vulns": {"findings": [
        {"source": "secret", "title": "Leaked secret"},
        {"source": "unknown", "title": "Other"},
    ]}}}

    attached = attach_finding_refs(report, manifest)

    assert attached == 1
    refs = report["phases"]["vulns"]["findings"][0]["evidence_refs"]
    assert refs[0]["path"] == "api/api_keys.json"
    assert "evidence_refs" not in report["phases"]["vulns"]["findings"][1]


def test_manifest_file_is_valid_json(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir()
    result = write_manifest(scan, {"scan_id": "empty"})

    data = json.loads((scan / result["path"]).read_text(encoding="utf-8"))
    assert data["artifact_count"] == 0
