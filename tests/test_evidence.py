import json

from core.evidence import (
    MANIFEST_NAME,
    attach_finding_refs,
    audit_scan,
    build_manifest,
    evidence_refs_for_finding,
    integrity_warning,
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


def test_evidence_refs_cover_native_cookie_and_header_findings(tmp_path):
    scan = tmp_path / "scan"
    (scan / "recon").mkdir(parents=True)
    (scan / "security").mkdir()
    (scan / "recon" / "recon.json").write_text("{}", encoding="utf-8")
    (scan / "security" / "cookies.json").write_text("{}", encoding="utf-8")
    (scan / "security" / "vulns.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(scan)

    cookie_refs = evidence_refs_for_finding({
        "title": "Weakly protected cookie: sid",
        "category": "cookie",
    }, manifest)
    header_refs = evidence_refs_for_finding({
        "title": "Weak Content-Security-Policy",
        "source": "vuln",
    }, manifest)

    assert [r["path"] for r in cookie_refs] == [
        "security/cookies.json", "security/vulns.json"]
    assert [r["path"] for r in header_refs] == [
        "recon/recon.json", "security/vulns.json"]


def test_evidence_refs_cover_security_audit_categories(tmp_path):
    scan = tmp_path / "scan"
    (scan / "security").mkdir(parents=True)
    (scan / "security" / "audit.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(scan)

    smap = evidence_refs_for_finding({"category": "sourcemap"}, manifest)
    gql = evidence_refs_for_finding({"category": "graphql"}, manifest)

    assert smap[0]["path"] == "security/audit.json"
    assert gql[0]["path"] == "security/audit.json"


def test_evidence_refs_do_not_invent_missing_artifacts(tmp_path):
    scan = tmp_path / "scan"
    (scan / "security").mkdir(parents=True)
    (scan / "security" / "vulns.json").write_text("{}", encoding="utf-8")
    manifest = build_manifest(scan)

    refs = evidence_refs_for_finding({
        "title": "Weakly protected cookie: sid",
        "category": "cookie",
    }, manifest)

    assert [r["path"] for r in refs] == ["security/vulns.json"]


def test_manifest_file_is_valid_json(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir()
    result = write_manifest(scan, {"scan_id": "empty"})

    data = json.loads((scan / result["path"]).read_text(encoding="utf-8"))
    assert data["artifact_count"] == 0


def test_audit_scan_reports_ok_missing_changed_and_corrupt(tmp_path):
    missing_dir = audit_scan(tmp_path / "nope")
    assert missing_dir["ok"] is False
    assert missing_dir["status"] == "missing_scan_dir"

    scan = tmp_path / "scan"
    scan.mkdir()
    missing_manifest = audit_scan(scan)
    assert missing_manifest["status"] == "missing_manifest"

    (scan / MANIFEST_NAME).write_text("{ broken", encoding="utf-8")
    corrupt = audit_scan(scan)
    assert corrupt["status"] == "corrupt_manifest"

    (scan / "api").mkdir()
    artifact = scan / "api" / "api_keys.json"
    artifact.write_text("{}", encoding="utf-8")
    write_manifest(scan, {"scan_id": "s1", "url": "https://x.com"})
    ok = audit_scan(scan)
    assert ok["ok"] is True
    assert ok["status"] == "ok"
    assert ok["scan_id"] == "s1"

    artifact.write_text('{"changed":true}', encoding="utf-8")
    changed = audit_scan(scan)
    assert changed["ok"] is False
    assert changed["status"] == "failed"
    assert changed["changed"] == ["api/api_keys.json"]


def test_integrity_warning_summarizes_without_artifact_contents():
    assert integrity_warning({"ok": True}) is None

    warning = integrity_warning({
        "ok": False,
        "status": "failed",
        "missing": ["api/api_keys.json"],
        "changed": ["recon/recon.json"],
    }, "scan s1")

    assert "scan s1" in warning
    assert "failed" in warning
    assert "missing=1" in warning
    assert "changed=1" in warning
