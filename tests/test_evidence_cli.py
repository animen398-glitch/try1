from core.evidence import write_manifest
from evidence_cli import cmd_json, cmd_verify, main


def test_cmd_verify_returns_audit_result(tmp_path):
    scan = tmp_path / "scan"
    (scan / "recon").mkdir(parents=True)
    (scan / "recon" / "recon.json").write_text("{}", encoding="utf-8")
    write_manifest(scan, {"scan_id": "s1"})

    result = cmd_verify(scan)

    assert result["ok"] is True
    assert result["checked"] == 1


def test_cmd_json_matches_verify_contract(tmp_path):
    result = cmd_json(tmp_path / "missing")

    assert result["ok"] is False
    assert result["status"] == "missing_scan_dir"


def test_main_verify_exit_codes_and_output(tmp_path, capsys):
    scan = tmp_path / "scan"
    scan.mkdir()

    failed = main(["verify", str(scan)])
    out = capsys.readouterr().out
    assert failed == 1
    assert "Evidence FAILED" in out
    assert "missing_manifest" in out

    (scan / "dns").mkdir()
    (scan / "dns" / "dns.json").write_text("{}", encoding="utf-8")
    write_manifest(scan, {"scan_id": "s1"})
    ok = main(["verify", str(scan)])
    out = capsys.readouterr().out
    assert ok == 0
    assert "Evidence OK" in out


def test_main_json_prints_structured_result(tmp_path, capsys):
    code = main(["json", str(tmp_path / "missing")])
    out = capsys.readouterr().out

    assert code == 1
    assert '"status": "missing_scan_dir"' in out
