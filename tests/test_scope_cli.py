from scope_cli import cmd_clear, cmd_set, cmd_show, main


def test_cmd_set_and_show_scope(tmp_path):
    cmd_set(
        tmp_path,
        "https://example.com",
        allowed_domains=["example.com"],
        denied_domains=["admin.example.com"],
        active_scan_enabled=True,
        passive_only=False,
        rate_limit="1 rps",
    )

    result = cmd_show(tmp_path, "example.com")

    assert result["scope"]["allowed_domains"] == ["example.com"]
    assert result["scope"]["denied_domains"] == ["admin.example.com"]
    assert result["scope"]["active_scan_enabled"] is True
    assert result["scope"]["passive_only"] is False


def test_cmd_clear_scope(tmp_path):
    cmd_set(tmp_path, "https://example.com", active_scan_enabled=True)

    result = cmd_clear(tmp_path, "example.com")

    assert result["explicit"] is False
    assert result["scope"]["active_scan_enabled"] is True


def test_main_show_unknown_project_returns_1(tmp_path, capsys):
    code = main(["--output", str(tmp_path), "show", "missing.com"])
    err = capsys.readouterr().err

    assert code == 1
    assert "project not found" in err


def test_main_set_prints_human_scope(tmp_path, capsys):
    code = main([
        "--output", str(tmp_path),
        "set", "https://example.com",
        "--allow", "example.com",
        "--deny", "admin.example.com",
        "--active",
        "--no-passive-only",
        "--rate-limit", "1 rps",
    ])
    out = capsys.readouterr().out

    assert code == 0
    assert "Scope for example.com" in out
    assert "active_scan_enabled: True" in out
    assert "passive_only: False" in out


def test_main_json_output(tmp_path, capsys):
    code = main([
        "--output", str(tmp_path),
        "--json",
        "set", "https://example.com",
        "--allow", "example.com",
    ])
    out = capsys.readouterr().out

    assert code == 0
    assert '"slug": "example.com"' in out
    assert '"allowed_domains": [' in out
