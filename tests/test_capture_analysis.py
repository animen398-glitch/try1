"""Capture tab leak analysis uses the shared SecretScanner (single source).

Regression: the tab used to carry its own _KEY_RE regex set that diverged from
core.secret_scanner — e.g. it never matched JWTs, Stripe keys or PEM blocks.
"""


def test_capture_analysis_detects_jwt_via_shared_scanner(qapp, tmp_path):
    from gui.main_window import MainWindow
    w = MainWindow()

    f = tmp_path / "page.html"
    # A JWT: detected by the shared SecretScanner, missed by the old local regex.
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    f.write_text(f"<script>const t='{jwt}'</script>", encoding="utf-8")

    stats = w._analyse_capture_files([str(f)])
    assert stats["key_leaks"] >= 1


def test_capture_analysis_counts_comments_and_hidden_paths(qapp, tmp_path):
    from gui.main_window import MainWindow
    w = MainWindow()

    f = tmp_path / "page.html"
    f.write_text(
        "<!-- developer note here -->"
        '<a href="/admin/login">x</a>',
        encoding="utf-8",
    )
    stats = w._analyse_capture_files([str(f)])
    assert stats["comments"] >= 1
    assert stats["hidden_paths"] >= 1


def test_capture_analysis_dedups_repeated_key(qapp, tmp_path):
    from gui.main_window import MainWindow
    w = MainWindow()

    key = "AKIAIOSFODNN7EXAMPLE"
    f = tmp_path / "page.html"
    f.write_text(f"{key} ... {key}", encoding="utf-8")
    stats = w._analyse_capture_files([str(f)])
    assert stats["key_leaks"] == 1
