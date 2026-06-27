"""Release-readiness contracts for CI/smoke tooling.

These tests do not execute CI, PyInstaller, or network steps. They pin the
workflow invariants that protect release builds from drifting away from the
local smoke checks.
"""

from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent


def test_ci_builds_windows_exe_and_smoke_runs_self_check():
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "build-windows:" in workflow
    assert "pyinstaller build.spec --clean --noconfirm" in workflow
    assert "dist/SiteAnalyzer.exe" in workflow
    assert "--self-check" in workflow
    assert "QT_QPA_PLATFORM: offscreen" in workflow


def test_ci_keeps_lint_and_test_jobs():
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "ruff check ." in workflow
    assert "pytest -q" in workflow
    assert 'python-version: ["3.11", "3.12"]' in workflow
