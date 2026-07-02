"""Tests for gui.task_runner.friendly_error_text (WS6, pure/Qt-free)."""

from gui.task_runner import friendly_error_text


def test_frames_reason_and_points_at_crash_report():
    out = friendly_error_text("connection refused")
    assert "connection refused" in out
    assert "отчёт о сбое" in out
    assert "Операция не выполнена" in out


def test_keeps_only_first_line():
    out = friendly_error_text("boom\n  File \"x.py\", line 3\n    raise")
    assert "boom" in out
    assert "x.py" not in out          # no stack-like blob leaks into the dialog


def test_empty_message_has_a_fallback():
    out = friendly_error_text("")
    assert "неизвестная ошибка" in out
    assert friendly_error_text(None).count("\n") >= 1
