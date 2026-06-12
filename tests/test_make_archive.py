"""_make_archive honours the auto_compress setting.

Regression: results were archived unconditionally; the 'auto_compress' setting
(default off) was ignored. Tested via a bare host object carrying .settings,
so no QApplication is needed.
"""

from pathlib import Path

from gui.window_helpers import WindowHelpersMixin


class _Host(WindowHelpersMixin):
    def __init__(self, settings):
        self.settings = settings


def test_archive_skipped_when_auto_compress_off(tmp_path):
    (tmp_path / "f.txt").write_text("data", encoding="utf-8")
    host = _Host({"auto_compress": False, "compression_format": "zip"})
    assert host._make_archive(tmp_path, "example", "capture") is None


def test_archive_created_when_auto_compress_on(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("data", encoding="utf-8")
    host = _Host({"auto_compress": True, "compression_format": "zip"})

    out = host._make_archive(src, "example", "capture")
    assert out is not None
    assert out.endswith(".zip")
    assert Path(out).exists()


def test_archive_skipped_for_empty_dir_even_when_enabled(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    host = _Host({"auto_compress": True, "compression_format": "zip"})
    assert host._make_archive(empty, "example", "capture") is None
