"""gui/first_run.py — first-run gate + pure health-report formatting (offline).

The dialog itself (QMessageBox.exec) is not driven here — like the other tab
tests we exercise the testable seams: the pure formatter and the first-run
detection/marking, with SETTINGS_FILE redirected to a tmp path.
"""
import core.config as config
from gui import first_run


_HEALTH_OK = {
    'python_version': '3.11.7',
    'required': [{'name': 'qtpy', 'ok': True}, {'name': 'requests', 'ok': True}],
    'required_ok': True,
    'optional': {'playwright': {'available': True}, 'ffmpeg': {'available': False}},
    'data_root_writable': True,
    'ok': True,
}
_HEALTH_BAD = {**_HEALTH_OK, 'ok': False, 'data_root_writable': False,
               'required': [{'name': 'qtpy', 'ok': False}]}


# ── pure formatter ─────────────────────────────────────────────────────────────

def test_report_text_ok():
    text = first_run.health_report_text(_HEALTH_OK)
    assert '3.11.7' in text
    assert 'ГОТОВ К РАБОТЕ' in text
    assert '1/2 доступно' in text          # playwright present, ffmpeg missing
    assert 'ffmpeg' in text                # listed as missing


def test_report_text_not_ok():
    text = first_run.health_report_text(_HEALTH_BAD)
    assert 'НЕ ХВАТАЕТ' in text
    assert 'Каталог данных доступен на запись: ✗' in text


# ── first-run gate ──────────────────────────────────────────────────────────────

def test_is_first_run_true_when_no_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(config, 'SETTINGS_FILE', tmp_path / 'settings.json')
    assert first_run.is_first_run() is True


def test_is_first_run_false_when_settings_exist(monkeypatch, tmp_path):
    f = tmp_path / 'settings.json'
    f.write_text('{}', encoding='utf-8')
    monkeypatch.setattr(config, 'SETTINGS_FILE', f)
    assert first_run.is_first_run() is False


def test_mark_first_run_done_persists(monkeypatch, tmp_path):
    f = tmp_path / 'settings.json'
    monkeypatch.setattr(config, 'SETTINGS_FILE', f)
    assert first_run.is_first_run() is True
    first_run._mark_first_run_done()
    assert f.exists()
    assert first_run.is_first_run() is False
