"""T12: atomic JSON/text writes — a crash mid-write never corrupts the target and
leaves no temp litter. Offline, no network."""
import json
import os

import pytest

from utils.atomic_io import atomic_write_json, atomic_write_text


def test_write_text_creates_parent_and_file(tmp_path):
    p = tmp_path / 'sub' / 'f.txt'  # parent dir auto-created
    atomic_write_text(p, 'hello')
    assert p.read_text(encoding='utf-8') == 'hello'


def test_write_json_roundtrip(tmp_path):
    p = tmp_path / 'd.json'
    atomic_write_json(p, {'a': 1, 'b': [1, 2]})
    assert json.loads(p.read_text(encoding='utf-8')) == {'a': 1, 'b': [1, 2]}


def test_no_temp_files_left_behind(tmp_path):
    atomic_write_json(tmp_path / 'f.json', {'x': 1})
    assert [q.name for q in tmp_path.iterdir()] == ['f.json']


def test_overwrites_existing(tmp_path):
    p = tmp_path / 'f.txt'
    atomic_write_text(p, 'one')
    atomic_write_text(p, 'two')
    assert p.read_text(encoding='utf-8') == 'two'


def test_failure_leaves_original_intact(tmp_path, monkeypatch):
    p = tmp_path / 'f.txt'
    atomic_write_text(p, 'old')

    def boom(src, dst):
        raise OSError('replace failed')

    monkeypatch.setattr(os, 'replace', boom)
    with pytest.raises(OSError):
        atomic_write_text(p, 'new')

    assert p.read_text(encoding='utf-8') == 'old'  # original untouched on failure
    # the partial temp file was cleaned up
    assert [q.name for q in tmp_path.iterdir() if q.name != 'f.txt'] == []
