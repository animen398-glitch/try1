"""Offline tests for parser hardening & input limits (Roadmap E10)."""

import io
import json
import zipfile

import pytest

from core.safe_parse import (
    MAX_JSON_BYTES,
    ParseLimitError,
    count_elements,
    json_nesting_depth,
    member_within_limit,
    safe_json_loads,
    safe_read_bytes,
    safe_read_json,
    safe_zip_json,
    safe_zip_read,
)


# --- depth scanning ----------------------------------------------------------

def test_nesting_depth_of_flat_and_nested():
    assert json_nesting_depth("{}") == 1
    assert json_nesting_depth("[1, 2, 3]") == 1
    assert json_nesting_depth('{"a": {"b": {"c": 1}}}') == 3
    assert json_nesting_depth("[[[[]]]]") == 4
    assert json_nesting_depth("42") == 0


def test_brackets_inside_strings_do_not_count():
    # The braces/brackets live inside a string literal and must be ignored.
    assert json_nesting_depth('{"k": "[[[[[not real]]]]]"}') == 1
    assert json_nesting_depth('{"k": "a \\" [ { nested-looking"}') == 1


def test_json_bomb_is_rejected_before_parse():
    bomb = "[" * 5000 + "]" * 5000
    with pytest.raises(ParseLimitError):
        safe_json_loads(bomb, max_depth=200)


def test_depth_within_limit_parses():
    payload = json.dumps({"a": {"b": {"c": [1, 2, 3]}}})
    assert safe_json_loads(payload, max_depth=10) == {"a": {"b": {"c": [1, 2, 3]}}}


# --- element counting --------------------------------------------------------

def test_count_elements_totals_keys_and_items():
    assert count_elements({"a": 1, "b": [1, 2, 3]}) == 5  # 2 keys + 3 items
    assert count_elements([]) == 0
    assert count_elements(7) == 0


def test_count_elements_is_iterative_on_deep_input():
    # A structure deeper than the interpreter recursion limit must not raise
    # RecursionError while being measured.
    obj = cur = {}
    for _ in range(3000):
        cur["n"] = {}
        cur = cur["n"]
    assert count_elements(obj) == 3000


def test_too_many_elements_rejected():
    with pytest.raises(ParseLimitError):
        safe_json_loads(json.dumps(list(range(100))), max_items=10)


# --- size limits -------------------------------------------------------------

def test_oversized_bytes_rejected():
    with pytest.raises(ParseLimitError):
        safe_json_loads(b"[]" + b" " * 100, max_bytes=10)


def test_oversized_str_rejected_on_encoded_length():
    with pytest.raises(ParseLimitError):
        safe_json_loads("ÿ" * 100, max_bytes=50)  # 2 bytes/char in utf-8


def test_bad_type_rejected():
    with pytest.raises(TypeError):
        safe_json_loads(12345)


def test_normal_payload_roundtrips():
    data = {"findings": [{"id": 1}], "n": 2}
    assert safe_json_loads(json.dumps(data)) == data
    assert MAX_JSON_BYTES > 0


# --- file readers ------------------------------------------------------------

def test_safe_read_json_reads_valid_file(tmp_path):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"ok": True}), encoding="utf-8")
    assert safe_read_json(p) == {"ok": True}


def test_safe_read_bytes_rejects_huge_file(tmp_path):
    p = tmp_path / "big.json"
    p.write_bytes(b"x" * 5000)
    with pytest.raises(ParseLimitError):
        safe_read_bytes(p, max_bytes=1000)


def test_safe_read_json_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        safe_read_json(tmp_path / "nope.json")


# --- zip readers (decompression-bomb guard) ----------------------------------

def _zip_with(members: dict) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_safe_zip_json_reads_small_member():
    zf = _zip_with({"data.json": json.dumps({"a": 1})})
    assert safe_zip_json(zf, "data.json") == {"a": 1}


def test_safe_zip_read_rejects_bomb_on_declared_size():
    # 5 MiB of highly-compressible zeros: tiny on disk, big when decompressed.
    zf = _zip_with({"bomb.bin": b"\x00" * (5 * 1024 * 1024)})
    with pytest.raises(ParseLimitError):
        safe_zip_read(zf, "bomb.bin", max_bytes=1024 * 1024)


def test_member_within_limit_returns_declared_size():
    zf = _zip_with({"a.txt": b"hello"})
    assert member_within_limit(zf, "a.txt") == 5
    with pytest.raises(ParseLimitError):
        member_within_limit(zf, "a.txt", max_bytes=2)
