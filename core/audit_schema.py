"""JSON schema helpers for client-safe audit exports.

The validator implements the small schema subset used by ASA export contracts
so release tests remain offline and stdlib-only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


SCHEMA_ALIASES = {
    "asa_audit_run": "asa_audit_run.schema.json",
    "asa_finding": "asa_finding.schema.json",
    "asa_validation": "asa_validation.schema.json",
}


def _schema_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "schemas"


def load_schema(schema_name: str) -> Dict[str, Any]:
    raw_name = str(schema_name or "").strip()
    filename = SCHEMA_ALIASES.get(raw_name, raw_name)
    if not filename.endswith(".json"):
        filename = f"{filename}.schema.json"
    path = _schema_dir() / filename
    if not path.is_file():
        raise FileNotFoundError(f"schema not found: {filename}")
    return json.loads(path.read_text(encoding="utf-8"))


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _validate(value: Any, schema: Dict[str, Any], path: str = "$") -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if not any(_type_ok(value, item) for item in expected_type):
            raise ValueError(f"{path} has invalid type")
    elif expected_type and not _type_ok(value, expected_type):
        raise ValueError(f"{path} must be {expected_type}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} has invalid value: {value}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise KeyError(f"{path}.{key} is required")
        properties = schema.get("properties") or {}
        for key, item in value.items():
            if key in properties:
                _validate(item, properties[key], f"{path}.{key}")

    if isinstance(value, list) and "items" in schema:
        for idx, item in enumerate(value):
            _validate(item, schema["items"], f"{path}[{idx}]")


def validate_audit_payload(payload: Dict[str, Any], schema_name: str) -> Dict[str, Any]:
    schema = load_schema(schema_name)
    _validate(payload, schema)
    return payload
