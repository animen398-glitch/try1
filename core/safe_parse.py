"""Parser hardening & input limits (Roadmap E10).

Offline, stdlib-only guards that stand between the app's core parsers and
untrusted or oversized input — a corrupt/tampered ``report.json``, a shared
``.zip`` project bundle, a hostile JSON body. The goal is denial-of-service
resistance, not correctness of well-formed data: enforce explicit, configurable
limits on **byte size**, **JSON nesting depth** (JSON bombs), **element count**
(memory-blow-up arrays/objects) and **decompressed member size** (zip bombs),
then fail fast with a clean, catchable error instead of exhausting memory, the
C stack, or CPU.

Design
------
- Pure and deterministic. No network, no new third-party dependencies.
- Limits are module-level named defaults and every entry point accepts explicit
  overrides, so callers stay in control without a config-schema change.
- :class:`ParseLimitError` subclasses :class:`ValueError`, so the many existing
  ``except Exception`` / ``except ValueError`` degrade-not-raise handlers keep
  working unchanged: a hostile input degrades to the same "skip/None" path a
  malformed file already took.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional, Union


# --- Configurable limits (defaults) ------------------------------------------

#: Largest raw JSON payload we will read/parse, in bytes.
MAX_JSON_BYTES = 64 * 1024 * 1024        # 64 MiB
#: Deepest nesting of objects/arrays permitted (JSON-bomb guard).
MAX_JSON_DEPTH = 200
#: Most total container elements (dict keys + list items) permitted.
MAX_JSON_ITEMS = 10_000_000
#: Largest a single ZIP member may decompress to (zip-bomb guard).
MAX_MEMBER_BYTES = 64 * 1024 * 1024      # 64 MiB


class ParseLimitError(ValueError):
    """Raised when input exceeds a configured size/depth/count limit.

    A subclass of ``ValueError`` on purpose — callers that already treat a bad
    parse as "skip this input" catch it for free.
    """


# Matches a complete JSON string token (with escapes). Used to strip string
# literals cheaply in C before the depth scan, so brackets *inside* strings are
# never miscounted and the Python-level scan runs over far fewer characters.
_STRING_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"', re.DOTALL)


def json_nesting_depth(text: str) -> int:
    """Maximum nesting depth of objects/arrays in ``text`` (0 if none).

    Linear, recursion-free, and string-aware: string literals are removed first
    so a ``{`` or ``[`` inside a JSON string does not inflate the depth.
    """
    structural = _STRING_TOKEN.sub("", text)
    depth = 0
    max_depth = 0
    for ch in structural:
        if ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1
    return max_depth


def count_elements(obj: Any, *, max_items: int = MAX_JSON_ITEMS) -> int:
    """Count total container elements, raising once the budget is exceeded.

    Iterative (explicit stack) so a deep structure cannot blow the Python stack
    while we measure it. Scalars count as zero elements; only dict keys and list
    items are counted.
    """
    total = 0
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            total += len(cur)
            if total > max_items:
                raise ParseLimitError(
                    f"JSON has too many elements (> {max_items})"
                )
            stack.extend(cur.values())
        elif isinstance(cur, list):
            total += len(cur)
            if total > max_items:
                raise ParseLimitError(
                    f"JSON has too many elements (> {max_items})"
                )
            stack.extend(cur)
    return total


def _as_text(
    data: Union[str, bytes, bytearray],
    *,
    max_bytes: int,
    encoding: str = "utf-8",
) -> str:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > max_bytes:
            raise ParseLimitError(f"input is too large (> {max_bytes} bytes)")
        return bytes(data).decode(encoding, errors="strict")
    if isinstance(data, str):
        # Guard on the encoded length so a multibyte string cannot smuggle past
        # a byte budget.
        if len(data.encode(encoding, errors="ignore")) > max_bytes:
            raise ParseLimitError(f"input is too large (> {max_bytes} bytes)")
        return data
    raise TypeError("safe_json_loads expects str or bytes")


def safe_json_loads(
    data: Union[str, bytes, bytearray],
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_items: int = MAX_JSON_ITEMS,
) -> Any:
    """Parse JSON with size, depth and element-count limits enforced.

    Order matters: cheap byte and depth guards run *before* ``json.loads`` so a
    JSON bomb is rejected without ever building the object graph; the element
    count is enforced after parsing (iteratively).
    """
    text = _as_text(data, max_bytes=max_bytes)
    depth = json_nesting_depth(text)
    if depth > max_depth:
        raise ParseLimitError(
            f"JSON is nested too deeply ({depth} > {max_depth})"
        )
    obj = json.loads(text)
    count_elements(obj, max_items=max_items)
    return obj


def safe_read_bytes(
    path: Union[str, Path],
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> bytes:
    """Read a file, rejecting it up front if it is larger than ``max_bytes``.

    The ``stat`` pre-check avoids pulling a huge file into memory just to reject
    it; the post-read guard covers the race where the file grows between stat
    and read.
    """
    p = Path(path)
    size = p.stat().st_size
    if size > max_bytes:
        raise ParseLimitError(f"file is too large ({size} > {max_bytes} bytes)")
    data = p.read_bytes()
    if len(data) > max_bytes:
        raise ParseLimitError(
            f"file is too large ({len(data)} > {max_bytes} bytes)"
        )
    return data


def safe_read_text(
    path: Union[str, Path],
    *,
    max_bytes: int = MAX_JSON_BYTES,
    encoding: str = "utf-8",
) -> str:
    return safe_read_bytes(path, max_bytes=max_bytes).decode(
        encoding, errors="strict"
    )


def safe_read_json(
    path: Union[str, Path],
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_items: int = MAX_JSON_ITEMS,
) -> Any:
    """Read and parse a JSON file under all input limits."""
    data = safe_read_bytes(path, max_bytes=max_bytes)
    return safe_json_loads(
        data, max_bytes=max_bytes, max_depth=max_depth, max_items=max_items
    )


def safe_zip_read(
    zf: "Any",
    name: str,
    *,
    max_bytes: int = MAX_MEMBER_BYTES,
) -> bytes:
    """Read one ZIP member, guarding against a decompression (zip) bomb.

    The member's declared uncompressed size is checked before reading so a tiny,
    highly-compressed member cannot balloon in memory; the length of the actual
    decompressed bytes is re-checked in case the header under-reported.
    """
    info = zf.getinfo(name)
    declared = getattr(info, "file_size", 0) or 0
    if declared > max_bytes:
        raise ParseLimitError(
            f"zip member {name!r} is too large ({declared} > {max_bytes} bytes)"
        )
    data = zf.read(name)
    if len(data) > max_bytes:
        raise ParseLimitError(
            f"zip member {name!r} is too large ({len(data)} > {max_bytes} bytes)"
        )
    return data


def safe_zip_json(
    zf: "Any",
    name: str,
    *,
    max_bytes: int = MAX_MEMBER_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
    max_items: int = MAX_JSON_ITEMS,
) -> Any:
    """Read and parse a JSON member of a ZIP under all input limits."""
    data = safe_zip_read(zf, name, max_bytes=max_bytes)
    return safe_json_loads(
        data, max_bytes=max_bytes, max_depth=max_depth, max_items=max_items
    )


def member_within_limit(
    zf: "Any",
    name: str,
    *,
    max_bytes: int = MAX_MEMBER_BYTES,
) -> Optional[int]:
    """Return a member's declared uncompressed size, or raise if over the limit.

    A cheap header-only check for callers (e.g. archive extractors) that stream
    a member to disk rather than into memory.
    """
    info = zf.getinfo(name)
    declared = getattr(info, "file_size", 0) or 0
    if declared > max_bytes:
        raise ParseLimitError(
            f"zip member {name!r} is too large ({declared} > {max_bytes} bytes)"
        )
    return declared
