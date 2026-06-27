"""Atomic file writes.

Write to a uniquely-named temp file in the *same directory* as the target, then
``os.replace`` it onto the target. ``os.replace`` is an atomic rename on the same
filesystem (POSIX and Windows), so a crash or a concurrent reader never sees a
partially-written (corrupt) file — the target is either the old content or the
new content, never a truncated mix.

This guards the project's small JSON state files (metadata.json, history
snapshots) the way WAL/quarantine guard the SQLite stores. Atomicity of
*visibility* is the goal, not power-loss durability (no fsync), matching the
stores' ``synchronous=NORMAL`` trade-off.
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Union

_PathLike = Union[str, Path]


def atomic_write_text(path: _PathLike, text: str, encoding: str = 'utf-8') -> None:
    """Atomically write ``text`` to ``path`` (temp-in-same-dir + os.replace).

    Creates the parent directory if needed. On any failure the partial temp file
    is removed and the original ``path`` (if any) is left untouched."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent),
                               prefix=f'.{path.name}.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding=encoding) as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: _PathLike, obj: Any, *, indent: int = 2) -> None:
    """Atomically write ``obj`` as JSON (UTF-8, ``default=str`` for stragglers)."""
    atomic_write_text(path, json.dumps(obj, indent=indent, ensure_ascii=False,
                                       default=str))
