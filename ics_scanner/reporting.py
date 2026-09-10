"""Common report contracts and atomic output helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


def report_metadata(**values: Any) -> dict[str, Any]:
    """Return metadata fields shared by all report formats."""
    return {"schema_version": SCHEMA_VERSION, **values}


def atomic_write_text(path: Path, content: str) -> Path:
    """Write a report atomically and restrict the final file to owner access."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


def atomic_write_json(path: Path, data: dict[str, Any]) -> Path:
    """Serialize JSON deterministically and write it atomically."""
    return atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
