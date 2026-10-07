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


_INDEX_NUMERIC_FIELDS = (
    "total_packets",
    "modbus_packets",
    "s7_packets",
    "dnp3_packets",
    "suspect_functions",
    "reachable",
    "unauthenticated_read",
    "broad_register_access",
)


def normalize_index_report(data: Any) -> dict[str, Any]:
    """Validate and normalize the small report surface consumed by index builders."""
    if not isinstance(data, dict):
        raise ValueError("report must be a JSON object")
    if "meta" not in data or "summary" not in data:
        raise ValueError("report must contain meta and summary objects")
    raw_meta = data["meta"]
    raw_summary = data["summary"]
    if not isinstance(raw_meta, dict) or not isinstance(raw_summary, dict):
        raise ValueError("report meta and summary must be JSON objects")
    summary: dict[str, Any] = {}
    for field in _INDEX_NUMERIC_FIELDS:
        value = raw_summary.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"summary.{field} must be a non-negative integer")
        summary[field] = value
    hosts = raw_summary.get("unique_hosts", [])
    if not isinstance(hosts, list) or any(not isinstance(item, str) for item in hosts):
        raise ValueError("summary.unique_hosts must be a list of strings")
    summary["unique_hosts"] = hosts
    pcap_file = raw_meta.get("pcap_file", "")
    if not isinstance(pcap_file, str):
        raise ValueError("meta.pcap_file must be a string")
    meta = {"pcap_file": pcap_file}
    return {"meta": meta, "summary": summary}


def json_for_script(value: Any) -> str:
    """Serialize data for an inline script without allowing HTML/script breakout."""
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
