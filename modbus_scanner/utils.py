"""Utilities for IndustrialScanner Modbus scanner."""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime
from pathlib import Path

from ics_scanner.security import TargetPolicyError, parse_network

__all__ = ["expand_targets", "html_template_path", "safe_str", "setup_logger", "utc_ts"]


def setup_logger(name: str) -> logging.Logger:
    """Configure a lightweight console logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
        ch.setFormatter(fmt)
        logger.addHandler(ch)
    return logger


def utc_ts() -> str:
    """Return ISO-like timestamp in UTC."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_str(e: Exception) -> str:
    """Safely stringify exceptions for logging."""
    try:
        return str(e)
    except Exception:
        return e.__class__.__name__


def expand_targets(arg: str, *, max_hosts: int = 256) -> list[str]:
    """Expand targets from multiple input formats:
    - "192.168.0.10,192.168.0.11"
    - "192.168.0.0/24" (CIDR)
    - "@targets.txt" (file with one IP per line)
    """
    if max_hosts < 1:
        raise ValueError("max_hosts must be positive")
    arg = arg.strip()
    out: list[str] = []

    if arg.startswith("@"):
        # File mode
        path = Path(arg[1:])
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
                if len(out) > max_hosts:
                    raise TargetPolicyError(f"target file exceeds maximum of {max_hosts} entries")
        return out

    if "," in arg:
        # Comma-separated IPs
        for token in arg.split(","):
            token = token.strip()
            if token:
                out.append(token)
                if len(out) > max_hosts:
                    raise TargetPolicyError(f"target list exceeds maximum of {max_hosts} entries")
        return out

    # CIDR or single IP
    try:
        net = parse_network(arg, max_hosts=max_hosts)
        hosts = list(net.hosts())
        return [str(ip) for ip in hosts] or [str(net.network_address)]
    except TargetPolicyError:
        # Preserve hostname compatibility; the central policy rejects it
        # before any network operation.
        if "/" in arg:
            raise
        try:
            ipaddress.ip_address(arg)
        except ValueError:
            return [arg]
        raise


def html_template_path(name: str) -> Path:
    """Resolve bundled HTML template path."""
    base = Path(__file__).resolve().parents[1] / "reports" / "templates"
    return base / name
