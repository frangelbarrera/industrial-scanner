"""Shared security controls for IndustrialScanner.

All active-scan entry points must use :func:`validate_targets` before any
network operation. The functions in this module deliberately fail closed.
"""

from __future__ import annotations

import html
import ipaddress
import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class TargetPolicyError(ValueError):
    """Raised when an active-scan target violates the safety policy."""


@dataclass(frozen=True)
class ScanPolicy:
    """Bounded policy applied before active network access."""

    allow_public: bool = False
    max_targets: int = 256
    max_cidr_hosts: int = 256
    max_inflight: int = 1
    min_timeout: float = 0.2
    max_timeout: float = 10.0
    delay_between_targets: float = 0.0

    def validate(self) -> None:
        if self.max_targets < 1 or self.max_cidr_hosts < 1:
            raise ValueError("target limits must be positive")
        if self.max_inflight != 1:
            raise ValueError("active OT scanning is intentionally single-flight")
        if not self.min_timeout <= self.max_timeout:
            raise ValueError("min_timeout must not exceed max_timeout")
        if self.min_timeout <= 0 or self.delay_between_targets < 0:
            raise ValueError("timeouts and delays must be non-negative")


def html_escape(value: Any) -> str:
    """Strictly escape an untrusted value for HTML text or attributes."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple, set)):
        return ", ".join(html_escape(v) for v in value)
    return html.escape(str(value), quote=True)


def safe_render(
    template_name: str,
    context: dict[str, Any],
    template_dir: str | os.PathLike[str] = "reports/templates",
) -> str:
    """Render a bundled template with autoescape enabled and no extensions."""
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "htm", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(template_name).render(**context)


def parse_network(target: str, *, max_hosts: int = 256) -> ipaddress._BaseNetwork:
    """Parse and size-check a network before it can be expanded."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        raise TargetPolicyError(f"Invalid IP/CIDR: {target!r}: {exc}") from exc
    if network.num_addresses > max_hosts:
        raise TargetPolicyError(
            f"CIDR {target!r} expands to {network.num_addresses} addresses (maximum {max_hosts})"
        )
    return network


def is_safe_target(
    target: str,
    *,
    allow_public: bool = False,
    max_hosts: int = 256,
) -> bool:
    """Return whether a single IP or bounded CIDR is safe to actively probe."""
    network = parse_network(target, max_hosts=max_hosts)
    if allow_public:
        return True
    address = network.network_address
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None and mapped.is_global:
            raise TargetPolicyError(
                f"Refusing to scan public address {target!r}; explicit authorization is required"
            )
        if address.sixtofour is not None and address.sixtofour.is_global:
            raise TargetPolicyError(
                f"Refusing to scan public address {target!r}; explicit authorization is required"
            )
        if address in ipaddress.IPv6Network("64:ff9b::/96"):
            raise TargetPolicyError(
                f"Refusing to scan public address {target!r}; explicit authorization is required"
            )
    if network.is_loopback or network.is_link_local or network.is_private or network.is_reserved:
        return True
    raise TargetPolicyError(
        f"Refusing to scan public address {target!r}; explicit authorization is required"
    )


def validate_targets(targets: Iterable[str], policy: ScanPolicy | None = None) -> list[str]:
    """Validate, normalize, deduplicate and bound targets before network access."""
    policy = policy or ScanPolicy()
    policy.validate()
    validated: list[str] = []
    seen: set[str] = set()
    for raw in targets:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        network = parse_network(value, max_hosts=policy.max_cidr_hosts)
        is_safe_target(value, allow_public=policy.allow_public, max_hosts=policy.max_cidr_hosts)
        hosts = network.hosts() if network.num_addresses > 1 else iter([network.network_address])
        for address in hosts:
            normalized = str(address)
            if normalized not in seen:
                seen.add(normalized)
                validated.append(normalized)
                if len(validated) > policy.max_targets:
                    raise TargetPolicyError(
                        f"target set exceeds maximum of {policy.max_targets} addresses"
                    )
    if not validated:
        raise TargetPolicyError("no valid targets remain after policy validation")
    return validated


def filter_targets(
    targets: Iterable[str], *, allow_public: bool = False, max_hosts: int = 256
) -> list[str]:
    """Compatibility wrapper that keeps only policy-compliant targets."""
    safe: list[str] = []
    for target in targets:
        try:
            safe.extend(
                validate_targets(
                    [target],
                    ScanPolicy(allow_public=allow_public, max_cidr_hosts=max_hosts),
                )
            )
        except TargetPolicyError as exc:
            logging.getLogger("ics_scanner").warning("Skipping unsafe target %s: %s", target, exc)
    return list(dict.fromkeys(safe))


_TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|%2e%2e)", re.IGNORECASE)


def safe_join_path(base: str | os.PathLike[str], *parts: str) -> Path:
    """Join path parts while rejecting traversal and symlink escapes."""
    base_path = Path(base).resolve()
    for part in parts:
        if _TRAVERSAL_RE.search(part):
            raise ValueError(f"Path traversal attempt blocked: {part!r}")
    full = (base_path / Path(*parts)).resolve()
    if base_path not in full.parents and full != base_path:
        raise ValueError(f"Resolved path escapes base: {full}")
    return full


def configure_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Configure a non-propagating logger with a consistent format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False
    return logger


__all__ = [
    "ScanPolicy",
    "TargetPolicyError",
    "configure_logging",
    "filter_targets",
    "html_escape",
    "is_safe_target",
    "parse_network",
    "safe_join_path",
    "safe_render",
    "validate_targets",
]
