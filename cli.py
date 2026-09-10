"""Backward-compatible CLI that delegates to the unified Click application."""

from __future__ import annotations

from ics_scanner.cli import cli


def build_parser():
    """Return the canonical CLI command; retained for import compatibility."""
    return cli


def dispatch(args) -> None:
    """Reject direct legacy dispatch and require the canonical CLI."""
    raise RuntimeError("The legacy dispatcher is retired; invoke ics_scanner.cli:main")


if __name__ == "__main__":
    cli()
