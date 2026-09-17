"""Packaging regression tests for dashboard runtime modules."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_sources_are_present_for_distribution() -> None:
    for module in (
        "build_dnp3_index.py",
        "build_global_index.py",
        "build_modbus_index.py",
        "build_s7_index.py",
    ):
        assert (REPO_ROOT / module).is_file()


def test_report_templates_are_present_for_distribution() -> None:
    templates = REPO_ROOT / "reports" / "templates"
    assert {path.name for path in templates.glob("*.html")} == {
        "dnp3_report.html",
        "modbus_report.html",
        "s7_report.html",
    }
