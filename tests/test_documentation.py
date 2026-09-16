"""Regression tests for documentation promises and navigation."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_tools_status_is_explicit() -> None:
    tools_readme = (REPO_ROOT / "tools" / "README.md").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "No Wireshark profiles" in tools_readme
    assert "tools/README.md" in readme


def test_62443_guide_is_published_and_linked() -> None:
    guide = REPO_ROOT / "docs" / "62443-zones-conduits.md"
    docs_index = (REPO_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    mkdocs = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    compliance = (REPO_ROOT / "docs" / "compliance.md").read_text(encoding="utf-8")

    assert guide.exists()
    contents = guide.read_text(encoding="utf-8")
    for required in ("zone", "conduit", "SL-T", "System Under Consideration", "2-1"):
        assert required.lower() in contents.lower()
    assert "62443-zones-conduits.md" in docs_index
    assert "62443-zones-conduits.md" in mkdocs
    assert "zones/conduits guide" in compliance
