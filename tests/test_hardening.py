"""Regression tests for the safety hardening layer."""

from __future__ import annotations

import pytest

from ics_scanner.security import ScanPolicy, TargetPolicyError, validate_targets
from modbus_scanner.utils import expand_targets


def test_huge_cidr_is_rejected_before_expansion() -> None:
    with pytest.raises(TargetPolicyError):
        expand_targets("10.0.0.0/8")


def test_public_target_is_rejected_by_central_policy() -> None:
    with pytest.raises(TargetPolicyError):
        validate_targets(["8.8.8.8"])


def test_public_target_requires_explicit_policy() -> None:
    assert validate_targets(["8.8.8.8"], ScanPolicy(allow_public=True)) == ["8.8.8.8"]


def test_target_count_is_bounded_after_deduplication() -> None:
    with pytest.raises(TargetPolicyError):
        validate_targets([f"192.0.2.{index}" for index in range(1, 4)], ScanPolicy(max_targets=2))


def test_comments_are_ignored_in_target_file(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("# documentation\n127.0.0.1\n", encoding="utf-8")
    assert expand_targets(f"@{target_file}") == ["127.0.0.1"]


def test_pcap_limits_are_rejected_when_invalid() -> None:
    from dnp3_monitor.dnp3_analyze import analyze_pcap
    from s7_comm_analyzer.s7_analyze import analyze_pcap as analyze_s7

    with pytest.raises(ValueError):
        analyze_pcap("missing.pcap", max_packets=0)
    with pytest.raises(ValueError):
        analyze_s7("missing.pcap", max_results=0)
