"""Tests for the service layer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from ics_scanner.security import TargetPolicyError
from ics_scanner.services import (
    analyze_pcap_service,
    build_dashboard_service,
    scan_modbus_service,
)
from s7_comm_analyzer.parsers import (
    FUNC_READ_VAR,
    ROSCTR_JOB,
    S7_PROTOCOL_ID,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _build_s7_packet(src="10.0.0.1", dst="10.0.0.2", func=FUNC_READ_VAR):
    payload = (
        bytes([S7_PROTOCOL_ID, ROSCTR_JOB])
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x02"
        + b"\x00\x00"
        + bytes([func, 0x00])
    )
    return Ether() / IP(src=src, dst=dst) / TCP(dport=102) / Raw(load=payload)


class TestScanModbusService:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_scan_private_ip(self, mock_client_class, tmp_path):
        from tests.test_modbus_scan import _make_mock_client

        mock_client = _make_mock_client(reachable=True, with_data=True)
        mock_client_class.return_value = mock_client

        json_out = tmp_path / "out.json"
        result = scan_modbus_service(
            targets_arg="127.0.0.1",
            port=502,
            unit_id=1,
            timeout=1.0,
            json_out=str(json_out),
        )
        assert result["summary"]["reachable"] == 1
        assert json_out.exists()
        assert result["meta"]["mitre_enriched"] is True

    def test_scan_public_ip_refused(self):
        """scan_modbus_service must refuse public IPs without allow_public."""
        with pytest.raises(TargetPolicyError):
            scan_modbus_service(targets_arg="8.8.8.8")

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_scan_public_ip_allowed(self, mock_client_class):
        from tests.test_modbus_scan import _make_mock_client

        mock_client = _make_mock_client(reachable=True, with_data=True)
        mock_client_class.return_value = mock_client
        # Should not raise
        result = scan_modbus_service(targets_arg="8.8.8.8", allow_public=True, timeout=1.0)
        assert result["summary"]["reachable"] == 1


class TestAnalyzePcapService:
    def test_analyze_s7comm(self, tmp_path):
        """analyze_pcap_service should run S7 analysis with MITRE enrichment."""
        pcap_path = tmp_path / "test.pcapng"
        pkts = [_build_s7_packet(func=FUNC_READ_VAR)]
        wrpcap(str(pcap_path), pkts)

        json_out = tmp_path / "out.json"
        result = analyze_pcap_service(str(pcap_path), "s7comm", json_out=str(json_out))
        assert result["summary"]["s7_packets"] == 1
        assert result["meta"]["mitre_enriched"] is True
        # Each result item should have a mitre_attack field
        for item in result["results"]:
            assert "mitre_attack" in item
        assert json_out.exists()

    def test_analyze_dnp3(self, tmp_path):
        """analyze_pcap_service should run DNP3 analysis with MITRE enrichment."""
        # Build a synthetic DNP3 PCAP
        from scapy.all import wrpcap

        from dnp3_monitor.parsers import APP_FUNC_READ
        from tests.test_dnp3_parsers import _build_dnp3_frame, _dnp3pkt

        frame = _build_dnp3_frame(app_func=APP_FUNC_READ)
        pkt = _dnp3pkt(frame)
        pcap_path = tmp_path / "test.pcap"
        wrpcap(str(pcap_path), [pkt])

        result = analyze_pcap_service(str(pcap_path), "dnp3")
        assert result["summary"]["dnp3_packets"] == 1
        assert result["meta"]["mitre_enriched"] is True

    def test_unsupported_protocol(self, tmp_path):
        with pytest.raises(ValueError):
            analyze_pcap_service("dummy.pcap", "profinet")


class TestBuildDashboardService:
    def test_build_modbus_dashboard(self, tmp_path):
        """build_dashboard_service should build a modbus index.html."""
        # Create an empty reports dir
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        out = build_dashboard_service("modbus", str(reports_dir))
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "Modbus Global Report Index" in content

    def test_build_s7comm_dashboard(self, tmp_path):
        """build_dashboard_service should build an s7comm index.html."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        out = build_dashboard_service("s7comm", str(reports_dir))
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "S7Comm Global Report Index" in content

    def test_build_dnp3_dashboard(self, tmp_path):
        """build_dashboard_service should build a dnp3 index.html."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        out = build_dashboard_service("dnp3", str(reports_dir))
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "DNP3 Global Report Index" in content

    def test_build_global_dashboard(self, tmp_path):
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        out = build_dashboard_service("global", str(reports_dir))
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "Global Executive Dashboard" in content

    def test_dashboard_with_existing_reports(self, tmp_path):
        """Dashboard service should pick up existing JSON reports in batch dirs."""
        reports_dir = tmp_path / "reports"
        modbus_batch = reports_dir / "modbus_batch"
        modbus_batch.mkdir(parents=True)
        # Write a fake JSON report
        (modbus_batch / "test.json").write_text(
            json.dumps(
                {
                    "meta": {"generated_at": "2025-01-01T00:00:00Z"},
                    "summary": {"total_packets": 10, "suspect_functions": 0},
                }
            ),
            encoding="utf-8",
        )
        out = build_dashboard_service("modbus", str(reports_dir))
        content = Path(out).read_text()
        # The dashboard should show the report in the table
        assert "test.json" in content or "test.html" in content

    def test_unsupported_protocol(self):
        with pytest.raises(ValueError):
            build_dashboard_service("profinet")


class TestPhaseOneContracts:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_service_applies_environment_allowlist(self, mock_client_class, monkeypatch):
        from tests.test_modbus_scan import _make_mock_client

        monkeypatch.setenv("INDUSTRIALSCANNER_ALLOWED_TARGETS", "127.0.0.0/8")
        mock_client_class.return_value = _make_mock_client(reachable=True, with_data=False)
        with pytest.raises(TargetPolicyError, match="outside the configured"):
            scan_modbus_service(targets_arg="192.168.1.10", timeout=1.0)
        mock_client_class.assert_not_called()

    def test_global_dashboard_preserves_s7_directory_and_metrics(self, tmp_path):
        reports = tmp_path / "reports"
        report = reports / "s7_batch" / "sample.json"
        report.parent.mkdir(parents=True)
        report.write_text(
            json.dumps(
                {
                    "meta": {"pcap_file": "sample.pcap"},
                    "summary": {"total_packets": 7, "s7_packets": 5, "suspect_functions": 2},
                }
            )
        )
        out = build_dashboard_service("global", str(reports))
        content = Path(out).read_text()
        assert "s7_index.html" in content
        assert "<td>7</td>" in content
        assert ">2</span>" in content


class TestPhaseOneDirectEntryPoints:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_probe_host_applies_environment_allowlist(self, mock_client_class, monkeypatch):
        monkeypatch.setenv("INDUSTRIALSCANNER_ALLOWED_TARGETS", "127.0.0.0/8")
        from modbus_scanner.modbus_scan import probe_host

        with pytest.raises(TargetPolicyError, match="outside the configured"):
            probe_host("192.168.1.10", 502, 1, 1.0)
        mock_client_class.assert_not_called()

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_probe_host_rejects_non_ip_target(self, mock_client_class):
        from modbus_scanner.modbus_scan import probe_host

        with pytest.raises(TargetPolicyError, match="Invalid IP/CIDR"):
            probe_host("example.com", 502, 1, timeout=1.0)
        mock_client_class.assert_not_called()
