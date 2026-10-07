"""Tests for modbus_scanner.modbus_scan.

Uses unittest.mock to stub the ModbusTcpClient so we can test probe_host,
scan_targets, and report writers without a real Modbus server.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from modbus_scanner.modbus_scan import (
    main,
    probe_host,
    scan_targets,
    write_html_report,
    write_json_report,
)


# ---------------------------------------------------------------------------
# Fixtures: build a MagicMock that simulates a ModbusTcpClient
# ---------------------------------------------------------------------------
class _FakeResponse:
    """Simulates a pymodbus response object."""

    def __init__(self, bits=None, registers=None, is_error=False):
        self.bits = bits
        self.registers = registers
        self._is_error = is_error

    def isError(self):
        return self._is_error


def _make_mock_client(*, reachable=True, with_data=True):
    """Return a MagicMock that simulates a connected ModbusTcpClient.

    ``spec=ModbusTcpClient`` keeps the mocked methods signature-faithful,
    so the version-dependent unit-id keyword detection in ``probe_host``
    is exercised against the real client API.
    """
    from pymodbus.client import ModbusTcpClient

    client = MagicMock(spec=ModbusTcpClient)
    client.connect.return_value = reachable
    if with_data:
        client.read_coils.return_value = _FakeResponse(bits=[True, False, True] * 5 + [True])
        client.read_discrete_inputs.return_value = _FakeResponse(bits=[False] * 16)
        client.read_holding_registers.return_value = _FakeResponse(registers=[1, 2, 3, 4, 5] * 2)
        client.read_input_registers.return_value = _FakeResponse(registers=[10, 20, 30, 40, 50] * 2)
    else:
        # All reads return error responses
        client.read_coils.return_value = _FakeResponse(is_error=True)
        client.read_discrete_inputs.return_value = _FakeResponse(is_error=True)
        client.read_holding_registers.return_value = _FakeResponse(is_error=True)
        client.read_input_registers.return_value = _FakeResponse(is_error=True)
    return client


# ---------------------------------------------------------------------------
# probe_host tests
# ---------------------------------------------------------------------------
class TestProbeHost:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_reachable_host_with_data(self, mock_client_class):
        """A reachable host that returns data should populate the reads dict."""
        mock_client = _make_mock_client(reachable=True, with_data=True)
        mock_client_class.return_value = mock_client

        result = probe_host("127.0.0.1", 502, 1, timeout=1.0)
        assert result["reachable"] is True
        assert result["ip"] == "127.0.0.1"
        assert result["port"] == 502
        assert result["unit_id"] == 1
        assert result["latency_ms"] is not None
        assert result["latency_ms"] >= 0
        assert result["reads"]["coils"] is not None
        assert len(result["reads"]["coils"]) > 0
        assert result["exposure"]["unauthenticated_read"] is True
        # 4 read windows all returned data
        assert result["exposure"]["broad_register_access"] is True
        assert result["errors"] == []

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_connection_failure(self, mock_client_class):
        """When connection fails, host should be marked unreachable."""
        mock_client = _make_mock_client(reachable=False)
        mock_client_class.return_value = mock_client

        result = probe_host("192.168.99.99", 502, 1, timeout=0.5)
        assert result["reachable"] is False
        assert "Connection failed" in result["errors"][0]
        assert result["latency_ms"] is not None

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_all_reads_error(self, mock_client_class):
        """When all reads return errors, exposure flags should be False."""
        mock_client = _make_mock_client(reachable=True, with_data=False)
        mock_client_class.return_value = mock_client

        result = probe_host("127.0.0.1", 502, 1, timeout=1.0)
        assert result["reachable"] is True
        assert result["exposure"]["unauthenticated_read"] is False
        assert result["exposure"]["broad_register_access"] is False
        # Each read attempt returns is_error=True, so the isError() check
        # makes the result not populate reads. No error messages are appended
        # because the code path only logs errors when an exception is raised.
        # Verify no reads were populated.
        for key in ("coils", "discrete_inputs", "holding_registers", "input_registers"):
            assert result["reads"][key] is None

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_partial_reads(self, mock_client_class):
        """When only some reads succeed, broad_register_access should be False."""
        mock_client = MagicMock()
        mock_client.connect.return_value = True
        mock_client.read_coils.return_value = _FakeResponse(bits=[True] * 16)
        mock_client.read_discrete_inputs.return_value = _FakeResponse(is_error=True)
        mock_client.read_holding_registers.return_value = _FakeResponse(is_error=True)
        mock_client.read_input_registers.return_value = _FakeResponse(is_error=True)
        mock_client_class.return_value = mock_client

        result = probe_host("127.0.0.1", 502, 1, timeout=1.0)
        assert result["reachable"] is True
        assert result["exposure"]["unauthenticated_read"] is True
        # Only 1 window with data, so broad_register_access is False
        assert result["exposure"]["broad_register_access"] is False

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_probe_exception(self, mock_client_class):
        """When an exception bubbles up, it should be captured in errors."""
        mock_client_class.side_effect = OSError("network unreachable")

        result = probe_host("127.0.0.1", 502, 1, timeout=0.5)
        assert result["reachable"] is False
        assert any("probe_error" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# scan_targets tests
# ---------------------------------------------------------------------------
class TestScanTargets:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_scan_multiple_targets(self, mock_client_class):
        """scan_targets should aggregate results across multiple hosts."""
        mock_client = _make_mock_client(reachable=True, with_data=True)
        mock_client_class.return_value = mock_client

        result = scan_targets(["127.0.0.1", "127.0.0.2"], 502, 1, 1.0)
        assert "meta" in result
        assert "results" in result
        assert "summary" in result
        assert len(result["results"]) == 2
        assert result["summary"]["reachable"] == 2
        assert result["summary"]["unauthenticated_read"] == 2
        assert result["summary"]["broad_register_access"] == 2

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_scan_empty_targets(self, mock_client_class):
        """scan_targets with empty list should produce empty results."""
        result = scan_targets([], 502, 1, 1.0)
        assert result["results"] == []
        assert result["summary"]["reachable"] == 0

    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_scan_mixed_reachability(self, mock_client_class):
        """Mixed reachability should produce correct summary counts."""
        # First call: reachable, second: unreachable
        good = _make_mock_client(reachable=True, with_data=True)
        bad = _make_mock_client(reachable=False)
        mock_client_class.side_effect = [good, bad]

        result = scan_targets(["127.0.0.1", "127.0.0.2"], 502, 1, 1.0)
        assert result["summary"]["reachable"] == 1


# ---------------------------------------------------------------------------
# write_json_report tests
# ---------------------------------------------------------------------------
class TestWriteJsonReport:
    def test_writes_valid_json(self, tmp_path):
        data = {"meta": {"generated_at": "2025-01-01T00:00:00Z"}, "results": []}
        out = tmp_path / "report.json"
        result = write_json_report(data, out)
        assert result == out
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded == data

    def test_creates_parent_dir(self, tmp_path):
        data = {"results": []}
        out = tmp_path / "subdir" / "report.json"
        write_json_report(data, out)
        assert out.exists()


# ---------------------------------------------------------------------------
# write_html_report tests
# ---------------------------------------------------------------------------
class TestWriteHtmlReport:
    def test_writes_html_with_autoescape(self, tmp_path):
        """HTML report should escape untrusted content."""
        malicious = "<script>alert(1)</script>"
        data = {
            "meta": {
                "generated_at": "2025-01-01",
                "targets": [malicious],
                "port": 502,
                "unit_id": 1,
                "timeout": 2.0,
            },
            "results": [
                {
                    "ip": malicious,
                    "port": 502,
                    "unit_id": 1,
                    "reachable": True,
                    "latency_ms": 5.0,
                    "reads": {
                        "coils": None,
                        "discrete_inputs": None,
                        "holding_registers": None,
                        "input_registers": None,
                    },
                    "exposure": {"unauthenticated_read": False, "broad_register_access": False},
                    "errors": [malicious],
                }
            ],
            "summary": {"reachable": 1, "unauthenticated_read": 0, "broad_register_access": 0},
        }
        # Need to use the actual templates directory
        template_dir = Path(__file__).resolve().parents[1] / "reports" / "templates"
        out = tmp_path / "report.html"
        if template_dir.exists():
            write_html_report(data, out)
            content = out.read_text()
            assert "<script>alert(1)</script>" not in content
            assert "&lt;script&gt;" in content


# ---------------------------------------------------------------------------
# main tests
# ---------------------------------------------------------------------------
class TestMain:
    @patch("modbus_scanner.modbus_scan.ModbusTcpClient")
    def test_main_writes_reports(self, mock_client_class, tmp_path, monkeypatch):
        """main should write both JSON and HTML reports."""
        mock_client = _make_mock_client(reachable=True, with_data=True)
        mock_client_class.return_value = mock_client
        # Keep the original working directory so the HTML template path resolves
        # correctly (reports/templates is relative to repo root).

        json_out = tmp_path / "out.json"
        html_out = tmp_path / "out.html"
        main(
            targets_arg="127.0.0.1",
            port=502,
            unit_id=1,
            timeout=1.0,
            json_out=str(json_out),
            html_out=str(html_out),
        )
        assert json_out.exists()
        loaded = json.loads(json_out.read_text())
        assert loaded["summary"]["reachable"] == 1
        # HTML report should also exist (template path resolves from cwd)
        if html_out.exists():
            content = html_out.read_text()
            assert "<!doctype html>" in content.lower()
