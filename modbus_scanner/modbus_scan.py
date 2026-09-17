"""
Modbus Scanner (Read-only) - IndustrialScanner.

Safe, read-only Modbus/TCP scanner for OT networks. It probes hosts, reads
small register/coil windows, assesses exposure risks, and generates
JSON/HTML reports.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException

from ics_scanner.reporting import atomic_write_json, atomic_write_text, report_metadata
from ics_scanner.security import ScanPolicy, validate_targets

from .utils import (
    expand_targets,
    safe_str,
    setup_logger,
    utc_ts,
)

LOG = setup_logger("modbus_scanner")


def probe_host(ip: str, port: int, unit_id: int, timeout: float = 2.0) -> dict[str, Any]:
    """
    Probe a single Modbus/TCP host safely (read-only).

    Issues short reads for coils, discrete inputs, holding and input registers,
    and collects basic latency and exposure signals.
    """
    start = time.time()
    result: dict[str, Any] = {
        "ip": ip,
        "port": port,
        "unit_id": unit_id,
        "reachable": False,
        "latency_ms": None,
        "reads": {
            "coils": None,
            "discrete_inputs": None,
            "holding_registers": None,
            "input_registers": None,
        },
        "exposure": {
            "unauthenticated_read": False,
            "broad_register_access": False,
        },
        "errors": [],
    }

    client: ModbusTcpClient | None = None
    try:
        client = ModbusTcpClient(host=ip, port=port, timeout=timeout)
        if not client.connect():
            result["errors"].append("Connection failed")
            return result

        result["reachable"] = True

        # pymodbus renamed the unit-id keyword across versions:
        # 3.14+ uses device_id, 3.5+ uses slave, older uses unit.
        import inspect

        read_params = inspect.signature(client.read_coils).parameters
        if "device_id" in read_params:
            unit_kwarg = "device_id"
        elif "slave" in read_params:
            unit_kwarg = "slave"
        else:
            unit_kwarg = "unit"

        try:
            rr = client.read_coils(address=0, count=16, **{unit_kwarg: unit_id})
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["coils"] = list(rr.bits) if rr.bits is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"coils_read_error: {safe_str(e)}")

        try:
            rr = client.read_discrete_inputs(address=0, count=16, **{unit_kwarg: unit_id})
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["discrete_inputs"] = list(rr.bits) if rr.bits is not None else []
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"discrete_inputs_read_error: {safe_str(e)}")

        try:
            rr = client.read_holding_registers(address=0, count=10, **{unit_kwarg: unit_id})
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["holding_registers"] = (
                    list(rr.registers) if rr.registers is not None else []
                )
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"holding_registers_read_error: {safe_str(e)}")

        try:
            rr = client.read_input_registers(address=0, count=10, **{unit_kwarg: unit_id})
            if not isinstance(rr, ModbusIOException) and rr.isError() is False:
                result["reads"]["input_registers"] = (
                    list(rr.registers) if rr.registers is not None else []
                )
                result["exposure"]["unauthenticated_read"] = True
        except Exception as e:
            result["errors"].append(f"input_registers_read_error: {safe_str(e)}")

        windows_with_data = sum(
            1 for _, v in result["reads"].items() if isinstance(v, list) and len(v) > 0
        )
        if windows_with_data >= 2:
            result["exposure"]["broad_register_access"] = True

    except Exception as e:
        result["errors"].append(f"probe_error: {safe_str(e)}")
    finally:
        if client is not None:
            # Best-effort close. Using contextlib.suppress to avoid the
            # bandit B110 try-except-pass anti-pattern while still tolerating
            # close failures (e.g., already-closed socket).
            import contextlib

            with contextlib.suppress(Exception):
                client.close()
        end = time.time()
        result["latency_ms"] = round((end - start) * 1000, 2)

    return result


def scan_targets(
    targets: list[str],
    port: int,
    unit_id: int,
    timeout: float,
    *,
    allow_public: bool = False,
    delay_between_targets: float = 0.0,
) -> dict[str, Any]:
    """Scan bounded targets sequentially after applying the safety policy."""
    if not targets:
        return {
            "meta": {
                **report_metadata(generated_at=utc_ts()),
                "targets": [],
                "port": port,
                "unit_id": unit_id,
                "timeout": timeout,
            },
            "results": [],
            "summary": {"reachable": 0, "unauthenticated_read": 0, "broad_register_access": 0},
        }
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0 <= unit_id <= 255:
        raise ValueError("unit_id must be between 0 and 255")
    if not 0.2 <= timeout <= 10.0:
        raise ValueError("timeout must be between 0.2 and 10 seconds")
    policy = ScanPolicy(
        allow_public=allow_public,
        delay_between_targets=delay_between_targets,
    )
    validated = validate_targets(targets, policy)
    aggregate: dict[str, Any] = {
        "meta": {
            **report_metadata(generated_at=utc_ts()),
            "targets": validated,
            "port": port,
            "unit_id": unit_id,
            "timeout": timeout,
            "policy": {
                "allow_public": allow_public,
                "max_targets": policy.max_targets,
                "max_cidr_hosts": policy.max_cidr_hosts,
                "delay_between_targets": delay_between_targets,
                "writes_intentionally_issued": False,
            },
        },
        "results": [],
        "summary": {
            "reachable": 0,
            "unauthenticated_read": 0,
            "broad_register_access": 0,
        },
    }
    results: list[dict[str, Any]] = aggregate["results"]
    summary: dict[str, int] = aggregate["summary"]

    for index, ip in enumerate(validated):
        LOG.info("Probing %s:%d (unit %d)", ip, port, unit_id)
        res = probe_host(ip, port, unit_id, timeout)
        results.append(res)

        if res["reachable"]:
            summary["reachable"] += 1
        if res["exposure"]["unauthenticated_read"]:
            summary["unauthenticated_read"] += 1
        if res["exposure"]["broad_register_access"]:
            summary["broad_register_access"] += 1
        if index + 1 < len(validated) and delay_between_targets:
            time.sleep(delay_between_targets)

    return aggregate


def write_json_report(data: dict[str, Any], out_path: Path) -> Path:
    return atomic_write_json(out_path, data)


def write_html_report(
    data: dict[str, Any], out_path: Path, template_path: Path | None = None
) -> Path:
    # Render with autoescape=True to prevent XSS from untrusted PCAP bytes.
    from ics_scanner.security import safe_render

    if template_path:
        template_dir = template_path.parent
    else:
        from importlib.resources import files

        template_dir = Path(str(files("reports") / "templates"))
    template_name = template_path.name if template_path else "modbus_report.html"
    html = safe_render(template_name, {"report": data}, template_dir=str(template_dir))
    return atomic_write_text(out_path, html)


def main(
    targets_arg: str,
    port: int = 502,
    unit_id: int = 1,
    timeout: float = 2.0,
    json_out: str | None = None,
    html_out: str | None = None,
) -> None:
    targets = expand_targets(targets_arg)
    LOG.info("Expanded targets: %s", targets)

    data = scan_targets(targets=targets, port=port, unit_id=unit_id, timeout=timeout)

    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/modbus_batch/modbus_scan_{ts}.json")
    html_path = Path(html_out or f"reports/modbus_batch/modbus_scan_{ts}.html")

    write_json_report(data, json_path)
    write_html_report(data, html_path)

    LOG.info("JSON report: %s", json_path)
    LOG.info("HTML report: %s", html_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IndustrialScanner Modbus read-only scanner")
    parser.add_argument(
        "--targets",
        required=True,
        help="Comma-separated IPs, CIDR (e.g. 192.168.0.0/24), or @file with one IP per line",
    )
    parser.add_argument("--port", type=int, default=502, help="Modbus/TCP port (default: 502)")
    parser.add_argument("--unit", type=int, default=1, help="Modbus Unit ID (default: 1)")
    parser.add_argument(
        "--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)"
    )
    parser.add_argument("--json-out", type=str, default=None, help="Path for JSON report")
    parser.add_argument("--html-out", type=str, default=None, help="Path for HTML report")

    args = parser.parse_args()
    main(
        targets_arg=args.targets,
        port=args.port,
        unit_id=args.unit,
        timeout=args.timeout,
        json_out=args.json_out,
        html_out=args.html_out,
    )
