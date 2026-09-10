"""Service layer for IndustrialScanner.

This module provides orchestration services that sit between the CLI/UI layer
and the protocol-specific adapters. It decouples high-level operations (scan
a target, analyze a PCAP, build a dashboard) from the underlying protocol
modules, making both easier to test and extend.

The services use the existing protocol modules (modbus_scanner, s7_comm_analyzer,
dnp3_monitor) as adapters and add MITRE ATT&CK enrichment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ics_scanner.mitre_attack import enrich_report_with_attack
from ics_scanner.security import (
    ScanPolicy,
    configure_logging,
    validate_targets,
)

LOG = configure_logging("ics_scanner.services")


def scan_modbus_service(
    targets_arg: str,
    port: int = 502,
    unit_id: int = 1,
    timeout: float = 2.0,
    json_out: str | None = None,
    html_out: str | None = None,
    *,
    allow_public: bool = False,
    enrich_attack: bool = True,
) -> dict[str, Any]:
    """Orchestrate a Modbus/TCP read-only scan.

    This service:
      1. Expands the targets argument (IPs, CIDR, @file).
      2. Filters targets through the safety policy (refuses public IPs unless
         allow_public=True).
      3. Runs the scan via modbus_scanner.modbus_scan.scan_targets.
      4. Optionally enriches each result with MITRE ATT&CK for ICS techniques.
      5. Writes JSON and HTML reports if paths are provided.

    Returns the aggregated scan result dict (with MITRE enrichment if enabled).
    Raises TargetPolicyError if all targets are filtered out.
    """
    from modbus_scanner.modbus_scan import (
        expand_targets,
        scan_targets,
        write_html_report,
        write_json_report,
    )

    raw_targets = expand_targets(targets_arg)
    safe_targets = validate_targets(raw_targets, ScanPolicy(allow_public=allow_public))
    LOG.info("Service: scanning %d target(s): %s", len(safe_targets), safe_targets)

    data = scan_targets(
        targets=safe_targets,
        port=port,
        unit_id=unit_id,
        timeout=timeout,
        allow_public=allow_public,
    )

    if enrich_attack:
        # Modbus results are not per-packet, so we enrich the summary only.
        # Each result gets an empty mitre_attack list as a placeholder for
        # future per-operation enrichment (when Modbus passive analysis is
        # added, each detected function code will be mapped to MITRE
        # techniques via ics_scanner.mitre_attack.map_function_to_techniques).
        for result in data.get("results", []):
            result["mitre_attack"] = []
        data["meta"]["mitre_enriched"] = True

    if json_out:
        write_json_report(data, Path(json_out))
    if html_out:
        write_html_report(data, Path(html_out))

    return data


def analyze_pcap_service(
    pcap_path: str,
    protocol: str,
    json_out: str | None = None,
    html_out: str | None = None,
    *,
    enrich_attack: bool = True,
) -> dict[str, Any]:
    """Orchestrate passive analysis of a single PCAP file.

    Args:
        pcap_path: Path to the PCAP/PCAPNG file.
        protocol: One of "s7comm" or "dnp3".
        json_out: Optional path for JSON report.
        html_out: Optional path for HTML report.
        enrich_attack: If True, enrich results with MITRE ATT&CK for ICS techniques.

    Returns the analysis result dict (with MITRE enrichment if enabled).
    """
    protocol = protocol.lower()
    if protocol not in ("s7comm", "dnp3"):
        raise ValueError(f"Unsupported protocol: {protocol}. Use 's7comm' or 'dnp3'.")

    if protocol == "s7comm":
        from s7_comm_analyzer.s7_analyze import analyze_pcap, write_html_report, write_json_report

        data = analyze_pcap(pcap_path)
        if enrich_attack:
            data = enrich_report_with_attack(data, "s7comm")
            data["meta"]["mitre_enriched"] = True
        if json_out:
            write_json_report(data, Path(json_out))
        if html_out:
            write_html_report(data, Path(html_out))
    else:  # dnp3
        from dnp3_monitor.dnp3_analyze import analyze_pcap, save_html, save_json

        data = analyze_pcap(pcap_path)
        if enrich_attack:
            data = enrich_report_with_attack(data, "dnp3")
            data["meta"]["mitre_enriched"] = True
        if json_out:
            save_json(data, json_out)
        if html_out:
            save_html(data, html_out)

    return data


def build_dashboard_service(
    protocol: str,
    reports_dir: str = "reports",
    output_file: str | None = None,
) -> str:
    """Orchestrate dashboard building for a specific protocol.

    Args:
        protocol: One of "modbus", "s7comm", "dnp3", or "global".
        reports_dir: Root directory containing the per-protocol batch folders.
        output_file: Override path for the generated HTML dashboard.

    Returns the path to the generated HTML dashboard.
    """
    protocol = protocol.lower()
    if protocol == "modbus":
        import build_modbus_index as mod

        mod.REPORT_DIR = str(Path(reports_dir) / "modbus_batch")
        if output_file:
            mod.OUTPUT_FILE = output_file
        reports = mod.load_reports()
        html = mod.build_index(reports)
        out_path = output_file or str(Path(reports_dir) / "modbus_index.html")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(html, encoding="utf-8")
        return out_path
    elif protocol == "s7comm":
        import build_s7_index as s7

        s7.REPORT_DIR = str(Path(reports_dir) / "s7_batch")
        if output_file:
            s7.OUTPUT_FILE = output_file
        reports = s7.load_reports()
        html = s7.build_index(reports)
        out_path = output_file or str(Path(reports_dir) / "s7_index.html")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(html, encoding="utf-8")
        return out_path
    elif protocol == "dnp3":
        import build_dnp3_index as dnp3

        dnp3.REPORT_DIR = str(Path(reports_dir) / "dnp3_batch")
        if output_file:
            dnp3.OUTPUT_FILE = output_file
        reports = dnp3.load_reports()
        html = dnp3.build_index(reports)
        out_path = output_file or str(Path(reports_dir) / "dnp3_index.html")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(html, encoding="utf-8")
        return out_path
    elif protocol == "global":
        import build_global_index as g

        out_path = output_file or str(Path(reports_dir) / "index.html")
        g.OUTPUT_FILE = out_path
        results = {}
        for proto, _folder in g.REPORTS.items():
            results[proto] = g.collect_summary(str(Path(reports_dir) / f"{proto.lower()}_batch"))
        html = g.build_index(results)
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(html, encoding="utf-8")
        return out_path
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")
