"""Unified, fail-closed CLI entry point for IndustrialScanner."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from ics_scanner.security import ScanPolicy, TargetPolicyError, configure_logging, validate_targets

console = Console()
log = configure_logging("ics_scanner.cli")


@click.group(help="IndustrialScanner — defensive ICS/OT analyzer.")
@click.version_option(package_name="industrial-scanner")
def cli() -> None:
    """Entry group."""


@cli.command("modbus", help="Active Modbus/TCP probe with no intentional writes.")
@click.option("--targets", required=True, help="Comma-separated IPs, bounded CIDR, or @file")
@click.option("--port", default=502, show_default=True, type=click.IntRange(1, 65535))
@click.option("--unit", default=1, show_default=True, type=click.IntRange(0, 255))
@click.option("--timeout", default=2.0, show_default=True, type=click.FloatRange(0.2, 10.0))
@click.option("--delay", default=0.0, show_default=True, type=click.FloatRange(0.0, 3600.0))
@click.option("--max-targets", default=256, show_default=True, type=click.IntRange(1, 256))
@click.option("--json-out", default=None, help="JSON report path")
@click.option("--html-out", default=None, help="HTML report path")
@click.option(
    "--allow-public",
    is_flag=True,
    default=False,
    help="Allow public targets only with explicit written authorization",
)
def modbus_cmd(
    targets: str,
    port: int,
    unit: int,
    timeout: float,
    delay: float,
    max_targets: int,
    json_out: str | None,
    html_out: str | None,
    allow_public: bool,
) -> None:
    from modbus_scanner.modbus_scan import (
        expand_targets,
        scan_targets,
        write_html_report,
        write_json_report,
    )
    from modbus_scanner.utils import utc_ts

    try:
        raw = expand_targets(targets, max_hosts=max_targets)
        safe = validate_targets(
            raw,
            ScanPolicy(
                allow_public=allow_public,
                max_targets=max_targets,
                delay_between_targets=delay,
            ),
        )
    except (TargetPolicyError, ValueError) as exc:
        console.print(f"[red]No safe targets after policy validation:[/red] {exc}")
        raise click.exceptions.Exit(2) from exc

    log.info("Scanning %d target(s): %s", len(safe), safe)
    data = scan_targets(
        targets=safe,
        port=port,
        unit_id=unit,
        timeout=timeout,
        allow_public=allow_public,
        delay_between_targets=delay,
    )
    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/modbus_batch/modbus_scan_{ts}.json")
    html_path = Path(html_out or f"reports/modbus_batch/modbus_scan_{ts}.html")
    write_json_report(data, json_path)
    write_html_report(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")

    table = Table(title="Modbus Scan Summary")
    table.add_column("IP")
    table.add_column("Reachable")
    table.add_column("Latency ms")
    table.add_column("Errors")
    for result in data["results"]:
        table.add_row(
            result["ip"],
            "OK" if result["reachable"] else "FAIL",
            str(result["latency_ms"]),
            str(len(result["errors"])),
        )
    console.print(table)


@cli.command("s7", help="Passive S7Comm analyzer for one PCAP.")
@click.option("--pcap", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--max-packets", default=100000, show_default=True, type=click.IntRange(1, 1000000))
@click.option("--max-results", default=10000, show_default=True, type=click.IntRange(1, 100000))
@click.option("--json-out", default=None)
@click.option("--html-out", default=None)
def s7_cmd(
    pcap: str, max_packets: int, max_results: int, json_out: str | None, html_out: str | None
) -> None:
    from ics_scanner.mitre_attack import enrich_report_with_attack
    from modbus_scanner.utils import utc_ts
    from s7_comm_analyzer.s7_analyze import analyze_pcap, write_html_report, write_json_report

    data = enrich_report_with_attack(
        analyze_pcap(pcap, max_packets=max_packets, max_results=max_results), "s7comm"
    )
    data["meta"]["mitre_enriched"] = True
    base = Path(pcap).stem
    ts = utc_ts().replace(":", "-")
    json_path = Path(json_out or f"reports/s7_batch/{base}_{ts}.json")
    html_path = Path(html_out or f"reports/s7_batch/{base}_{ts}.html")
    write_json_report(data, json_path)
    write_html_report(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")


@cli.command("dnp3", help="Passive DNP3 analyzer for one PCAP.")
@click.option("--pcap", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--max-packets", default=100000, show_default=True, type=click.IntRange(1, 1000000))
@click.option("--max-results", default=10000, show_default=True, type=click.IntRange(1, 100000))
@click.option("--json-out", default=None)
@click.option("--html-out", default=None)
def dnp3_cmd(
    pcap: str, max_packets: int, max_results: int, json_out: str | None, html_out: str | None
) -> None:
    from dnp3_monitor.dnp3_analyze import analyze_pcap, save_html, save_json
    from ics_scanner.mitre_attack import enrich_report_with_attack

    data = enrich_report_with_attack(
        analyze_pcap(pcap, max_packets=max_packets, max_results=max_results), "dnp3"
    )
    data["meta"]["mitre_enriched"] = True
    base = Path(pcap).stem
    json_path = json_out or f"reports/dnp3_batch/{base}.json"
    html_path = html_out or f"reports/dnp3_batch/{base}.html"
    save_json(data, json_path)
    save_html(data, html_path)
    console.print(f"[green]OK[/green] JSON: {json_path}")
    console.print(f"[green]OK[/green] HTML: {html_path}")


def main() -> None:
    try:
        cli()
    except TargetPolicyError as exc:
        console.print(f"[red]Target policy violation:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
