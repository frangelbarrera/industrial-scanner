"""
Passive analyzer for Siemens S7Comm traffic.

Scans all PCAP/PCAPNG files inside pcaps/s7/, extracts metadata, detects
sensitive function codes, and generates JSON/HTML reports in reports/s7_batch/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scapy.all import TCP, PcapReader

from ics_scanner.mitre_attack import enrich_report_with_attack
from ics_scanner.reporting import atomic_write_json, atomic_write_text, report_metadata
from modbus_scanner.utils import setup_logger, utc_ts

from .parsers import SUSPECT_FUNCS, parse_s7_packet

LOG = setup_logger("s7_analyzer")

PCAP_DIR = Path("pcaps/s7")
OUT_DIR = Path("reports/s7_batch")


def analyze_pcap(
    pcap_path: str,
    *,
    max_packets: int = 100_000,
    max_results: int = 10_000,
) -> dict[str, Any]:
    """Analyze a PCAP incrementally with explicit resource limits."""
    if max_packets < 1 or max_results < 1:
        raise ValueError("PCAP limits must be positive")
    results: list[dict[str, Any]] = []
    summary = {
        "total_packets": 0,
        "s7_packets": 0,
        "suspect_functions": 0,
        "unique_hosts": set(),
    }

    truncated = False
    with PcapReader(str(pcap_path)) as packets:
        for pkt in packets:
            summary["total_packets"] += 1
            if summary["total_packets"] > max_packets:
                truncated = True
                break
            if TCP in pkt and (pkt[TCP].dport == 102 or pkt[TCP].sport == 102):
                parsed = parse_s7_packet(pkt)
                if parsed:
                    if len(results) >= max_results:
                        truncated = True
                        break
                    results.append(parsed)
                    summary["s7_packets"] += 1
                    summary["unique_hosts"].add(parsed["src"])
                    summary["unique_hosts"].add(parsed["dst"])
                    if parsed["function_code"] in SUSPECT_FUNCS:
                        summary["suspect_functions"] += 1

    return {
        "meta": {
            **report_metadata(generated_at=utc_ts()),
            "pcap_file": str(pcap_path),
            "limits": {"max_packets": max_packets, "max_results": max_results},
            "truncated": truncated,
        },
        "results": results,
        "summary": {
            "total_packets": summary["total_packets"],
            "s7_packets": summary["s7_packets"],
            "suspect_functions": summary["suspect_functions"],
            "unique_hosts": list(filter(None, summary["unique_hosts"])),
        },
    }


def write_json_report(data: dict[str, Any], out_path: Path) -> Path:
    return atomic_write_json(out_path, data)


def write_html_report(
    data: dict[str, Any], out_path: Path, template_path: Path | None = None
) -> Path:
    # Render with autoescape=True to prevent XSS from untrusted PCAP bytes.
    from ics_scanner.security import safe_render

    template_dir = template_path.parent if template_path else Path("reports/templates")
    template_name = template_path.name if template_path else "s7_report.html"
    html = safe_render(template_name, {"report": data}, template_dir=str(template_dir))
    return atomic_write_text(out_path, html)


def main() -> None:
    if not PCAP_DIR.exists():
        LOG.error("PCAP folder does not exist: %s", PCAP_DIR)
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    pcaps = [f for f in PCAP_DIR.iterdir() if f.suffix in (".pcap", ".pcapng")]
    if not pcaps:
        LOG.info("No PCAP files found in %s", PCAP_DIR)
        return

    LOG.info("Processing %d S7 PCAP files from %s...", len(pcaps), PCAP_DIR)

    for pcap_file in pcaps:
        LOG.info("Analyzing %s", pcap_file.name)
        try:
            data = analyze_pcap(pcap_file)
            data = enrich_report_with_attack(data, "s7comm")
            data["meta"]["mitre_enriched"] = True
            base = pcap_file.stem
            json_path = OUT_DIR / f"{base}.json"
            html_path = OUT_DIR / f"{base}.html"
            write_json_report(data, json_path)
            write_html_report(data, html_path)
            LOG.info("[OK] Reports generated: %s, %s", json_path, html_path)
        except Exception as e:
            LOG.error("[ERROR] Failed to process %s: %s", pcap_file, e)


if __name__ == "__main__":
    main()
