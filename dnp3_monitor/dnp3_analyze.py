"""
DNP3 Monitor: PCAP analysis for DNP3 traffic over TCP/UDP port 20000.
Generates JSON and HTML reports with summary and per-packet details.
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.all import TCP, UDP, PcapReader

from ics_scanner.reporting import atomic_write_json, atomic_write_text, report_metadata

from .parsers import parse_dnp3_packet


def utc_ts() -> str:
    from datetime import UTC

    return datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")


def analyze_pcap(
    pcap_path: str,
    *,
    max_packets: int = 100_000,
    max_results: int = 10_000,
) -> dict[str, Any]:
    """Analyze a PCAP incrementally and stop at bounded resource limits."""
    if max_packets < 1 or max_results < 1:
        raise ValueError("PCAP limits must be positive")
    results: list[dict[str, Any]] = []

    summary = {"total_packets": 0, "dnp3_packets": 0, "suspect_functions": 0, "unique_hosts": set()}

    truncated = False
    with PcapReader(pcap_path) as packets:
        for pkt in packets:
            summary["total_packets"] += 1
            if summary["total_packets"] > max_packets:
                truncated = True
                break
            is_dnp3 = False
            if (TCP in pkt and (pkt[TCP].dport == 20000 or pkt[TCP].sport == 20000)) or (
                UDP in pkt and (pkt[UDP].dport == 20000 or pkt[UDP].sport == 20000)
            ):
                is_dnp3 = True

            if not is_dnp3:
                continue

            parsed = parse_dnp3_packet(pkt)
            if parsed:
                if len(results) >= max_results:
                    truncated = True
                    break
                results.append(parsed)
                summary["dnp3_packets"] += 1
                summary["unique_hosts"].add(parsed["src"])
                summary["unique_hosts"].add(parsed["dst"])
                if parsed.get("suspect"):
                    summary["suspect_functions"] += 1

    return {
        "meta": {
            **report_metadata(generated_at=utc_ts()),
            "pcap_file": pcap_path,
            "limits": {"max_packets": max_packets, "max_results": max_results},
            "truncated": truncated,
        },
        "results": results,
        "summary": {
            "total_packets": summary["total_packets"],
            "dnp3_packets": summary["dnp3_packets"],
            "suspect_functions": summary["suspect_functions"],
            "unique_hosts": list(filter(None, summary["unique_hosts"])),
        },
    }


def save_json(report: dict[str, Any], json_out: str) -> None:
    """Write the JSON report, creating parent directories if needed.

    Handles the case where json_out has no directory component (e.g., "out.json"
    in the current working directory) without raising from os.makedirs('').
    """
    atomic_write_json(Path(json_out), report)


def build_html(report: dict[str, Any]) -> str:
    """Build DNP3 HTML report with proper HTML escaping (XSS fix).

    Original code used f-strings to embed PCAP-derived bytes directly into HTML,
    enabling stored XSS when reports were generated from attacker-controlled PCAPs.
    This implementation uses markupsafe.escape() on every untrusted field.
    """
    from markupsafe import escape

    rows = []
    for r in report.get("results", []):
        func = r.get("function", "")
        func_html = f"<span class='bad'>{escape(func)}</span>" if r.get("suspect") else escape(func)
        hints = ", ".join(r.get("hints", []))
        rows.append(
            "<tr>"
            f"<td>{escape(r.get('src', ''))}</td>"
            f"<td>{escape(r.get('dst', ''))}</td>"
            f"<td>{func_html}</td>"
            f"<td>{escape(r.get('length', ''))}</td>"
            f"<td>{escape(hints)}</td>"
            "</tr>"
        )

    # All values below are tool-internal constants, NOT user-controlled.
    gen = report["meta"]["generated_at"]
    pcap = report["meta"]["pcap_file"]
    summary = report["summary"]
    hosts = ", ".join(summary["unique_hosts"])

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IndustrialScanner | DNP3 Analysis Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
    h1 {{ margin-bottom: 4px; }}
    .meta {{ color: #555; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; }}
    th {{ background: #f4f4f4; text-align: left; }}
    .bad {{ color: #c62828; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>DNP3 Analysis Report</h1>
  <div class="meta">
    <div><strong>Generated:</strong> {escape(gen)}</div>
    <div><strong>PCAP File:</strong> {escape(pcap)}</div>
  </div>

  <h2>Summary</h2>
  <table>
    <tr>
      <th>Total Packets</th>
      <th>DNP3 Packets</th>
      <th>Suspect Functions</th>
      <th>Unique Hosts</th>
    </tr>
    <tr>
      <td>{summary["total_packets"]}</td>
      <td>{summary["dnp3_packets"]}</td>
      <td>{summary["suspect_functions"]}</td>
      <td>{escape(hosts)}</td>
    </tr>
  </table>

  <h2>Per-Packet Details</h2>
  <table>
    <tr>
      <th>Source</th>
      <th>Destination</th>
      <th>Function</th>
      <th>Length</th>
      <th>Hints</th>
    </tr>
    {"".join(rows)}
  </table>

  <h2>Notes</h2>
  <ul>
    <li>This analysis is passive and read-only.</li>
    <li>Suspect operations include Operate, Write, EnableUnsolicited, and Restart commands.</li>
    <li>Heuristic parsing: deeper decoding can be added later.</li>
  </ul>
</body>
</html>
"""


def save_html(report: dict[str, Any], html_out: str) -> None:
    """Write the HTML report, creating parent directories if needed."""
    html = build_html(report)
    atomic_write_text(Path(html_out), html)


def main(
    pcap_file: str,
    json_out: str = None,
    html_out: str = None,
) -> dict[str, Any]:
    from ics_scanner.mitre_attack import enrich_report_with_attack

    data = analyze_pcap(pcap_file)
    data = enrich_report_with_attack(data, "dnp3")
    data["meta"]["mitre_enriched"] = True
    if not json_out:
        json_out = str(Path("reports") / f"dnp3_scan_{utc_ts()}.json")
    if not html_out:
        html_out = str(Path("reports") / f"dnp3_scan_{utc_ts()}.html")

    save_json(data, json_out)
    save_html(data, html_out)
    return {
        "json": json_out,
        "html": html_out,
    }
