"""
Global Index Generator for S7Comm Analyzer with charts.

Reads all JSON reports in reports/s7_batch/ and builds reports/s7_index.html
with an executive summary, links to HTML reports, and Chart.js visualizations.
"""

from __future__ import annotations

import html as html_lib
import json
import os
from datetime import UTC, datetime
from typing import Any

REPORT_DIR = os.path.join("reports", "s7_batch")
OUTPUT_FILE = os.path.join("reports", "s7_index.html")


def load_reports() -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    if not os.path.isdir(REPORT_DIR):
        return reports
    for fname in os.listdir(REPORT_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(REPORT_DIR, fname)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            html_name = fname.replace(".json", ".html")
            reports.append(
                {
                    "json": fname,
                    "html": html_name,
                    "meta": data.get("meta", {}),
                    "summary": data.get("summary", {}),
                }
            )
        except Exception as e:
            print(f"[WARN] Could not read {fname}: {e}")
    return reports


def build_index(reports: list[dict[str, Any]], now_override: str | None = None) -> str:
    now = now_override or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")

    labels = []
    total_packets = []
    s7_packets = []
    suspects = []

    for r in reports:
        labels.append(r["html"])
        summ = r["summary"]
        total_packets.append(summ.get("total_packets", 0))
        s7_packets.append(summ.get("s7_packets", 0))
        suspects.append(summ.get("suspect_functions", 0))

    parts = []
    parts.append("<!doctype html><html lang='en'><head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<title>IndustrialScanner | S7Comm Global Report Index</title>")
    parts.append("<script src='assets/chart.umd.min.js'></script>")
    parts.append("<style>")
    parts.append("body { font-family: Arial, sans-serif; margin: 24px; color: #222; }")
    parts.append("h1 { margin-bottom: 4px; }")
    parts.append("table { border-collapse: collapse; width: 100%; margin-top: 12px; }")
    parts.append("th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }")
    parts.append("th { background: #f4f4f4; text-align: left; }")
    parts.append(".bad { color: #c62828; font-weight: bold; }")
    parts.append(".charts { display: flex; gap: 40px; margin-top: 24px; }")
    parts.append(".chart-container { width: 45%; }")
    parts.append("</style></head><body>")
    parts.append("<h1>S7Comm Global Report Index</h1>")
    parts.append(f"<div><strong>Generated:</strong> {html_lib.escape(now)}</div>")

    parts.append("<table>")
    parts.append(
        "<tr><th>Report</th><th>PCAP File</th><th>Total Packets</th>"
        "<th>S7 Packets</th><th>Suspect Functions</th><th>Unique Hosts</th></tr>"
    )
    for r in reports:
        meta = r["meta"]
        summ = r["summary"]
        suspect = summ.get("suspect_functions", 0)
        suspect_html = f"<span class='bad'>{suspect}</span>" if suspect > 0 else str(suspect)
        parts.append("<tr>")
        parts.append(
            f"<td><a href='s7_batch/{html_lib.escape(r['html'])}'>"
            f"{html_lib.escape(r['html'])}</a></td>"
        )
        parts.append(f"<td>{html_lib.escape(str(meta.get('pcap_file', '')))}</td>")
        parts.append(f"<td>{summ.get('total_packets', '')}</td>")
        parts.append(f"<td>{summ.get('s7_packets', '')}</td>")
        parts.append(f"<td>{suspect_html}</td>")
        parts.append(f"<td>{html_lib.escape(', '.join(summ.get('unique_hosts', [])))}</td>")
        parts.append("</tr>")
    parts.append("</table>")

    parts.append("<div class='charts'>")
    parts.append("<div class='chart-container'><canvas id='chartPackets'></canvas></div>")
    parts.append("<div class='chart-container'><canvas id='chartSuspects'></canvas></div>")
    parts.append("</div>")
    parts.append("<script>")
    parts.append(f"const labels = {labels};")
    parts.append(f"const totalPackets = {total_packets};")
    parts.append(f"const s7Packets = {s7_packets};")
    parts.append(f"const suspects = {suspects};")
    parts.append("""
    new Chart(document.getElementById('chartPackets'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Total Packets', data: totalPackets, backgroundColor: 'rgba(54, 162, 235, 0.6)' },
                { label: 'S7 Packets', data: s7Packets, backgroundColor: 'rgba(75, 192, 192, 0.6)' }
            ]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'top' } },
            scales: { x: { ticks: { autoSkip: false, maxRotation: 90, minRotation: 45 } } }
        }
    });
    new Chart(document.getElementById('chartSuspects'), {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                label: 'Suspect Functions',
                data: suspects,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.6)',
                    'rgba(255, 159, 64, 0.6)',
                    'rgba(255, 205, 86, 0.6)',
                    'rgba(75, 192, 192, 0.6)',
                    'rgba(54, 162, 235, 0.6)',
                    'rgba(153, 102, 255, 0.6)',
                    'rgba(201, 203, 207, 0.6)'
                ]
            }]
        },
        options: { responsive: true, plugins: { legend: { position: 'right' } } }
    });
    """)
    parts.append("</script>")

    parts.append("<h2>Notes</h2><ul>")
    parts.append(
        "<li>This index consolidates all reports generated in <code>reports/s7_batch/</code>.</li>"
    )
    parts.append("<li>Click on the report name to open the detailed HTML view.</li>")
    parts.append(
        "<li>Values in red indicate detected suspect functions (Start, Stop, "
        "WriteVar, DownloadBlock, CopyRamToRom, FirmwareUpdate).</li>"
    )
    parts.append(
        "<li>The charts display the global distribution of packets and suspect functions.</li>"
    )
    parts.append("</ul>")
    parts.append("</body></html>")
    return "\n".join(parts)


if __name__ == "__main__":
    reports = load_reports()
    if not reports:
        print("[INFO] No JSON reports found in reports/s7_batch/")
    else:
        os.makedirs("reports", exist_ok=True)
        html = build_index(reports)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[OK] Global S7Comm index generated at {OUTPUT_FILE}")
