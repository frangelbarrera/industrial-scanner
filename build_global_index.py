"""
Minimalist Executive Meta-Dashboard.

Consolidates global metrics for Modbus, S7Comm, and DNP3 and generates
reports/index.html with a summary table and quick links.
"""

from __future__ import annotations

import html as html_lib
import json
import os
from datetime import UTC, datetime

REPORTS = {
    "Modbus": os.path.join("reports", "modbus_batch"),
    "S7Comm": os.path.join("reports", "s7_batch"),
    "DNP3": os.path.join("reports", "dnp3_batch"),
}

OUTPUT_FILE = os.path.join("reports", "index.html")


def collect_summary(folder: str) -> tuple[int, int, int]:
    total_pcaps = 0
    total_packets = 0
    suspect = 0
    if not os.path.exists(folder):
        return (0, 0, 0)
    for fname in os.listdir(folder):
        if not fname.endswith(".json"):
            continue
        total_pcaps += 1
        try:
            with open(os.path.join(folder, fname), encoding="utf-8") as f:
                data = json.load(f)
            summ = data.get("summary", {})
            total_packets += summ.get("total_packets", 0)
            suspect += summ.get("suspect_functions", 0)
        except Exception as e:
            # Log the corrupt file for traceability instead of silently
            # skipping. Using print() because this is a standalone script.
            print(f"[WARN] Could not read {fname} in {folder}: {e}")
            continue
    return (total_pcaps, total_packets, suspect)


def build_index(results: dict[str, tuple[int, int, int]], now_override: str | None = None) -> str:
    now = now_override or datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    parts = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>IndustrialScanner | Global Executive Dashboard</title>")
    parts.append(
        "<style>body{font-family:Arial;margin:24px;color:#222;}"
        "table{border-collapse:collapse;width:100%;margin-top:20px;}"
        "th,td{border:1px solid #ddd;padding:8px;}"
        "th{background:#f4f4f4;}"
        ".bad{color:#c62828;font-weight:bold;}"
        "a.button{display:inline-block;padding:6px 12px;margin:4px;"
        "background:#1976d2;color:#fff;text-decoration:none;border-radius:4px;}"
        "</style>"
    )
    parts.append("</head><body>")
    parts.append("<h1>Global Executive Dashboard</h1>")
    parts.append(f"<div><strong>Generated:</strong> {html_lib.escape(now)}</div>")
    parts.append(
        "<table><tr><th>Protocol</th><th>PCAPs Processed</th>"
        "<th>Total Packets</th><th>Suspect Functions</th><th>Dashboard</th></tr>"
    )
    for proto, (pcaps, packets, suspects) in results.items():
        suspect_html = f"<span class='bad'>{suspects}</span>" if suspects > 0 else str(suspects)
        link = f"{proto.lower()}_index.html"
        parts.append(
            f"<tr><td>{html_lib.escape(proto)}</td><td>{pcaps}</td>"
            f"<td>{packets}</td><td>{suspect_html}</td>"
            f"<td><a class='button' href='{link}'>Open {html_lib.escape(proto)}</a></td></tr>"
        )
    parts.append("</table>")
    parts.append(
        "<p>This meta-dashboard provides an executive view: global metrics "
        "and quick access to each detailed analysis.</p>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


if __name__ == "__main__":
    results = {}
    for proto, folder in REPORTS.items():
        results[proto] = collect_summary(folder)
    os.makedirs("reports", exist_ok=True)
    html = build_index(results)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Global meta-dashboard generated at {OUTPUT_FILE}")
