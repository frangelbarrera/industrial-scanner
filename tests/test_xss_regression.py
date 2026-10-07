"""Verify that HTML reports escape untrusted input (XSS regression)."""

from __future__ import annotations

from dnp3_monitor.dnp3_analyze import build_html


def test_dnp3_html_escapes_untrusted_payload():
    """A PCAP-derived field containing <script> MUST NOT appear verbatim in HTML."""
    malicious = "<script>alert('XSS')</script>"
    report = {
        "meta": {"generated_at": "2025-01-01T00:00:00Z", "pcap_file": malicious},
        "summary": {
            "total_packets": 0,
            "dnp3_packets": 0,
            "suspect_functions": 0,
            "unique_hosts": [malicious],
        },
        "results": [
            {
                "src": malicious,
                "dst": malicious,
                "function": malicious,
                "length": 0,
                "hints": [malicious],
                "suspect": True,
            }
        ],
    }
    html = build_html(report)

    # Executable HTML tags MUST NOT appear verbatim — they get escaped.
    assert "<script>" not in html
    assert "</script>" not in html
    assert "&lt;script&gt;" in html

    # The browser-rendered text DOES contain "alert(" as visible content,
    # but the markup is inert. Verify the dangerous <script>...</script>
    # sequence is broken into escaped entities.
    assert "<script>alert(" not in html


def test_dashboard_index_neutralizes_script_breakout(tmp_path):
    import build_s7_index

    build_s7_index.REPORT_DIR = str(tmp_path)
    hostile = tmp_path / "<script>alert.json"
    hostile.write_text(
        '{"meta":{"pcap_file":"</script><script>alert(1)</script>"},'
        '"summary":{"total_packets":1,"s7_packets":1,"suspect_functions":0,'
        '"unique_hosts":["</script><script>alert(2)</script>"]}}'
    )
    html = build_s7_index.build_index(
        build_s7_index.load_reports(), now_override="2025-01-01 00:00:00Z"
    )
    assert "</script><script>alert" not in html
    assert "\\u003c" in html
