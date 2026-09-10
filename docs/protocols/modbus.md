# Modbus/TCP

Modbus/TCP is the most widely deployed industrial protocol, running over
TCP/502. It is a simple request-response protocol originally designed by
Modicon (now Schneider Electric) in 1979 for serial communication, later
adapted for TCP.

## What IndustrialScanner does

The Modbus scanner issues **only read function codes**:

| Code | Name | Description |
|---|---|---|
| 0x01 | Read Coils | Read discrete outputs (ON/OFF) |
| 0x02 | Read Discrete Inputs | Read discrete inputs (read-only) |
| 0x03 | Read Holding Registers | Read 16-bit registers |
| 0x04 | Read Input Registers | Read 16-bit input registers (read-only) |

No write or control operations are intentionally issued. Read-only does not
guarantee zero operational impact: validate the scanner in a representative
lab, obtain asset-owner authorization, and use a maintenance window before
active scanning of production PLCs.

## Usage

```bash
industrial-scanner modbus --targets 192.168.1.10 --unit 1
industrial-scanner modbus --targets 192.168.1.0/24 --port 502 --unit 1
industrial-scanner modbus --targets @targets.txt --timeout 2.5
```

## Output

Each scan produces:

- **JSON report** in `reports/modbus_batch/modbus_scan_<timestamp>.json`
- **HTML report** in `reports/modbus_batch/modbus_scan_<timestamp>.html`

The report includes:

- Per-host: reachable, latency_ms, reads (4 windows), exposure flags, errors
- Summary: total reachable, unauthenticated_read count, broad_register_access count

## Exposure signals

The scanner reports two exposure signals per host:

- **unauthenticated_read**: True if any read function returned data without
  authentication. Modbus/TCP has no built-in authentication, so this is
  almost always True for any reachable PLC.
- **broad_register_access**: True if 2 or more read windows returned data.
  This indicates the PLC exposes multiple data types without restriction.

## Security considerations

- Modbus/TCP has **no authentication, no encryption, no integrity** by design
- Anyone with network access to TCP/502 can read AND write to the PLC
- The scanner is read-only, but a malicious actor on the same network is not
- Active reads can still consume device or network resources; execution is
  single-flight by default and supports a delay between targets
- For production deployments, consider **Modbus/TCP Security (RFC 9441)**
  which adds TLS + X.509 + per-function-code access control

## MITRE ATT&CK mapping

Read operations map to:
- T0801 — Monitor Process State
- T0802 — Automated Discovery

(Write/control operations — if detected in passive PCAPs — map to T0858
Change Operating Mode. The scanner does not issue these.)
