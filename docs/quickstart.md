# Quickstart

This guide walks you through installing IndustrialScanner and running your
first analysis in under 5 minutes.

## Installation

### From PyPI (recommended)

```bash
pip install industrial-scanner
```

### From source (development)

```bash
git clone https://github.com/frangelbarrera/industrial-scanner.git
cd IndustrialScanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

### Docker

```bash
docker pull ghcr.io/frangelbarrera/industrial-scanner:latest
docker run --rm -v $(pwd):/work industrial-scanner modbus --targets 127.0.0.1
```

## Your first Modbus scan

ModbusPal is bundled for testing. Start it (or any Modbus/TCP server on
port 502), then:

```bash
industrial-scanner modbus --targets 127.0.0.1 --unit 1
```

You'll see a summary table in the console and JSON + HTML reports in
`reports/modbus_batch/`.

## Your first S7Comm analysis

```bash
industrial-scanner s7 --pcap pcaps/s7/step7_s300_stop.pcapng
```

The tool unwraps TPKT/COTP framing, parses the S7 PDU, and classifies each
packet by function code (ReadVar, WriteVar, Start, Stop, DownloadBlock, …).
Reports are written to `reports/s7_batch/` with MITRE ATT&CK enrichment.

## Your first DNP3 analysis

```bash
industrial-scanner dnp3 --pcap pcaps/dnp3/read_and_response.pcap
```

The tool decodes the DNP3 link, transport, and application layers per
IEEE 1815-2012, identifying function codes by binary offset (Read, Write,
Operate, ColdRestart, …).

## Building dashboards

After generating per-PCAP reports, build consolidated dashboards by running
the build scripts directly:

```bash
# Modbus dashboard
python build_modbus_index.py

# S7Comm dashboard
python build_s7_index.py

# DNP3 dashboard
python build_dnp3_index.py

# Global executive dashboard (aggregates all three)
python build_global_index.py
```

The global dashboard at `reports/index.html` provides an executive view
across all three protocols.

> **Note**: a `dashboard` subcommand is planned for a future release to
> unify these scripts under the CLI. For now, use the build scripts directly.

## Operational capture aids

The `tools/` directory is reserved for reviewed Wireshark profiles and capture
utilities. No such artifacts are published yet. Until they are added and
validated, use a separately approved profile and follow your organization's
passive, receive-only collection procedure. See
[`tools/README.md`](../tools/README.md) for the publication criteria.

## Next steps

- [Protocol guides](protocols/modbus.md) for deep dives into each protocol
- [MITRE ATT&CK mapping](mitre-attack.md) to understand the threat intelligence
- [Architecture](architecture.md) for the design philosophy
- [IEC 62443 zones and conduits](62443-zones-conduits.md) for a corporate
  assessment and evidence workflow
- [Contributing](contributing.md) if you want to add a new protocol parser
