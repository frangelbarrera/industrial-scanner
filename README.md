<div align="center">

# IndustrialScanner

**Read-only security analyzer for Industrial Control Systems (ICS) / Operational Technology (OT)**

Modbus/TCP &middot; Siemens S7Comm &middot; DNP3

</div>

---

[![License: MIT](https://img.shields.io/github/license/frangelbarrera/industrial-scanner?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/frangelbarrera/industrial-scanner/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/frangelbarrera/industrial-scanner/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-261230?style=flat-square)](https://docs.astral.sh/ruff/)
[![Coverage](https://img.shields.io/badge/coverage-89%25-brightgreen?style=flat-square)](https://pytest.org)
[![Security: bandit](https://img.shields.io/badge/security-bandit-1f6feb?style=flat-square)](https://github.com/PyCQA/bandit)
[![MITRE ATT&CK for ICS](https://img.shields.io/badge/MITRE%20ATT%26CK%20for%20ICS-mapped-00B4D8?style=flat-square)](https://attack.mitre.org/matrices/ics/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square)](https://github.com/frangelbarrera/industrial-scanner/pkgs/container/industrial-scanner)
[![Stars](https://img.shields.io/github/stars/frangelbarrera/industrial-scanner?style=flat-square)](https://github.com/frangelbarrera/industrial-scanner/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/frangelbarrera/industrial-scanner?style=flat-square)](https://github.com/frangelbarrera/industrial-scanner/commits)
[![Issues](https://img.shields.io/github/issues/frangelbarrera/industrial-scanner?style=flat-square)](https://github.com/frangelbarrera/industrial-scanner/issues)

> ⚠️ **Read-only research / education tool.** Never deploy against production OT environments without explicit written authorization. See [`SECURITY.md`](SECURITY.md) and the [Safe Harbor](SECURITY.md#safe-harbor) section.

---

## What it does

IndustrialScanner gives OT/ICS security practitioners a **safe, read-only, automated analysis suite** for the three most common industrial protocols:

| Module | Protocol | Mode | Output |
|---|---|---|---|
| `modbus_scanner` | Modbus/TCP (port 502) | Active read-only probe (coils, inputs, registers) | JSON + HTML |
| `s7_comm_analyzer` | Siemens S7Comm (TPKT/COTP, port 102) | Passive PCAP analysis | JSON + HTML |
| `dnp3_monitor` | DNP3 (TCP/UDP 20000) | Passive PCAP analysis | JSON + HTML |
| `build_*_index.py` | All three | Consolidated dashboard | HTML + Chart.js |

The suite is intentionally split into **report generation** (scanners/analyzers) and **dashboard building** (index builders). Scanners produce per-target reports; index builders aggregate them into executive dashboards.

---

## Why it exists

ICS/OT networks are not regular IT networks. They prioritize **availability and safety** over speed and convenience, and they use specialized protocols that traditional security tooling ignores. A single misconfiguration can halt a substation, a production line, or a water treatment plant.

Commercial ICS/OT tooling (Claroty, Nozomi, Dragos) is excellent but expensive and closed-source. IndustrialScanner closes that gap by giving practitioners, researchers, and educators a transparent, auditable, and free toolkit to understand the security posture of their OT assets.

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/frangelbarrera/industrial-scanner.git
cd IndustrialScanner

# 2. Install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Copy env template (optional for read-only analysis)
cp .env.example .env

# 4. Run a Modbus scan (read-only, safe probes)
industrial-scanner modbus --targets 127.0.0.1 --unit 1
# or
python -m modbus_scanner.modbus_scan --targets 127.0.0.1 --unit 1

# 5. Analyze S7Comm PCAPs (single file)
industrial-scanner s7 --pcap pcaps/s7/step7_s300_stop.pcapng

# 6. Batch-analyze all DNP3 PCAPs in pcaps/dnp3/
python run_dnp3_all.py

# 7. Build consolidated dashboards
python build_s7_index.py        # S7 dashboard
python build_dnp3_index.py      # DNP3 dashboard
python build_global_index.py    # Global executive dashboard
```

Outputs land in `reports/` as HTML dashboards with Chart.js visualizations.

> **Operational tools:** the `tools/` directory is reserved for reviewed
> Wireshark profiles and capture aids. No profiles are published yet; see
> [`tools/README.md`](tools/README.md) instead of assuming they are available.

---

## Repository layout

```text
IndustrialScanner/
├─ modbus_scanner/        # Active read-only Modbus/TCP scanner
│  ├─ modbus_scan.py
│  └─ utils.py
├─ s7_comm_analyzer/      # Passive S7Comm analyzer
│  ├─ s7_analyze.py
│  └─ parsers.py
├─ dnp3_monitor/           # Passive DNP3 analyzer
│  ├─ dnp3_analyze.py
│  └─ parsers.py
├─ ics_scanner/            # Shared security primitives (NEW)
│  ├─ security.py          # HTML escape, target policy, path guards
│  └─ cli.py               # Unified Click+Rich CLI
├─ reports/
│  ├─ modbus_batch/
│  ├─ s7_batch/
│  ├─ dnp3_batch/
│  ├─ templates/           # Jinja2 templates (autoescape on)
│  ├─ modbus_index.html
│  ├─ s7_index.html
│  ├─ dnp3_index.html
│  └─ index.html
├─ tests/                  # pytest + property-based tests (NEW)
├─ tools/                  # Reviewed operator aids (currently reserved)
├─ .github/workflows/      # CI, release, dependency scan (NEW)
├─ pcaps/                  # Sample PCAPs
├─ docs/images/            # Screenshots
├─ cli.py                  # Legacy CLI (kept for compatibility)
├─ build_*.py              # Dashboard builders
├─ pyproject.toml          # Modern packaging (PEP 621)
├─ .pre-commit-config.yaml # Ruff + mypy + bandit hooks
└─ .env.example            # Environment template
```

---

## Unified CLI (new)

The new Click+Rich based CLI lives in `ics_scanner/cli.py`. Install exposes the `industrial-scanner` entry point:

```bash
industrial-scanner modbus --targets 192.168.0.10,192.168.0.11 --unit 1
industrial-scanner s7 --pcap pcaps/s7/step7_s300_stop.pcapng
industrial-scanner dnp3 --pcap pcaps/dnp3/read_and_response.pcap
```

The CLI enforces a **target safety policy**: public IPs are refused by default (use `--allow-public` only after explicit written authorization). This prevents accidental wide-area scanning of legacy PLCs.

---

## Usage by protocol

### Modbus (active, read-only)

```bash
python -m modbus_scanner.modbus_scan --targets 127.0.0.1 --port 502 --unit 1
# or
industrial-scanner modbus --targets 127.0.0.1 --port 502 --unit 1
```

- Issues **only read function codes**: `0x01 Read Coils`, `0x02 Read Discrete Inputs`, `0x03 Read Holding Registers`, `0x04 Read Input Registers`.
- Collects latency, exposure signals (`unauthenticated_read`, `broad_register_access`).
- Outputs JSON + HTML in `reports/modbus_batch/`.

### S7Comm (passive, from PCAPs)

```bash
industrial-scanner s7 --pcap pcaps/s7/step7_s300_stop.pcapng
python -m s7_comm_analyzer.s7_analyze  # batch-process all PCAPs in pcaps/s7/
python build_s7_index.py                # consolidated dashboard with Chart.js
```

- Unwraps **TPKT/COTP framing** (RFC 1006 / ISO 8073) before parsing the S7 PDU.
- **Strict binary parser** per Siemens spec: decodes the S7 header (ROSCTR) and parameter block (function code at offset 10), not heuristic ASCII matching.
- Function classifier: `ReadVar`, `WriteVar`, `Start`, `Stop`, `DownloadBlock`, `UploadBlock`, `CopyRamToRom`, `Password`, `ReadSzl`, plus `SetupComm`, `CpuServices`, `ModeTransition`, `FlashLed` and `AckData` responses.
- Each packet is enriched with **MITRE ATT&CK for ICS** techniques (T0801, T0802, T0816, T0821, T0831, T0836, T0843, T0845, T0858, T0859, T0868, T0888, T0889), validated against the official STIX bundle by `tests/test_mitre_attack_ground_truth.py`.

### DNP3 (passive, from PCAPs)

```bash
industrial-scanner dnp3 --pcap pcaps/dnp3/read_and_response.pcap
python run_dnp3_all.py     # batch-process all PCAPs in pcaps/dnp3/
python build_dnp3_index.py
```

- **Strict binary parser** per IEEE 1815-2012: decodes the link layer (10 bytes), transport layer, and application layer (function code at offset 12).
- Function classifier: `Read`, `Write`, `Select`, `Operate`, `DirectOperate`, `ColdRestart`, `WarmRestart`, `StopApplication`, `DeleteFile`, `EnableUnsolicited`, `AssignClass`, `Authenticate`, and 16 more.
- Each suspect function is flagged and enriched with MITRE ATT&CK for ICS techniques.

### Global executive dashboard

```bash
python build_global_index.py
```

Produces `reports/index.html` with totals and quick links per protocol.

---

## Screenshots

### Demo (animated)

![IndustrialScanner demo](docs/images/dashboard_demo.gif)

*The demo cycles through the global executive dashboard, S7Comm dashboard, DNP3 dashboard, and a per-PCAP DNP3 report showing MITRE ATT&CK mapping in action.*

### Global Executive Dashboard

![Global Dashboard](docs/images/dashboard_global.png)

### S7Comm Dashboard (with Chart.js visualizations)

![S7 Dashboard](docs/images/dashboard_s7.png)

### DNP3 Dashboard (with Chart.js visualizations)

![DNP3 Dashboard](docs/images/dashboard_dnp3.png)

### Per-PCAP report with MITRE ATT&CK enrichment

**S7 individual report** — shows parsed packets with ROSCTR, function code, and hints:
![S7 Report](docs/images/report_s7_detail.png)

**DNP3 individual report** — shows parsed packets with function code, suspect flag, and MITRE techniques:
![DNP3 Report](docs/images/report_dnp3_detail.png)

---

## Test data

The repo bundles:

- **Sample PCAPs** for S7Comm (`.pcapng`) and DNP3 (`.pcap`) under `pcaps/`.
- **ModbusPal.jar**, a third-party Modbus/TCP emulator, for spinning up a local test target. (External dependency; report issues to its upstream project.)

These let you validate the toolkit end-to-end without external infrastructure.

---

## Development

```bash
pip install -e ".[dev]"
pre-commit install
pytest
ruff check .
mypy modbus_scanner s7_comm_analyzer dnp3_monitor ics_scanner
```

### CI/CD

The repo ships five GitHub Actions workflows under `.github/workflows/`:

| Workflow | Purpose |
|---|---|
| `ci.yml` | Lint (ruff), type-check (mypy), tests (3.11/3.12/3.13), security-scan (bandit + pip-audit + semgrep + CodeQL), build |
| `release.yml` | On tag `v*`, publish to PyPI + GitHub Release |
| `dependency-scan.yml` | Daily `pip-audit` of pinned dependencies |

### Conventions

- **Style**: Ruff (line-length 100, pyupgrade, bugbear, simplify, security).
- **Types**: strict mypy on `modbus_scanner`, `s7_comm_analyzer`, `dnp3_monitor`, `ics_scanner`.
- **Tests**: pytest + hypothesis for fuzz testing of parsers.
- **Commits**: conventional-commits style (`feat:`, `fix:`, `sec:`, `docs:`, `ci:`).
- **Versioning**: Semantic Versioning 2.0.0.

---

## Security

See [`SECURITY.md`](SECURITY.md) for the full policy, supported versions, vulnerability reporting flow, Safe Harbor, and known security considerations.

Key highlights:

- **Read-only by design**: Modbus scanner issues only `0x01`–`0x04` function codes.
- **Target safety policy**: public IPs are refused by default (`--allow-public` requires explicit opt-in).
- **HTML/JSON output escaping**: all untrusted PCAP bytes are escaped via `ics_scanner.security.html_escape()` or Jinja2 `autoescape=True`.
- **No write/control primitives** for S7Comm or DNP3.
- **No telemetry / no outbound calls**: the tool runs entirely offline.

---

## Compliance references

IndustrialScanner is positioned against the following standards (see [`docs/compliance.md`](docs/compliance.md) for the full gap analysis):

- **IEC 62443** (industrial automation and control systems security)
- **NIST SP 800-82 Rev 3** (Guide to Operational Technology (OT) Security)
- **NERC CIP** (Critical Infrastructure Protection)
- **ISO/IEC 27019** (Energy utility industry security)

The tool is **not** compliance-certified and does not replace a formal audit, but its outputs can feed an audit evidence portfolio.

For a practical workflow covering zones, conduits, target security levels, and asset-owner evidence, see the [IEC 62443 zones and conduits guide](docs/62443-zones-conduits.md).

---

## Roadmap

| Quarter | Theme | Highlights |
|---|---|---|
| Q1 | Stabilization | Strict parsers (per IEEE 1815 / IEC 61131), type hints everywhere, 80%+ coverage |
| Q2 | Security hardening | DNP3 SA v5, Modbus/TCP TLS (RFC 9441), SBOM generation, signed releases |
| Q3 | Architecture | Plugin system for new protocols (PROFINET, EtherNet/IP, IEC 61850), async I/O |
| Q4 | Ecosystem | PyPI release, Docker image, MkDocs site, community Discord, S4 / Black Hat ICS talks |

---

## A note on language composition

GitHub's language breakdown shows a high HTML percentage because the tool generates HTML dashboards. The actual application logic is entirely Python — see `modbus_scanner/`, `s7_comm_analyzer/`, `dnp3_monitor/`, and `ics_scanner/`.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Contributing

PRs welcome. Please read [`SECURITY.md`](SECURITY.md) first, run `pre-commit install`, and ensure all CI checks pass before requesting review.

For larger changes, open an issue first to discuss the design.

---

## Acknowledgements

Built on the shoulders of giants:

- [scapy](https://github.com/secdev/scapy) — packet manipulation
- [pymodbus](https://github.com/pymodbus-dev/pymodbus) — Modbus implementation
- [Jinja2](https://github.com/pallets/jinja) — HTML templating
- [ModbusPal](https://modbuspal.sourceforge.net/) — Modbus emulator
- [snap7](https://snap7.sourceforge.net/) — Siemens S7 reference
- The broader ICS-CERT, SANS ICS, and Dragos research communities

Maintained by **Frangel Raúl Crespo Barrera** — [`frangelbarrera`](https://github.com/frangelbarrera).
