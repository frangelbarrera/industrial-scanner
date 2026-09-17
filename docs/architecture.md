# Architecture

IndustrialScanner is organized as a layered application:

```
┌─────────────────────────────────────────────┐
│  CLI layer (ics_scanner/cli.py)              │
│  Click + Rich, target safety policy          │
└─────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────┐
│  Service layer (ics_scanner/services.py)     │
│  Orchestration: scan, analyze, dashboard      │
└─────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────┐
│  Protocol adapters                            │
│  modbus_scanner/  s7_comm_analyzer/  dnp3_monitor/  │
└─────────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────────┐
│  Shared primitives (ics_scanner/)             │
│  security  mitre_attack  plugins  reporting  │
└─────────────────────────────────────────────┘
```

## Layers

### CLI layer

`ics_scanner/cli.py` exposes a Click-based CLI with three subcommands:
`modbus`, `s7`, `dnp3`. It enforces the target safety policy (public IPs
refused without `--allow-public`).

### Service layer

`ics_scanner/services.py` provides three orchestration functions:

- `scan_modbus_service`: target expansion + safety filter + scan + MITRE enrichment
- `analyze_pcap_service`: PCAP analysis + MITRE enrichment (single entry for S7/DNP3)
- `build_dashboard_service`: dashboard HTML generation for any protocol

The service layer decouples the CLI from the protocol modules, making
both easier to test.

### Protocol adapters

Each protocol has its own package:

- `modbus_scanner/` — active read-only Modbus/TCP scanner (function codes 0x01–0x04)
- `s7_comm_analyzer/` — passive S7Comm parser with TPKT/COTP unwrapping
- `dnp3_monitor/` — passive DNP3 parser per IEEE 1815-2012

### Shared primitives

`ics_scanner/` contains cross-cutting concerns:

- `security.py` — HTML escape, target safety, path traversal guards
- `mitre_attack.py` — MITRE ATT&CK for ICS technique mapping
- `plugins.py` — protocol parser plugin registry via setuptools entry points

## Plugin system

Third-party packages can add new protocol parsers by registering an entry
point in their `pyproject.toml`:

```toml
[project.entry-points."industrial_scanner.parsers"]
profinet = "my_package.profinet_parser:ProfinetParser"
```

The parser must implement the `ProtocolParser` protocol from
`ics_scanner.plugins`:

```python
class ProtocolParser(Protocol):
    @property
    def protocol_name(self) -> str: ...
    def can_parse(self, packet: Any) -> bool: ...
    def parse(self, packet: Any) -> Optional[Dict[str, Any]]: ...
```

## Testing strategy

- **Unit tests** (pytest): cover parsers, security primitives, services and
  MITRE mapping
- **Property-based tests** (Hypothesis): generated inputs check parser
  invariants (never crashes, deterministic, field preservation)
- **Snapshot tests**: 6 HTML baselines for the 4 dashboard builders
- **Coverage**: 80% minimum enforced on every full run

## CI/CD pipeline

GitHub Actions workflows run on every push and PR:

- `ci.yml` — lint (ruff) + typecheck (mypy) + test (matrix Python 3.11/3.12/3.13)
  + security-scan (bandit + pip-audit + semgrep + CodeQL) + build (wheel + sdist)
- `dependency-scan.yml` — daily pip-audit of dependencies
- `docs.yml` — deploys MkDocs site to GitHub Pages on docs/ changes
- `docker.yml` — builds Docker image and pushes to GHCR

Tags matching `v*` trigger the `release.yml` workflow: PyPI publication and a
GitHub Release with generated notes.
