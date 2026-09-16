# IndustrialScanner

**Read-only security analyzer for Industrial Control Systems (ICS) / Operational Technology (OT).**

IndustrialScanner is an open-source toolkit for analyzing industrial network
traffic from three of the most common ICS/OT protocols:

- **Modbus/TCP** (port 502) — active read-only probing
- **Siemens S7Comm** (TCP/102) — passive PCAP analysis with TPKT/COTP unwrapping
- **DNP3** (TCP/UDP 20000) — passive PCAP analysis per IEEE 1815-2012

The tool is designed for auditors, researchers, and educators working on
ICS/OT security. It is **read-only by design**: the Modbus scanner issues only
function codes 0x01–0x04, and the S7/DNP3 analyzers operate on captured PCAP
files without sending any traffic.

## Key features

- **Strict binary parsers** (not heuristic ASCII matching) per IEEE 1815-2012
  and Siemens S7Comm spec, including TPKT/COTP unwrapping
- **MITRE ATT&CK for ICS mapping** — every suspect function is mapped to
  MITRE techniques (T0801, T0808, T0848, T0858, T0859, T0879, T0885, T0894, …)
- **Plugin system** — add new protocols via setuptools entry points
- **Service layer** — clean orchestration between CLI and protocol modules
- **HTML/JSON reports** with XSS-safe autoescaping
- **Executive dashboards** with Chart.js visualizations
- **Target safety policy** — public IPs refused without explicit opt-in
- **62443 assessment aid** — zones/conduits register and evidence workflow, without making compliance claims

## Quickstart

```bash
# Install
pip install industrial-scanner

# Run a Modbus scan (read-only, safe probes)
industrial-scanner modbus --targets 127.0.0.1 --unit 1

# Analyze a PCAP
industrial-scanner s7 --pcap capture.pcapng
industrial-scanner dnp3 --pcap capture.pcap
```

See the [Quickstart guide](quickstart.md) for the full workflow.

## Documentation

- [Quickstart](quickstart.md)
- [Protocol guides](protocols/modbus.md)
- [MITRE ATT&CK mapping](mitre-attack.md)
- [Architecture](architecture.md)
- [IEC 62443 zones and conduits](62443-zones-conduits.md) for a corporate assessment and evidence workflow
- [Security policy](security.md)
- [Contributing](contributing.md)
