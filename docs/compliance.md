# Compliance References & Gap Analysis

IndustrialScanner is a research and educational tool for passive ICS protocol
analysis. It is **not** compliance-certified and does not replace a formal
audit. This page maps where its capabilities align with common OT security
standards — and, just as importantly, where the gaps are — so that anyone
evaluating the tool knows exactly what it does and does not provide.

## Positioning summary

| Standard | Relationship | What the tool provides |
|---|---|---|
| **MITRE ATT&CK for ICS** | Direct mapping | Suspect protocol functions are enriched with ATT&CK for ICS techniques. The catalog is validated against the official STIX bundle in CI (`tests/test_mitre_attack_ground_truth.py`). |
| **NIST SP 800-82 Rev. 3** | Partial support (detection aid) | Passive PCAP analysis of Modbus/TCP, S7Comm and DNP3 can feed the network-monitoring evidence expected for OT security programs. It is a point tool, not a monitoring platform. |
| **IEC 62443** | Assessment aid only | The [zones/conduits guide](62443-zones-conduits.md) provides a practical register and evidence workflow informed by 62443-3-2 and 2-1. The tool implements no 62443 requirements and performs no certification testing. |
| **NERC CIP** | Reference only | Report outputs (JSON/HTML, per-PCAP evidence) can contribute to an audit evidence portfolio (e.g. CIP-010 configuration monitoring), but the tool itself satisfies no CIP requirement. |
| **ISO/IEC 27019** | Reference only | Same as above: outputs may inform energy-utility security reviews; the tool makes no certification claim. |

## Known gaps

Honest limitations of the current implementation:

- **Passive scope only for S7Comm/DNP3.** The Modbus scanner is active but
  strictly read-only (function codes `0x01`–`0x04`). There are no write or
  control primitives for any protocol.
- **No continuous monitoring.** Analysis is batch-oriented (per PCAP file);
  there is no live capture, streaming detection, or alerting pipeline.
- **No asset inventory or profiling.** The tool classifies protocol functions,
  not devices; it does not build a passive asset baseline.
- **Protocol coverage is deliberately narrow.** S7Comm (classic), Modbus/TCP
  and DNP3 only. No S7Comm-Plus (`0x72`), PROFINET, EtherNet/IP or IEC 61850.
- **No TCP reassembly.** Frames split across TCP segments (or several TPKT
  PDUs coalesced into one segment) are not reassembled; analysis is
  per-segment. S7 PDUs larger than one MSS (e.g. S7-1500, PDU 1920) may be
  under-counted.
- **Userdata sub-function coverage is partial.** Password, ReadSZL and Flash
  LED commands are decoded; other programming commands (variable-table
  transfers, block info, mode transitions) are reported with the generic
  `Userdata` label.
- **Target safety policy covers the CLI entry point.** The service layer and
  CLI filter public targets; scripts that import the Modbus scanner directly
  bypass that filter and are the operator's responsibility.
- **Reports are evidence, not attestations.** Generated JSON/HTML reports
  document what was observed in the analyzed captures and carry no compliance
  status.

## Using the tool in an audit context

The intended role is narrow and concrete: produce repeatable, structured
evidence of which ICS protocol operations appear in a capture, with MITRE
ATT&CK for ICS attribution for suspect functions. Feed those outputs into
your audit workflow; do not treat running the tool as fulfilling any control
by itself.
