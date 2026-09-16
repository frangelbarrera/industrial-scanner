# IEC 62443: zones, conduits, and security-program evidence

IndustrialScanner can support an OT security assessment, but it is not a
compliance engine or a certification tool. This guide defines the smallest
repeatable workflow for using its evidence in an operator's security program.

> **Scope statement.** [IEC 62443-3-2:2020](https://webstore.iec.ch/en/publication/30727)
> defines a risk-assessment approach for system design, including zones,
> conduits, and target security levels. [IEC 62443-2-1:2024](https://webstore.iec.ch/en/publication/62883)
> defines asset-owner security-program requirements. IndustrialScanner
> contributes technical observations; the asset owner remains responsible for
> the assessment, risk decisions, approvals, and operational controls. See the
> [ISA/IEC 62443 series overview](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series)
> for the official structure of the series.

## Recommended operating model

Use a **System Under Consideration (SUC)** for one bounded plant, process, or
operational service. Keep the assessment versioned and assign an accountable
asset owner. Do not use a single global diagram for unrelated plants or safety
functions.

| Phase | Required outcome | IndustrialScanner contribution | Owner decision |
|---|---|---|---|
| 1. Establish context | SUC boundary, safety/availability constraints, approved scope, evidence owner | Record capture scope and report provenance | Approve scope and rules of engagement |
| 2. Inventory and model | Asset inventory, observed communications, trust boundaries | Identify observed Modbus/TCP, S7Comm, and DNP3 communications from approved PCAPs | Confirm asset ownership, criticality, and functional grouping |
| 3. Partition into zones and conduits | Zone and conduit candidates with boundaries and allowed flows | Provide observed endpoints and flows as grouping input | Approve the partition and boundary definitions |
| 4. Assess risk | Threat scenarios, consequences, likelihood, unmitigated and mitigated risk | Highlight observed read/write/control-like functions and ATT&CK for ICS context | Accept, treat, transfer, or reject each risk |
| 5. Set requirements | SL-T per zone/conduit and security-requirements traceability | Provide evidence references for observed exposure | Approve target levels and compensating measures |
| 6. Treat and verify | Approved remediation plan, residual risk, exceptions, review date | Re-run passive analysis or authorized read-only checks as evidence | Validate effectiveness without disrupting operations |

## Zone and conduit register

Maintain this register as the authoritative assessment artifact. A report is
an input to the register, not a substitute for it.

| ID | Type | Boundary / members | Critical function | Trust assumptions | Allowed protocols and flows | SL-T | Evidence / owner |
|---|---|---|---|---|---|---|---|
| Z-001 | Zone | Example: PLC cell A | Closed-loop control | Cell devices are managed by the OT team | S7Comm from the approved engineering station | To be assessed | Asset owner / evidence ID |
| C-001 | Conduit | Example: cell A to supervisory zone | Supervisory exchange | The firewall is the enforcement point | Explicitly approved S7Comm flows | To be assessed | Network owner / rule ID |

**Rules for a defensible register:**

1. Give every zone and conduit a stable ID; never rely only on a diagram label.
2. Define boundaries by function, trust, and consequence, not merely by subnet
   or VLAN. Document safety-related systems and their interfaces separately.
3. Record direction, endpoints, protocol, ports, and business purpose for every
   conduit. "Any/any" is a finding, not a description.
4. Link each important assertion to evidence with a timestamp, capture
   identity, parser version, and reviewer. Preserve the original PCAP and its
   hash under the site's evidence procedure.
5. Mark unknowns explicitly. Do not infer that an asset is absent because it
   did not appear in one capture.

## Evidence workflow with IndustrialScanner

1. Obtain written authorization, define a maintenance-safe window, and select
   a passive collection point. For live OT collection, use a receive-only
   mirror path and document the interface state and the proof that no packet
   was sent into the plant network.
2. Analyze approved captures with the relevant passive analyzer. The Modbus
   command is an active read-only probe and must be treated separately under
   the site's rules of engagement; it is not a replacement for passive
   collection.
3. Store the generated JSON as the machine-readable evidence record and
   retain the HTML report for human review. Record the command line, tool
   version, capture hash, analyst, UTC timestamps, and limitations.
4. Map observed endpoints and flows into the zone/conduit register. Treat
   protocol observations as supporting evidence: they do not prove complete
   inventory, permitted business purpose, or absence of risk.
5. Review suspect operations with the process owner. ATT&CK for ICS mappings
   are useful context, but they are not a severity decision and do not replace
   the site's consequence analysis.
6. Repeat after approved changes and compare the register, evidence
   identifiers, and residual-risk decisions. Retain superseded versions rather
   than editing history in place.

## Relation to an IEC 62443-2-1 asset-owner program

The assessment becomes corporate practice only when it is connected to an
asset-owner program. At minimum, define and approve:

- accountable roles for asset ownership, cybersecurity, network operations,
  engineering, safety, and change control;
- a controlled inventory and architecture-document lifecycle;
- rules of engagement for passive collection and any read-only active test;
- risk-acceptance, exception-expiry, compensating-control, and revalidation
  procedures;
- incident handling, vulnerability and patch decisions, backup and recovery,
  and supplier access expectations;
- training, records retention, and a review cadence tied to process or network
  changes.

This list is a practical planning aid, not a claim that the tool satisfies any
requirement of IEC 62443-2-1.

## Definition of done

A review is ready to be presented for governance or risk-committee sign-off
when the SUC boundary is approved, the zone/conduit register has no
unexplained critical unknowns, every high-impact flow has an owner and an
evidence reference, SL-T decisions are documented, and residual risks have an
accepted treatment or an accountable exception with an expiry date.

## Related references

- [IEC 62443 series overview (ISA)](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series)
- [Compliance references and gap analysis](compliance.md)
- [Security policy and safe harbor](security.md)
- [Quickstart](quickstart.md)
