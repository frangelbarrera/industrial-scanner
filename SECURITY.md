# Security Policy — IndustrialScanner

IndustrialScanner is a Python toolkit for **passive analysis of ICS/OT
traffic** (Siemens S7Comm over TCP/102, DNP3 over TCP-UDP/20000) and
**read-only active probing** of Modbus/TCP devices (port 502). It is
designed for auditors, researchers, and educators working on industrial
control systems security.

The project is **actively maintained**. Security reports are welcomed and
will be triaged and patched.

---

## Supported Versions

| Version | Supported   | Notes                                            |
|---------|-------------|--------------------------------------------------|
| `main`  | Yes         | Active development branch.                       |
| tags    | Best effort | Tagged releases receive fixes via new tags.      |

If you need a fix backported to an older tag, please open an issue describing
the version and the CVE/finding.

---

## Reporting a Vulnerability

Please report security issues **privately** before any public disclosure:

- **Email:** `frangelrcbarrera@gmail.com`
- **Subject prefix:** `[SECURITY] IndustrialScanner — <short summary>`

Include in the report:

1. Affected file(s) and line numbers (e.g., `s7_comm_analyzer/parsers.py:42`).
2. A minimal reproduction (PoC) or PCAP snippet if applicable.
3. Impact assessment and the affected protocol(s): Modbus, S7Comm, DNP3.
4. Your suggested mitigation, if any.
5. Whether you intend to publish the finding, and your preferred timeline.

**Do not open public GitHub issues for security reports.**

---

## Response Timeline

| Step                              | Target                |
|-----------------------------------|-----------------------|
| Acknowledgement of receipt        | ≤ 5 business days     |
| Initial triage & severity rating  | ≤ 10 business days    |
| Coordinated disclosure discussion | ≤ 30 calendar days    |
| Public advisory (if accepted)     | Mutually agreed date  |

The maintainer operates this project on a personal, part-time basis. The
above targets are best-effort; researchers will be kept informed if delays
occur.

---

## Scope

### In scope

- The Python source tree under `modbus_scanner/`, `s7_comm_analyzer/`,
  `dnp3_monitor/`, and `ics_scanner/`.
- The Jinja2 HTML templates under `reports/templates/`.
- Parsing of untrusted PCAP/PCAPNG files via `scapy.rdpcap`.
- HTML/JSON report generation from PCAP-derived or Modbus-derived data.
- The CLI entry points declared in `pyproject.toml`.
- The CI/CD workflows under `.github/workflows/`.
- The `Dockerfile` and the published Docker image on GHCR.

### Out of scope

- The committed sample PCAPs under `pcaps/` (public ICS training captures,
  anonymized; not part of the tool's runtime).
- `ModbusPal.jar`, an unrelated third-party Modbus emulator bundled for
  convenience — report issues to its upstream project.
- Vulnerabilities in dependencies (`pymodbus`, `scapy`, `Jinja2`,
  `pydantic`) — please report them to their respective maintainers via
  their CVE/CSAF channels.
- Self-XSS requiring the attacker to already control the auditor's machine.

---

## Safe Harbor

Good-faith security research on **systems you own or are explicitly
authorized to test** is welcomed. The maintainer will not pursue civil or
criminal action against researchers who:

- Respect the in-scope/out-of-scope boundaries above.
- Avoid disruption to live ICS/OT environments, including production PLCs,
  RTUs, HMIs, or SCADA hosts.
- Do not access, exfiltrate, or destroy data that does not belong to them.
- Provide reasonable time for acknowledgement before public disclosure.
- Refrain from leveraging findings for extortion, ransom, or competitive gain.

Researchers who wish to validate findings against ICS protocols are strongly
encouraged to use isolated lab setups such as ModbusPal, snap7, OpenPLC, or
the sample PCAPs bundled with this repository.

---

## Legal Framework

This policy is informed by widely recognized international instruments and
national computer-misuse statutes. Researchers are responsible for
understanding and complying with the laws of their jurisdiction.

- **Council of Europe Convention on Cybercrime (Budapest Convention, 2001)**
  — Articles 2, 3, and 5 on illegal access, system interference, and the
  interference with data; Article 15 on safeguards for legitimate research.
- **United States — Computer Fraud and Abuse Act (18 U.S.C. § 1030)**,
  particularly the research and good-faith limitations recognized in
  recent DOJ guidelines.
- **European Union — Directive 2013/40/EU** on attacks against information
  systems.

Nothing in this policy overrides statutory obligations; it only expresses
the maintainer's intent **not to refer for prosecution** reports that
comply with this Safe Harbor.

---

## Security Features

IndustrialScanner implements the following security features:

### Read-only by design

- The Modbus scanner issues **only** function codes `0x01 Read Coils`,
  `0x02 Read Discrete Inputs`, `0x03 Read Holding Registers`,
  `0x04 Read Input Registers`. Write/control codes (`0x05`, `0x06`,
  `0x0F`, `0x10`, etc.) are **never** issued.
- S7Comm and DNP3 analyzers operate on captured PCAP files only — they
  send **no traffic** to the network.

### Target safety policy

- The CLI enforces a target safety policy: public IPs are refused by default.
  Pass `--allow-public` only after explicit written authorization from the
  asset owner.
- CIDR scans are limited to `/24` (256 hosts) by default.
- Path traversal is blocked for user-supplied output filenames via
  `ics_scanner.security.safe_join_path`.

### HTML/JSON output safety

- All HTML reports use **Jinja2 with `autoescape=True`** or
  `markupsafe.escape()` on every untrusted field. This prevents stored XSS
  from malicious PCAPs.
- Index builders (`build_*.py`) use `html.escape()` on every untrusted
  field.
- A regression test (`tests/test_xss_regression.py`) verifies that
  `<script>` tags in PCAP-derived fields are escaped.

### Strict protocol parsing

- S7Comm parser uses **binary decoding** per the Siemens spec (TPKT/COTP
  unwrapping + S7 header + parameter block) with no string-based guessing.
- DNP3 parser uses **binary decoding** per IEEE 1815-2012 (link layer +
  transport + application layer) with no pattern matching on payload bytes.
- Property-based fuzz testing with Hypothesis verifies that the parsers
  never crash on arbitrary input.

### CI/CD security

- **Bandit** static analysis runs on every push and PR (0 HIGH findings
  accepted; LOW findings are reviewed).
- **pip-audit** scans dependencies for known CVEs on every push and daily.
- **Semgrep** runs OWASP Top 10 + Python rulesets.
- **CodeQL** semantic analysis runs on every push.

### No telemetry, no outbound calls

IndustrialScanner runs entirely offline. It does not:
- Phone home
- Send usage statistics
- Download updates
- Connect to any external service

All processing is local. The only network connections are the ones you
initiate via the Modbus scanner.

---

## Known Security Considerations

- **S7Comm-Plus** (firmware ≥ V3.0 on S7-1200/1500) uses encrypted X3.1324
  framing and is **not** supported. The analyzer returns `NonS7Payload`
  for these frames.
- **DNP3 Secure Authentication v5 (SA v5)** is detected (function `0x1D`)
  but the challenge-response is not validated. SA v5 is mandatory for
  IEC 62443 SL 3+ compliance. (Roadmap: Q2 2026.)
- **Modbus/TCP TLS (RFC 9441)** is not yet implemented. Modbus traffic is
  sent in plaintext. (Roadmap: Q2 2026.)
- **Sample PCAPs** in `pcaps/` have been anonymized (public IPs replaced
  with synthetic 10.x.x.x addresses), but may still contain MAC addresses
  from lab equipment. Treat them as public artifacts.

---

## Contact

- **Maintainer:** Frangel Barrera
- **Email:** `frangelrcbarrera@gmail.com`
- **GitHub:** [`frangelbarrera/industrial-scanner`](https://github.com/frangelbarrera/industrial-scanner)

For non-security questions, please open a regular GitHub issue.

---

*This policy is versioned with the repository.*
