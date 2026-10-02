**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** scanner target selection, rate/concurrency controls, report handling, and OT assessment claims.

| Field | Current record |
|---|---|
| Status | Policy documented; enforcement evidence remains in existing scanner code and tests. |
| Evidence | `tests/test_security.py`, `tests/test_hardening.py`, `tests/test_mitre_attack.py`, `docs/62443-zones-conduits.md`, `docs/compliance.md`, `docs/mitre-attack.md`. |
| Standards | IEC 62443 references in repository docs; NIST SP 800-82 Rev. 3 and MITRE ATT&CK for ICS are references, not certifications. Exact benchmark revisions are not centrally pinned in this policy. |
| Verification | `pytest -q`; review `dependency-scan.yml`; inspect target validation before an authorized engagement. |
| Limitations | This page does not prove safe behavior against every network target or establish compliance. |

Use scanners only against assets owned by the operator or explicitly authorized in writing. The default operating mode should be read-only, use laboratory allowlists, reject public or out-of-scope targets, and enforce rate and concurrency limits. Reports may contain topology, credentials, or operational details; redact, restrict, retain, and delete them according to the engagement record.
