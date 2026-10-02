# Safe target policy

Use scanners only against assets owned by the operator or explicitly authorized in writing. The default operating mode is read-only and should reject public or out-of-scope targets. Laboratory allowlists, rate limits, concurrency limits, and an explicit exception process must be defined before active scanning.

Reports may contain network topology, credentials, or operational details. Store them with least privilege, redact sensitive values before sharing, and define retention and cleanup. IEC 62443, NIST SP 800-82, and MITRE ATT&CK for ICS are reference frameworks for scoped assessment, not certifications provided by this repository.
