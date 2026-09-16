# Operational tools

This directory is reserved for reviewed, versioned operator aids that complement
IndustrialScanner without changing its read-only analysis behavior.

## Current status

No Wireshark profiles or capture utilities are published here yet, and no
artifacts in this directory should be assumed to exist. The directory is kept
intentionally explicit so that documentation never implies that operational
aids are already available.

## Publication criteria

Future additions should be:

- passive by default, and clearly labeled when a setting can affect capture behavior;
- accompanied by provenance, version, and license information, plus a short usage note;
- validated against the sample PCAPs in this repository;
- reviewed for accidental transmission, active probing, or any unsafe behavior;
- treated as supporting material, not as a replacement for the authorization and
  chain-of-custody procedures in [`SECURITY.md`](../SECURITY.md).

Until reviewed artifacts are published here, use a separately approved
Wireshark profile and follow your organization's receive-only capture
procedure.
