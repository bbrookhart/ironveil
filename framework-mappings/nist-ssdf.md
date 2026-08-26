# NIST SSDF mapping

Baseline: NIST SP 800-218 / SSDF 1.1 (final). SP 800-218 Rev. 1 / SSDF 1.2 is tracked as draft.

| Practice | IRONVEIL implementation |
|---|---|
| PO.1 | Versioned policy, standards registry, ADRs, and assurance assumptions |
| PO.3 | Release roles separated across source, build, signing, release, target, and audit domains |
| PS.1 | Test-only private keys remain outside Git; hosted mode favors short-lived identity |
| PS.2 | Digest-bound provenance, SBOM, signature envelope, and evidence manifest |
| PW.4 | Locked, explicit synthetic dependency ground truth and deterministic build inputs |
| PW.7 | Unit, property, scenario, policy, architecture, and integration tests |
| PW.8 | Evidence package retains build, composition, test, signing, release, and update records |
| RV.1 | Dependency-to-device and mission-function impact query |
| RV.3 | Target-bound recall scope and last-known-good recovery model |

This is a control mapping, not NIST certification.

