# SLSA v1.2 claims assessment

| Track | Requirement | Status | Evidence | Gap |
|---|---|---|---|---|
| Source | Version controlled | PARTIAL | repository + revision evidence | Synthetic local object |
| Source | History/provenance | PARTIAL | revision and reviewer chain | No GitHub source attestation |
| Source | Continuous controls | NOT_VERIFIED | local policy only | Live controls not captured |
| Source | Two-party review | NOT_VERIFIED | SCN-003 behavior | Branch policy is not proof |
| Build | Provenance exists | VERIFIED IN MODEL | `EV-PROV-001` | Applies only to synthetic build |
| Build | Hosted authenticated provenance | NOT_VERIFIED | none | Local signer only |
| Build | Hardened build platform | NOT_VERIFIED | none | No Build L3 claim |

IRONVEIL does not aggregate these rows into a self-awarded SLSA level.

