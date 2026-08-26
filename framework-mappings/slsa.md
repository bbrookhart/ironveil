# SLSA v1.2 assessment

IRONVEIL does not self-award a SLSA level. The local lab emits SLSA-shaped provenance and validates
subject, source, builder, repository, and workflow identity. Hosted build-platform properties and
GitHub repository controls require independent evidence.

| Track requirement | Status | Evidence | Gap |
|---|---|---|---|
| Source is version controlled | PARTIAL | `EV-SOURCE-001` | Synthetic until repository evidence is captured |
| Source history and provenance | PARTIAL | Source revision + review object | GitHub attestation not captured |
| Two-party review | NOT_VERIFIED | Local policy test | Branch protection is not API-verified |
| Build provenance exists | VERIFIED | `EV-PROV-001` | Applies to the synthetic lab artifact |
| Authenticated hosted provenance | NOT_VERIFIED | None | Local signer is test-only |
| Hardened build platform | NOT_VERIFIED | None | No Build L3 claim |

