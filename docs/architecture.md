# Architecture

IRONVEIL separates evidence production from the decision to trust evidence. The local research path
is source fixture → deterministic builder → artifact → provenance/SBOM/security evidence → evidence
envelope signature → release authorization → target gate → installed-state reconciliation.

## Components

| Component | Responsibility | Trust boundary |
|---|---|---|
| `ironveil.lab` | deterministic fixture build and evidence construction | BUILD |
| `ironveil.signing.local` | offline test signing and signature verification | SIGNING |
| `ironveil.policy.engine` | fail-closed release decision | RELEASE |
| `ironveil.sbom.verify` | schema/binding and ground-truth measurement | AUDIT |
| `ironveil.evaluation.scenarios` | controlled adversarial mutations and metrics | AUDIT |
| `ironveil.graph.lineage` | provenance trace and blast-radius queries | AUDIT |
| `DeviceState` | target inventory and installed state | TARGET |

## Data flow

All evidence objects bind to an immutable artifact digest. A signature covers an evidence-envelope
digest rather than only a filename. The independent release authorization binds artifact, source,
required evidence, expiry, and target group. The target gate checks metadata freshness and version
before installation; post-install verification compares observed and intended state.

## External integration boundaries

OCI Registry is optional and isolated to a Docker Compose profile. Hosted Sigstore signing,
transparency inclusion, production TUF, live GitHub source-control evidence, and hardware measurement
are not part of the default v0.1 trust path and are not claimed.

