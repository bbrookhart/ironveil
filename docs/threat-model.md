# Threat model

## Scope

IRONVEIL evaluates unauthorized movement of a synthetic software/firmware artifact from source through
installation. The attacker may control an individual source, build, signing, distribution, or update
component, but the configured verifier, policy, trust root, device inventory, and clock remain trusted.

| Threat | Objective | IRONVEIL treatment | Scenario |
|---|---|---|---|
| Unauthorized source | Release unapproved revision | Detect/Prevent through source policy | SCN-002 |
| Review bypass | Eliminate independent approval | Detect/Prevent | SCN-003 |
| Repository control drift | Weaken branch/status controls | Detect when evidence says false; live state out of scope | SCN-002/003 |
| Dependency substitution | Insert unexpected component | Detect/Prevent against ground truth | SCN-007 |
| Build compromise | Use unexpected builder or workflow | Detect/Prevent | SCN-006/020 |
| Build-input substitution | Mismatch source/configuration | Detect through provenance equality | SCN-005/020 |
| Artifact substitution | Replace output after build | Detect/Prevent by digest | SCN-004 |
| Provenance replay | Attach evidence for another subject | Detect/Prevent by subject digest | SCN-005 |
| Unauthorized signer | Present valid crypto from wrong identity | Detect/Prevent by trust and identity | SCN-009 |
| Private-key compromise | Misuse a trusted local key | Limit through release/target policy; root compromise out of scope | BROKEN SEAL |
| Registry substitution | Move mutable tag or object | Detect/Prevent by observed digest | SCN-010 |
| Metadata replay/freeze | Serve stale formerly valid state | Detect on expiry; availability out of scope | SCN-011 |
| Rollback | Install an older release | Prevent unless explicit recovery | SCN-012/016 |
| Wrong target | Send valid artifact to other device group | Prevent by dual target binding | SCN-013 |
| Online role compromise | Misuse non-root update role | Limit/Detect through role status and release evidence | SCN-014 |
| SBOM manipulation | Misrepresent composition | Detect against synthetic ground truth | SCN-008 |
| Vulnerability evidence tampering | Hide or alter findings | Detect through signed envelope and manifest | SCN-019 |
| Known vulnerable dependency | Release affected critical finding | Prevent through security gate | SCN-018 |
| CI identity drift | Use unexpected workflow/ref | Detect/Prevent by exact identity | SCN-020 |
| Failed release | New artifact fails health check | Recover through explicit last-known-good authorization | SCN-016 |

## Out of scope

Compromise of the verifier or policy engine, trusted public root, authoritative device state, trusted
clock, host kernel, Python runtime, or root filesystem is not addressed. Availability attacks can stop
updates. The model does not inspect source intent, prove freedom from vulnerabilities, exploit real
systems, or establish hardware authenticity.

