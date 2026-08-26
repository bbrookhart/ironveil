# Assurance case

## C-ART-001 — Installed artifacts trace to authorized source

**Claim.** Under the v0.1 trust model, an artifact authorized for protected installation is bound to an
approved source revision.

**Argument.** The observed artifact digest must equal the release artifact digest. Build provenance
must name that digest as its subject and identify the approved source revision. Source evidence must
satisfy repository, branch, reviewer, and status-check policy. The evidence envelope signature and
root manifest detect post-signing or post-package changes.

**Evidence.** `EV-SOURCE-001`, `EV-PROV-001`, `EV-SIGN-001`, `EV-MANIFEST-001`, SCN-002, SCN-004,
SCN-005, and SCN-020.

**Assumptions.** The verifier, policy, public trust root, filesystem, and source evidence issuer remain
trustworthy. Source evidence is synthetic and does not establish live GitHub controls.

## C-SIGN-001 — Valid but unauthorized signatures do not release artifacts

**Claim.** Cryptographic validity from an unexpected signer or issuer is insufficient for protected
deployment.

**Argument.** Full verification requires cryptography, configured public key, exact signer and issuer,
independent release authorization, and target policy.

**Evidence.** `INV-002`, SCN-009, and OPERATION BROKEN SEAL.

## C-TARGET-001 — Releases are target- and version-bound

**Claim.** An artifact valid for one target group or version cannot install on an unauthorized target
or as an unapproved rollback.

**Argument.** Release authorization and update metadata independently name the target group. Device
policy checks hardware model, minimum version, installed version, maintenance state, expiry, and
explicit recovery status.

**Evidence.** SCN-011, SCN-012, SCN-013, SCN-014, SCN-015, and SCN-016.

## C-COMP-001 — Declared composition is measured against known truth

**Claim.** For the included VEILNODE fixture, composition divergence is detected.

**Argument.** The SBOM is digest-bound and compared to an explicit component/PURL ground-truth set;
precision and recall must both equal 1.0.

**Evidence.** `EV-SBOM-001`, `standards/dependency-ground-truth.json`, SCN-007, and SCN-008.

## Attack → control → evidence matrix

| Threat | Control | Verification | Test | Evidence |
|---|---|---|---|---|
| Artifact substitution | Digest-bound artifact identity | observed = expected | SCN-004 | `INV-001.artifact-digest` |
| Provenance replay | Subject digest binding | subject = artifact | SCN-005 | `EV-PROV-001` |
| Untrusted builder | Exact builder/workflow | identity equality | SCN-006/020 | `EV-PROV-001` |
| Wrong signer | Root + signer + issuer | crypto and policy | SCN-009 | `EV-SIGN-001` |
| SBOM divergence | Ground-truth set comparison | precision/recall | SCN-007/008 | `EV-SBOM-001` |
| Expired metadata | Trusted-clock expiry | expiry > now | SCN-011 | `EV-UPDATE-001` |
| Rollback | Monotonic version policy | incoming ≥ installed | SCN-012 | device state |
| Wrong target | Dual target binding | group equality | SCN-013 | release + update evidence |
| Evidence tampering | Envelope + root manifest | digest equality | SCN-019 | `EV-MANIFEST-001` |
| Vulnerable dependency | Finding/VEX gate | status evaluation | SCN-018 | `EV-SEC-001` |

Missing evidence changes a check to `FAILED`; it never becomes `VERIFIED` by omission.

