# IRONVEIL: End-to-End Provenance Assurance for Software and Firmware in High-Consequence Systems

## Abstract

Software-signing and SBOM programs often establish isolated facts without proving the full history of
the artifact a target will execute. IRONVEIL is a defensive research platform that binds source
authorization, build provenance, composition, security evidence, signing identity, release approval,
update state, target authorization, and installed-state measurement into one policy-evaluated chain.
The v0.1 implementation evaluates this thesis through a deterministic fictional industrial gateway,
20 synthetic scenarios, an evidence graph, and a signature-only comparison. Results are limited to the
documented threat model and must not be interpreted as certification or a guarantee of software safety.

## 1. Problem statement

A signature answers whether a private signing relationship validated over bytes; it does not establish
source review, builder identity, dependency integrity, security-test completion, target authorization,
freshness, or installed state. An SBOM describes declared composition but does not prove how an artifact
was built. Provenance records history but does not grant deployment authority. High-consequence
operators need these objects bound by digest and judged by an independent fail-closed policy.

## 2. Threat model

The evaluated attacker can mutate individual source, build, dependency, artifact, provenance, signing,
distribution, update, and evidence links. The verifier, configured policy, public trust root, clock,
device inventory, and execution environment are trusted. Availability, malicious-but-approved source,
host compromise, and hardware authenticity are not solved by v0.1.

## 3. Related standards

IRONVEIL uses SLSA 1.2 for source/build track concepts, in-toto Statement v1 and SLSA provenance v1
identifiers for attestations, CycloneDX 1.7 and CISA 2026 guidance for composition, NIST SSDF 1.1 and
SP 800-161 Rev. 1 Update 1 for secure-development and C-SCRM traceability, Sigstore Bundle 0.3.2 as a
hosted-signing design target, TUF 1.0.36 for update resilience, and Uptane 2.1.0 as an industrial target
design reference. Draft SSDF 1.2 is recorded as draft. No framework conformance or certification is
self-awarded.

## 4. Assurance architecture

Each trust domain generates claims that another domain verifies. Source evidence cannot sign or
release an artifact. The build emits an immutable artifact and provenance subject. Composition and
security evidence bind to that digest. Signing authenticates the evidence envelope, not only a
filename. Release authority separately binds the evidence set to targets and expiry. The target gate
checks current metadata, version, group, and safety state. Installation is reconciled by digest.

## 5. Source controls

The source object records repository, branch, revision, author, reviewer, protected-branch state, and
required checks. Policy requires author and reviewer separation. Because v0.1 does not independently
retrieve repository controls, the evidence remains synthetic and SLSA Source L4 is not claimed.

## 6. Build provenance

VEILNODE consumes two explicit inputs and emits canonical timestamp-free JSON. Reproducibility tests
compare two builds byte-for-byte. Provenance identifies source revision, repository, builder, workflow,
definition, image claim, environment, and artifact digest. Subject, source, builder, and workflow drift
fail authorization.

## 7. Composition evidence

The SBOM carries component name, version, PURL, hash, license, scope, dependency relationships,
generator, timestamp, and generation context. A separate ground-truth fixture enables measurable
precision and recall; unknown and missing components fail the protected path. VEX states require
justification for `NOT_AFFECTED`.

## 8. Signing and identity

Offline research mode uses an ephemeral Ed25519 key excluded from source control. The signed payload
contains the artifact and evidence-envelope digests. The full verifier constrains the public trust root,
signer identity, issuer, and policy context. Hosted Sigstore/Fulcio/Rekor integration is planned and not
represented as complete.

## 9. Release authorization

The independent release object carries artifact digest, source revision, required evidence, approver,
expiry, recovery flag, and target groups. Decisions are `ALLOW`, `DENY`, `REVIEW_REQUIRED`, or
`RECOVER`. Missing critical evidence fails closed.

## 10. Secure distribution

Artifact identity is a digest, never a mutable tag. The optional OCI registry profile binds only to
loopback. The target model checks metadata version, role authorization, artifact digest, target group,
and expiration. This executes TUF-inspired semantics but is not a TUF implementation claim.

## 11. Target and installed-state assurance

Device manifests describe hardware model, target group, installed and minimum versions, artifact and
SBOM digests, maintenance state, last-known-good digest, and simulated measurement. Rollback is denied
unless recovery is explicitly authorized. Health-check failure under recovery evidence produces
`RECOVER`, not a silent downgrade.

## 12. Evaluation methodology

SCN-001 is the golden release. Sixteen other adversarial mutations and three authorized lifecycle
operations exercise source, artifact, provenance, builder, dependency, SBOM, signer, registry,
metadata, version, target, role, recovery, vulnerability, evidence, and CI identity behavior. The
flagship experiment compares cryptographic signature validity without policy against full-chain
authorization. Metrics and raw scenario outcomes are generated by code and committed separately.

## 13. Results

Run `ironveil experiment run BROKEN-SEAL` and inspect
`experiments/results/broken-seal.json`. The result records the exact denominator, unauthorized
installations, signature-only and IRONVEIL acceptance rates, detection/enforcement metrics, pass rate,
and local latency. The result applies only to the synthetic suite and documented assumptions.

## 14. Supply-chain incident response

A directed graph connects dependency → artifact → release → device → mission function. Given a PURL,
IRONVEIL reports affected releases, artifacts, devices, and mission functions plus a recommended scope.
This demonstrates how provenance can support a software recall rather than remain archival metadata.

## 15. Limitations

The most important gaps are live repository evidence, hardened hosted builds, Sigstore keyless and
transparency integration, conformant TUF repository/client behavior, multi-release fleet scale,
hardware measurement, real vulnerability intelligence, and independent execution-environment trust.
Evidence proves defined properties; it does not prove benign intent or absence of vulnerabilities.

## 16. Future work

The next milestone replaces simulated update metadata with python-tuf threshold-role operation, adds
GitHub/Sigstore portable bundles with exact certificate identity policy, publishes OCI content by
digest, and evaluates multiple suppliers, releases, device classes, and mission dependencies. A later
hardware track can compare simulated measurement with TPM-backed measured boot while preserving clear
claim boundaries.

