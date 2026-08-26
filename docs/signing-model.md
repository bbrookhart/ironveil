# Signing model

## Local research mode

Bootstrap generates an Ed25519 key under `.ironveil/trust/`. The private key is mode 0600, ignored by
Git, and explicitly `LOCAL_TEST_ONLY`. The signature covers the artifact digest and a digest of the
source, provenance, SBOM, security, release, and update evidence. Verification checks cryptography,
the configured public root, signer identity, and issuer.

## Hosted release design

The planned hosted path uses Sigstore keyless signing, an exact GitHub Actions issuer and workflow
identity, transparency inclusion, and an offline-verifiable bundle. Wildcards are forbidden in
production policy. This integration is not active in v0.1.

## Security property

A cryptographically valid signature is necessary but insufficient. Authorization is a separate policy
decision, tested explicitly by SCN-009 and the signature-only comparison.

