# Signing modes

- Hosted release mode is designed for Sigstore keyless signing with an exact GitHub OIDC issuer,
  repository, workflow, and ref constraint. CI integration is not activated in v0.1.
- Local research mode uses an ephemeral Ed25519 key below `.ironveil/trust/`. The private key is
  test-only, ignored by Git, and never presented as a production or Sigstore identity.

