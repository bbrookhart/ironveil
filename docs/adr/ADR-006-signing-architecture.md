# ADR-006: Signing architecture

- **Status:** Accepted
- **Context:** Hosted CI and offline research have different identity and availability constraints.
- **Decision:** Design hosted Sigstore identity mode and implement ephemeral local Ed25519 research mode.
- **Alternatives:** Commit a long-lived key; require external identity for all tests.
- **Consequences:** The lab is reproducible offline; hosted guarantees remain planned.
- **Security implications:** Local keys are test-only, excluded from Git, and never presented as Sigstore evidence.

