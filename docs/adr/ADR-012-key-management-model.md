# ADR-012: Key-management model

- **Status:** Accepted
- **Context:** A universal committed key would make the demonstration insecure.
- **Decision:** Generate ephemeral ignored local keys, pin exact signer/issuer policy, and plan separated hosted roles.
- **Alternatives:** Shared static secret; wildcard identity matching.
- **Consequences:** Bootstrap regenerates lab trust; evidence is local-run-specific.
- **Security implications:** Private material is not published and unexpected identity fails even with valid cryptography.

