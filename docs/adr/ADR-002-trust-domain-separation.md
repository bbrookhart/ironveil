# ADR-002: Trust-domain separation

- **Status:** Accepted
- **Context:** One pipeline with source, signing, release, and deployment authority has excessive blast radius.
- **Decision:** Separate SOURCE, BUILD, SIGNING, RELEASE, DISTRIBUTION, TARGET, and AUDIT domains.
- **Alternatives:** A universal CI identity; one signing key for every role.
- **Consequences:** More evidence relationships and explicit authority handoffs.
- **Security implications:** Compromise of one ordinary domain is insufficient for protected installation.

