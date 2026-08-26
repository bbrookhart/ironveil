# ADR-011: Recovery architecture

- **Status:** Accepted
- **Context:** Anti-rollback controls can conflict with returning to a last-known-good image.
- **Decision:** Require explicit recovery authorization and a failed health check; preserve last-known-good digest separately.
- **Alternatives:** Always forbid downgrade; automatically roll back on process failure.
- **Consequences:** Recovery is auditable and distinct from attacker-induced rollback.
- **Security implications:** Ordinary update artifacts cannot authorize their own downgrade.

