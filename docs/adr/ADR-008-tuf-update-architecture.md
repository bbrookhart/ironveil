# ADR-008: TUF update architecture

- **Status:** Accepted for v0.1; supersession planned
- **Context:** Hand-rolled TUF verification would create an unsafe conformance illusion.
- **Decision:** Implement and label synthetic TUF security semantics, then adopt python-tuf for repository/client conformance.
- **Alternatives:** Claim TUF based on look-alike JSON; make Docker/external services mandatory.
- **Consequences:** Rollback, expiry, role, and target research works now; full metadata flow remains a gap.
- **Security implications:** No TUF conformance claim is made.

