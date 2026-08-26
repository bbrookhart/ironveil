# ADR-004: Attestation format

- **Status:** Accepted
- **Context:** Custom envelopes reduce interoperability and make subject binding ambiguous.
- **Decision:** Use the in-toto Statement v1 identifier with standard predicate identifiers.
- **Alternatives:** Unsigned custom JSON; filename-linked evidence.
- **Consequences:** Objects align with an established claim model while local serialization stays simple.
- **Security implications:** Every attestation identifies immutable subjects; local objects are still marked simulated.

