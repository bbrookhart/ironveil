# ADR-003: SLSA evidence architecture

- **Status:** Accepted
- **Context:** Build success does not identify artifact history.
- **Decision:** Emit SLSA-shaped provenance bound to artifact digest and evaluate Source and Build tracks separately.
- **Alternatives:** Store log text; self-award a repository SLSA level.
- **Consequences:** Provenance is queryable; hosted-platform properties remain gaps.
- **Security implications:** No Build L2/L3 or Source L4 claim without independent evidence.

