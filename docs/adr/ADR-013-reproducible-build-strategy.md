# ADR-013: Reproducible-build strategy

- **Status:** Accepted
- **Context:** Timestamps, archive order, and environment can make equivalent builds differ.
- **Decision:** Build a canonical sorted compact JSON artifact from two explicit inputs with no embedded time.
- **Alternatives:** Container tarball for v0.1; claim reproducibility without comparison.
- **Consequences:** Two local builds are byte-identical; evidence timestamps remain intentionally variable.
- **Security implications:** Artifact substitution is distinguishable from nondeterministic packaging noise.

