# ADR-010: Evidence graph

- **Status:** Accepted
- **Context:** JSON archives do not answer incident-response reachability questions.
- **Decision:** Use a directed NetworkX graph for review-to-device trace and dependency-to-mission impact.
- **Alternatives:** Relational joins only; static diagrams.
- **Consequences:** Trace and recall queries are executable; v0.1 scale is intentionally small.
- **Security implications:** Impact scope can be derived from recorded relationships rather than guessed.

