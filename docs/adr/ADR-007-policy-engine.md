# ADR-007: Policy engine

- **Status:** Accepted
- **Context:** The v0.1 policy is small, typed, and security critical.
- **Decision:** Use a custom deterministic Pydantic-based engine; evaluate OPA when policies require independent distribution.
- **Alternatives:** OPA/Rego now; implicit Python conditionals spread across commands.
- **Consequences:** Minimal runtime and high unit/property testability, with less policy-language portability.
- **Security implications:** Critical failures are fail-closed and mutation-sensitive conditions have direct tests.

