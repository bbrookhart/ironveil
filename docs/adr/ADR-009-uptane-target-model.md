# ADR-009: Uptane-inspired target model

- **Status:** Accepted
- **Context:** Industrial fleets require inventory and target-specific update decisions.
- **Decision:** Borrow Uptane 2.1.0 inventory, target binding, manifest, version, and recovery concepts.
- **Alternatives:** Treat every target as identical; claim automotive conformance.
- **Consequences:** Device and mission impact are explicit without automotive scope.
- **Security implications:** Correctly signed wrong-target artifacts are denied; Uptane conformance is not claimed.

