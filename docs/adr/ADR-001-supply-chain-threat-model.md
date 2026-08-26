# ADR-001: Supply-chain threat model

- **Status:** Accepted
- **Context:** Unlimited attacker claims are untestable and encourage overstatement.
- **Decision:** Model compromise of individual source, build, signing, distribution, and update links while trusting the verifier, policy, roots, inventory, and clock.
- **Alternatives:** Treat every component as simultaneously compromised; test only happy paths.
- **Consequences:** Claims are precise but cannot cover verifier/root compromise.
- **Security implications:** Every result names its assumptions and scenario boundary.

