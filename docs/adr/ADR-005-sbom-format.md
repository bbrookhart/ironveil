# ADR-005: SBOM format

- **Status:** Accepted
- **Context:** Composition requires identifiers, hashes, licenses, and relationships.
- **Decision:** Use CycloneDX 1.7-shaped JSON and validate against explicit synthetic ground truth.
- **Alternatives:** SPDX; scanner output treated as truth.
- **Consequences:** Precision and recall are measurable for VEILNODE.
- **Security implications:** A syntactically valid but composition-inaccurate SBOM fails policy.

