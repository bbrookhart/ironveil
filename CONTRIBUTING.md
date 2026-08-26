# Contributing

Contributions should strengthen an assurance claim, implementation, test, evidence object, or
research limitation. Avoid empty directories, decorative controls, and unsupported compliance claims.

1. Create a focused branch and describe the threat/control/evidence relationship.
2. Add or update automated tests, including a negative test for security-critical logic.
3. Run `make lint typecheck test test-properties test-scenarios security docs`.
4. Update the standards registry only from an official source and preserve retrieval date and status.
5. Mark fixtures `SIMULATED`, gaps `NOT_VERIFIED`, and future work `PLANNED`.

Never commit secrets, production keys, vendor firmware, real infrastructure data, or unauthorized
attack material. By contributing, you agree that your contribution is licensed under Apache-2.0.

