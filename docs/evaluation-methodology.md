# Evaluation methodology

The scenario engine starts from a golden release whose full chain evaluates to `ALLOW`. Each scenario
applies exactly one controlled mutation or authorized lifecycle operation, then evaluates the same
policy. When the experiment models a malicious but cryptographically valid producer, it re-signs the
mutated envelope using a lab key; signature validity therefore cannot stand in for authorization.

Unauthorized Artifact Acceptance Rate is unauthorized attempts ending in `ALLOW` divided by all
unauthorized attempts. Authorized golden, key-rotation, and recovery operations are excluded from the
denominator. The suite also measures provenance-break detection, target authorization, rollback and
signer enforcement, SBOM recall, scenario pass rate, and local median verification latency.

Results are deterministic except time measurements and evidence timestamps. Claims are limited to the
20 scenarios, configured policy, synthetic ground truth, and documented TCB.

