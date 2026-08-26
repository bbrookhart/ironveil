# Research question

> Can a critical-infrastructure operator verify the complete trust history of software or firmware
> before deployment, even if individual supply-chain components are assumed capable of compromise?

IRONVEIL evaluates whether independently generated evidence can bind an installed artifact to an
authorized source revision, expected builder and workflow, declared and measured composition,
expected signer, independent release approval, current update metadata, authorized target, and
post-install digest.

The v0.1 result is scoped to deterministic synthetic fixtures. It tests whether the verifier rejects
the defined broken chains; it does not generalize to every real supply-chain attack.

