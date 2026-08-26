# Trust model

## Trust domains

- **SOURCE:** repository identity, revision, author, reviewer, branch, checks.
- **BUILD:** builder, workflow, inputs, configuration, environment, artifact.
- **SIGNING:** key or workload identity and issuer.
- **RELEASE:** policy engine and independent approval.
- **DISTRIBUTION:** artifact and update repositories; considered capable of substitution or replay.
- **TARGET:** device identity, hardware class, installed version, clock, maintenance state.
- **AUDIT:** evidence retention, manifest verification, graph queries, experiment results.

## Trusted computing base

The v0.1 TCB is the verifier code, policy configuration, local public trust root, release authorization
logic, device state, filesystem, and clock. The private key is trusted only for local research. A
compromise of the verifier, policy, trust root, or authoritative device state can invalidate results.

## Separation objective

No single ordinary domain can declare a release trusted. Source approval does not sign an artifact;
the builder cannot authorize a target; signing does not grant release approval; distribution cannot
change a digest-pinned identity; the device cannot rewrite its root trust through an ordinary release.

