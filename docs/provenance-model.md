# Provenance model

IRONVEIL uses the in-toto Statement v1 identifier and SLSA provenance v1 predicate identifier. The
synthetic object captures artifact subject digest, repository and revision, builder, workflow, build
definition, pinned-image claim, parameters, and environment.

Verification requires exact equality for repository, revision, expected builder, expected workflow,
and artifact subject digest. A provenance document valid for artifact A cannot authorize B. The local
object is labeled `simulated: true`; it is not authenticated hosted provenance and does not establish
SLSA Build L2 or L3.

