# OCI integration boundary

The v0.1 verifier is digest-native and contains an OCI registry service in `docker-compose.yml` for
integration experiments. Default acceptance tests do not require Docker or claim a published OCI
artifact. Mutable tags are never accepted as release identities.

