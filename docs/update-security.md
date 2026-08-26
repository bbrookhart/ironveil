# Update security

The executable v0.1 target gate checks digest, metadata role status, target group, version, expiration,
release authorization, maintenance state, and recovery status. Fixtures model root version, targets
role, metadata version, and a trusted clock. Tests reject expired metadata, rollback, wrong-target
delivery, registry substitution, and unauthorized online-role use.

This model uses TUF 1.0.36 and Uptane 2.1.0 as design references, but its metadata is labeled
`SIMULATED_TUF_SEMANTICS`. It does not use a conformant repository/client workflow, threshold root
keys, delegated targets, snapshot, or timestamp files yet. TUF and Uptane conformance are not claimed.

Authorized recovery is separate from rollback: it requires explicit release evidence and a failed
health check. The last-known-good digest is preserved for the simulator; no physical partition or
hardware secure boot is claimed.

