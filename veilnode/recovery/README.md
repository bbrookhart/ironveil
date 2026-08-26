# VEILNODE recovery fixture

The local lab preserves an explicitly authorized last-known-good digest in each device manifest.
Recovery is allowed only when release authorization carries `recovery: true`; it is separate from
an attacker-induced downgrade. This is a simulation and does not represent a hardware recovery
partition.

