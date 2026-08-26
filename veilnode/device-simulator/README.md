# Device simulator

The simulator is implemented by `ironveil.models.DeviceState` and the target checks in
`ironveil.policy.engine`. State is written below `.ironveil/devices/` during `make bootstrap`.
The measured-boot field is explicitly marked `SIMULATED`.

