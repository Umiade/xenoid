# xenoid-sensorshal

`xenoid-sensorshal` is the runtime AIDL sensor service. It registers `android.hardware.sensors.ISensors/default` and provides a profile-aligned sensor catalog and event channel to Android's `sensorservice`.

The stable AIDL inputs are stored under `aidl/`. Generated NDK bindings are build output and are not tracked.

Build from the repository root:

```bash
./scripts/build-sensors-hal.sh arm64
```

The runtime image installs the resulting service binary and VINTF fragment and starts it before framework consumers connect.
