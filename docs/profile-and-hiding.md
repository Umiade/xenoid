# Device Profile, Mutation, and Environment Hiding

## Collector

The daemon APK collector returns JSON with:

- build identity (`Build.BRAND`, `Build.MODEL`, `Build.FINGERPRINT`, etc.)
- ids (`android_id`, `boot_id`, serial when available)
- battery
- display metrics
- sensors
- locale/timezone

```bash
./xenoid device collect --out .xenoid/current-device.json
```

## Apply profile

```bash
./xenoid device apply examples/fingerprints/sample-profile.json
```

By default Xenoid regenerates uniqueness fields:

- `android_id`
- `boot_id`

The daemon applies mutable settings and properties during profile convergence:

- `settings put secure android_id ...`
- `resetprop ... || setprop ...` for build properties
- `persist.sys.locale`
- `persist.sys.timezone`
- staged battery/environment values under `/data/local/tmp/xenoid-profile`

The full profile is staged at:

```text
/data/local/tmp/xenoid-profile/effective.json
```

System services and native helpers consume the staged profile for non-mutable surfaces such as sensors, boot ID reads, and battery values.

## Single field mutation

```bash
./xenoid device set android_id random
./xenoid device set ro.product.model "Pixel 8 Pro"
./xenoid device set timezone America/Los_Angeles
```

## Hiding

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
```

The daemon stages the global hiding policy under:

```text
/data/local/tmp/xenoid-hide/policy.json
```

Policy surfaces include:

- root files / `su` path
- Magisk/Zygisk markers
- Frida process/port markers
- debug/test-key properties
- package visibility

Global hiding is enforced by prop-area, bind overlays, kmod/eBPF, and the zygote preload layer; the daemon, CLI, and MCP expose one policy contract.

## Native hide helper

The native helper lives at `native/xenoid-hide`. It supports:

```bash
xenoid-hide status
xenoid-hide apply [policy.json]
```

The daemon calls `/data/local/tmp/xenoid-hide-helper status/apply` when deployed. This provides native surface inspection and policy staging; enforcement lives in prop-area, overlay, kmod/eBPF and the zygote preload shim.

## Frida app-process hiding

`frida/scripts/xenoid-default.js` provides app-process level hiding:

- hides root/Magisk/Frida/Xposed file probes via Java `File.exists` and libc `access/stat/open` hooks
- rewrites selected `android.os.SystemProperties.get` results
- blocks suspicious `Runtime.exec` checks

Deploy with `./xenoid frida deploy-scripts`; load into a target app with `./xenoid frida load-script`.

## Profile-generated Frida spoofing

```bash
./xenoid device generate-frida examples/fingerprints/sample-profile.json --out .xenoid/frida/generated-profile.js
./xenoid frida load-script com.example.app .xenoid/frida/generated-profile.js --spawn
```

The generated script hooks app-process reads for:

- `android.os.Build` fields
- `android.os.SystemProperties.get`
- `Settings.Secure.getString(..., "android_id")`
- `TimeZone.getDefault`
- selected battery `Intent.getIntExtra` values

By default it regenerates unique ids (`android_id`, `boot_id`) unless `--keep-unique` is set.

## Native profile helper

`native/xenoid-profile` is the Android arm64 helper for inspecting staged profile state:

```bash
xenoid-profile status
xenoid-profile env
xenoid-profile dump
xenoid-profile get boot_id
```

Daemon/CLI integration:

```bash
./xenoid profile deploy-helper native/xenoid-profile/xenoid-profile
./xenoid profile status
./xenoid profile env
./xenoid profile dump
```

The helper consumes staged profile files under `/data/local/tmp/xenoid-profile`, including `effective.json` and `boot_id`.

## Service/system Frida generation

```bash
./xenoid device generate-service-frida examples/fingerprints/sample-profile.json --out .xenoid/frida/generated-service-profile.js
```

The service-oriented script hooks:

- boot_id-like Java `BufferedReader.readLine` values
- `Settings.Secure.getString` for `android_id`
- `android.os.SystemProperties.get`
- `android.os.Build` fields
- battery `Intent.getIntExtra` values
- `SensorManager.getSensorList` as the framework sensor access point

Generated scripts are local runtime artifacts under `.xenoid/frida/`; production startup removes analysis payloads.
