# Device Profile, Mutation, and Environment Hiding

## Collector

The daemon APK collector returns JSON with:

- build and partition identity (`Build.*`, properties, security patch, shipping API, SKU)
- ids (`android_id`, `boot_id`, serial, IMEI/IMEISV when available)
- battery capacity, charge, voltage, temperature, status, health, and power source
- display modes/metrics and touchscreen identity/axes
- CPU topology/frequencies, memory, and storage geometry
- sensor catalog plus an accelerometer event sample
- Camera2 geometry, output sizes, flash/OIS state, and physical-camera IDs
- locale/timezone and thermal zones

```bash
./xenoid device collect --out .xenoid/current-device.json
```

## Apply profile

```bash
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
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

## Canonical Raven contract

`examples/fingerprints/pixel-raven-android13.json` is the single production template. It identifies Google Pixel 6 Pro `raven` model/SKU `G8V0U` running Android 13 build `TP1A.221005.002` (`9012097`), fingerprint `google/raven/raven:13/TP1A.221005.002/9012097:user/release-keys`, bootloader `slider-1.2-8895132`, security patch `2022-10-05`, and shipping API 31.

The same profile owns the surfaces that need cross-layer agreement:

- 1440 x 3120 at 560 dpi, physical 512 ppi, with real 60/120 Hz display modes
- eight Tensor CPU cores, 12 GiB memory, and a grow-only sparse 128,000,000,000-byte UFS 3.1 data image with an Android-facing f2fs contract
- 5003 mAh typical / 4905 mAh minimum battery capacity and coherent charge fields
- Raven sensor identities (LSM6DSR, MMC56X3X, TMD3719, ICP10101, CHRE fusion sensors, and the private VD6282 rear-light sensor)
- one back and one front Camera2 device with per-camera geometry and output tables; only the rear device exposes flash/torch

The `provenance` object records Google specifications, AOSP Raven sources, the factory image, the community sensor registry, and community-derived camera geometry. Community-derived fields are not represented as Google-published values. Body dimensions, weight, color, benchmark results, and other facts without an Android runtime owner do not belong in the profile.

PackageManager feature declarations follow implemented HAL behavior rather than Pixel marketing specifications. NFC, UWB, fingerprint/UDFPS, true NR, autofocus, OIS, full/manual/RAW camera, HiFi sensor, and head-tracker support remain absent until their owning subsystem exists. The active cellular profile is LTE-only and each carrier's band list must be a subset of the official G8V0U LTE matrix.

The 128 GB value is logical sparse capacity, not host-space preallocation. The profile's `capacityBytes == sectorSizeBytes * sectorCount` invariant drives `/proc/partitions`, `/proc/diskstats`, `/dev/block/sda`, the Raven userdata by-name alias, and block sysfs as one Android storage view. Its `filesystem: f2fs` value also drives canonical mount records and both libc and direct-syscall `statfs`/`fstatfs` results for unprivileged and isolated apps. The persistent backing image remains ext4 for grow-only recovery, and privileged maintenance paths retain that real view. Container/Colima memory budgets may remain below the 12 GiB Android view; those host budgets do not change the guest-visible device contract.

## Single field mutation

```bash
./xenoid device set android_id random
./xenoid device set ro.product.model "Pixel 6 Pro"
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
./xenoid device generate-frida examples/fingerprints/pixel-raven-android13.json --out .xenoid/frida/generated-profile.js
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
./xenoid device generate-service-frida examples/fingerprints/pixel-raven-android13.json --out .xenoid/frida/generated-service-profile.js
```

The service-oriented script hooks:

- boot_id-like Java `BufferedReader.readLine` values
- `Settings.Secure.getString` for `android_id`
- `android.os.SystemProperties.get`
- `android.os.Build` fields
- battery `Intent.getIntExtra` values
- `SensorManager.getSensorList` as the framework sensor access point

Generated scripts are local runtime artifacts under `.xenoid/frida/`; production startup removes analysis payloads.
