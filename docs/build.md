# Build Xenoid Components

## Host CLI/MCP

No external Python dependencies are required.

```bash
./xenoid doctor
```

## Global proxy runtime

Proxy source compilation and authenticated control contracts are runtime-free:

```bash
python3 scripts/test-proxy-compiler.py
```

The transparent data plane runs on the selected Docker engine host. On first `proxy prepare`, `proxy set`, or enabled-state convergence, Xenoid installs the root engine helper, per-instance systemd agent, unprivileged compiler/fetch workers, and required distro packages. It downloads Mihomo `v1.19.29` only from the pinned release URL and verifies both the compressed archive and extracted ARM64 binary SHA-256 digests. The binary is host state under `/usr/lib/xenoid/proxy`; it is not a tracked or packaged build artifact.

The daemon APK contains the encrypted desired-state manager and ordinary-app IPv4/IPv6 DNS, TCP, and UDP probes. Host Python modules and the engine/agent scripts are included in release bundles.


## Daemon APK

Preferred:

```bash
./xenoid build daemon
```

The build script first tries Gradle/Android Gradle Plugin. If Gradle is unavailable, it falls back to a standalone Android SDK build using:

- `aapt2`
- `javac`
- `d8`
- `zipalign`
- `apksigner`

Output:

```text
daemon/app/build/outputs/apk/debug/app-debug.apk
```

## Native low-level input helper

```bash
./xenoid build input
```

The script auto-discovers Android NDK under `$ANDROID_HOME`, `$ANDROID_SDK_ROOT`, or `$HOME/Library/Android/sdk/ndk`.

Output:

```text
native/xenoid-input/xenoid-input
```

## Camera provider and graphics allocator

```bash
scripts/build-gralloc.sh arm64
scripts/build-camera-hal.sh arm64
./xenoid build all
```

Outputs:

```text
native/xenoid-gralloc/gralloc.redroid.so
native/xenoid-camerahal/android.hardware.camera.provider-service-aidl
native/xenoid-camerahal/media_profiles_V1_0.xml
```

The runtime image installs the provider at `/system/bin/hw/android.hardware.camera.provider-service-aidl` and its framework camcorder profiles at `/vendor/etc/media_profiles_V1_0.xml`. The enhanced allocator replaces the owning `gralloc.redroid.so` and supplies the existing `gralloc.tensor.so` hardware-name alias from the same binary; it is not a second allocator.

The provider build generates the Android 13 stable-AIDL NDK bindings, links the matching platform camera metadata/Binder libraries, strips the service, and rejects product-specific marker strings in the runtime artifact.

## Build all

```bash
./xenoid build all
```

Expected verification on Apple Silicon macOS:


- daemon APK: built and signed
- native input helper: built for `aarch64-linux-android21`
- camera provider: built for Android ARM64 with stable-AIDL VINTF registration
- enhanced gralloc: built for Android ARM64 with legacy RGB/framebuffer ABI preserved
- doctor: passed

## Verify and bundle OTA

```bash
./xenoid doctor
./xenoid ota make --version 0.1.0-dev
```

Bundle output:

```text
dist/ota/xenoid-0.1.0-dev.tar.gz
```

## Hide helper and runtime context

```bash
./xenoid build hide
./xenoid runtime-context
```

Outputs:

```text
native/xenoid-hide/xenoid-hide
dist/runtime-context/Dockerfile
```

## Verification coverage

`./xenoid doctor` checks:

- host dependencies and redroid preflight
- Python compilation
- CLI dry-run and MCP tool exposure
- mock daemon API contract
- deterministic proxy source compilation, bounded subscription fetching, authenticated/replay-safe engine protocol, and fixed-instance controller race contracts
- ADB/boot/daemon/root state when Android is running

`./xenoid doctor --full --require-runtime` additionally rebuilds artifacts and
checks OTA, runtime context, hook surfaces, and the live runtime smoke path.

Kernel module builds are transactional. `scripts/build-kmod.sh` compiles in a staging directory, preserves the previous module as a last-known-good copy, replaces the loaded module only after compilation succeeds, and attempts to restore the previous module if `insmod` or a required probe registration fails. The required permission probes are `security_socket_create` and `security_netlink_send`; a vendor kernel that does not expose them fails the load before Android startup. The cellular runtime probe uses schema v2 and must show ordinary-app `RTM_GETLINK` `sendto` as `EACCES`, ordinary GETADDR/GETROUTE success, isolated non-Unix socket `EACCES`, and privileged `xenoid-netctl` success.

## Location cellular runtime (RIL / RadioConfig)

The cellular identity stack is a version-15 legacy vendor RIL plus an AIDL RadioConfig service; both are built from the pinned Android NDK:

```bash
scripts/build-ril.sh arm64
scripts/build-radio-config.sh arm64
```

Outputs:

```text
native/xenoid-ril/libxenoid-ril.so
native/xenoid-radio-config/android.hardware.radio.config-service.xenoid
```

Runtime-free contracts for the location identity layer:

```bash
python3 scripts/test-cellular-profile.py   # seven-country profiles, MSISDN templates, crash-safe state machine
python3 scripts/test-ril-source.py         # canonical binary profile and RIL/SIM-file source contracts
python3 scripts/test-proxy-control.py      # generation/check-bound proxy data-plane proof (no region evidence)
```

`test-cellular-profile.py` pins the libphonenumber-derived per-country MSISDN templates, the 3GPP EARFCN/band round-trip used by the image's telephony band bridge (`scripts/patch-telephony-legacy-lte-band.py`), profile digest stability, and the stage/arm/recreate/verify/promote transaction including crash resume. `scripts/smoke-cellular-runtime.sh` is the live counterpart: an ordinary + isolated-process probe APK checks SIM/subscription/LTE cell/MSISDN, the single `rmnet_data0` cellular network, and the raw-syscall interface views.

## Native profile helper

```bash
./xenoid build profile
./xenoid build all
```

Output:

```text
native/xenoid-profile/xenoid-profile
```

## Native helpers (hide / overlay / prop-area / input / profile)

```bash
./xenoid build all
```

Outputs include:

```text
native/xenoid-hide/xenoid-hide
native/xenoid-hide/xenoid-overlay
native/xenoid-hide/xenoid-prop-area
native/xenoid-input/xenoid-input
native/xenoid-profile/xenoid-profile
```

The production privilege path uses token-gated `xenoid-rootd`; app-process instrumentation uses opt-in Frida, while system policy uses eBPF and the runtime protection layers.
