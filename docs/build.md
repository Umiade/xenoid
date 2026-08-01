# Build Xenoid Components

## Host CLI/MCP

No external Python dependencies are required.

```bash
./xenoid doctor
```

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
- ADB/boot/daemon/root state when Android is running

`./xenoid doctor --full --require-runtime` additionally rebuilds artifacts and
checks OTA, runtime context, hook surfaces, and the live runtime smoke path.

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
