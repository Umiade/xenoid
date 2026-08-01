# Xenoid Operations

## Apple Silicon macOS

Requirements: Apple Silicon, macOS, Homebrew, Python 3.9 or newer, and at least 8 GB of allocatable memory.

Clone this repository as `xenoid`, then:

```bash
cd xenoid
./xenoid install-runtime
./xenoid up
./xenoid view
```

`install-runtime` installs and validates Docker CLI, Colima, ADB, scrcpy, JDK 17, Android SDK platform/build-tools 35, and Android NDK. It prepares the ARM64 Colima VM and binderfs and creates `.xenoid/config.json` when absent. It does not start Android.

`up` builds the configured artifacts, starts Android, deploys the daemon and native helpers, applies the device profile and protection policy, activates system protection, and validates the live runtime. It returns nonzero if convergence or validation fails.

## Linux ARM

Requirements: Ubuntu 22.04 or 24.04 ARM64, Python 3.9 or newer, Docker Engine, root or sudo access, and a kernel with `binder_linux`. Source builds also require JDK 17, Android SDK platform 35, Android build-tools 35.0.0, and Android NDK 27.2.12479018 or a compatible newer release.

```bash
cd xenoid
mkdir -p .xenoid
cp examples/config-linux-arm.json .xenoid/config.json
sudo ./scripts/setup-linux-binderfs.sh
./xenoid up
```

Release bundles contain prebuilt artifacts and can start with:

```bash
./xenoid up --skip-build
```

Linux ARM hosts must expose binderfs to the Android container and use the redroid Android 13 `64only` image.

## Lifecycle

```bash
./xenoid up
./xenoid status
./xenoid logs --out-dir .xenoid/logs
./xenoid view
./xenoid stop
```

Preview startup without changing the runtime:

```bash
./xenoid up --dry-run
```

`start` is the lower-level container command. Use `up` for normal operation because it owns complete state convergence and final validation.

## Diagnostics

```bash
./xenoid doctor
./xenoid doctor --require-runtime
./xenoid doctor --full --require-runtime
./xenoid doctor --out /tmp/xenoid-doctor.json
```

- `doctor` performs non-mutating host and available-runtime checks.
- `--require-runtime` fails unless Android and the daemon are ready.
- `--full` adds builds, packaging checks, runtime-context checks, and the complete live smoke path.
- `ok` reports the requested check result; `complete` reports end-to-end runtime readiness.

`up` already runs the required live checks. Use standalone `doctor` for diagnosis and evidence.

## Configuration

```bash
./xenoid config show
./xenoid config set --backend colima-docker
./xenoid init --backend colima-docker
```

Configuration examples:

- `examples/config-macos-colima.json`
- `examples/config-linux-arm.json`

Local configuration and runtime state belong under `.xenoid/` and must not be committed.

## Remote Linux Docker engine

```bash
docker context create linux-arm --docker host=ssh://user@server
./xenoid config set --backend linux-docker --docker-context linux-arm
./xenoid up
```

With `backend=linux-docker`, Xenoid prepares binder and runtime protection on the selected Docker engine host and does not start local Colima.

## Root control

```bash
./xenoid daemon health
./xenoid root status
./xenoid root exec id
```

Privileged operations pass through the daemon and loopback-only `xenoid-rootd`. Mutating requests require the per-instance token provisioned under `.xenoid/`; the Android rootfs exposes no persistent application-visible `su` path.

## Camera media control

Use the Android Xenoid settings screen for Storage Access Framework imports, or use the same persistent state through the host CLI:

```bash
./xenoid camera status
./xenoid camera set photo FILE
./xenoid camera set video FILE
./xenoid camera mode naturalized
./xenoid camera mode faithful
./xenoid camera clear video
./xenoid camera clear all
./xenoid camera apply
./xenoid camera status --check
```

Imports are copied into private Android storage and the original host path is discarded. `apply` is idempotent and republishes the saved state without requiring the original file. `status --check` opens both cameras from the daemon's ordinary application UID and requires nonempty 320x240 YUV and JPEG captures with matched timestamps.

`up` always applies the saved camera state after daemon/rootd readiness and runs the same Camera2 self-test before final runtime validation. A missing source is valid and selects the fallback scene; a configured but missing or corrupt saved source fails convergence. The stock Android Camera app supports photo capture and H.264 recording in the source-free state.

## Frida

Frida is opt-in and is not part of production startup.

```bash
python -m pip install frida-tools
./xenoid frida install
./xenoid frida start
./xenoid frida status
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

`frida install` matches the host `frida-tools` version and deploys the Android ARM64 server. Run `up` after an analysis session to restore production state.

## Device profiles

```bash
./xenoid device collect --out /tmp/device-profile.json
./xenoid device apply examples/fingerprints/sample-profile.json
./xenoid device apply examples/fingerprints/sample-profile.json --keep-unique
./xenoid profile status
```

Profile application converges SettingsProvider, property-area state, native runtime helpers, and reboot-persistent data. Recollect the complete profile after a change.

## Applications, input, and automation

```bash
./xenoid app install /path/to/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid app uninstall com.example.app
./xenoid input tap 540 1800
./xenoid input swipe 540 1600 540 400 500
./xenoid automation plan examples/automation/ordered-task.js
./xenoid automation run examples/automation/ordered-task.js
```

The daemon performs low-level input through the deployed `/dev/uinput` helper. Use each subcommand's `--help` output as the parameter reference.

## Protection policy

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
./xenoid ebpf status
```

Production protection combines image state, property-area normalization, mount overlays, the zygote preload layer, eBPF/kernel enforcement, and framework/HAL services. `up` owns deployment and activation; individual build/load commands are for diagnosis and development.

## Build and release

```bash
./xenoid build all
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Release bundles include the CLI, MCP server, runtime assets, daemon APK, native helpers, configuration examples, skill files, doctor metadata, and SHA-256 manifests.

## OTA

```bash
./xenoid ota make --version 0.1.0
./xenoid ota install-bundle dist/ota/xenoid-0.1.0.tar.gz
./xenoid ota check
./xenoid ota apply
```

## MCP

```bash
./xenoid mcp-config
./xenoid-mcp
```

MCP uses the same backend, token, and runtime preconditions as the CLI. See [`mcp-tools.md`](mcp-tools.md) for the complete tool contract.
