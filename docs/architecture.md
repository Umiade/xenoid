# Xenoid Architecture

Xenoid is split into three layers:

1. **Host layer** (`src/xenoid`) — CLI and MCP server for local agents/users.
2. **Runtime layer** — Android container backend through Docker/Colima on Apple Silicon macOS or Docker on Linux ARM.
3. **Android control layer** (`daemon`) — daemon APK exposing JSON APIs for root/frida/profile/automation/OTA.

## Why a Linux VM on macOS

Android container runtimes depend on Linux kernel facilities and device namespaces. macOS does not expose those interfaces directly, so Xenoid runs an ARM64 Linux VM through Colima and starts the Android container with Docker inside it.

## Host API

```bash
xenoid doctor
xenoid init
xenoid start
xenoid stop
xenoid status
xenoid daemon health
xenoid device collect --out .xenoid/device.json
xenoid device apply examples/fingerprints/sample-profile.json
xenoid automation run examples/automation/tap-home.js
xenoid ota check
xenoid mcp-config
```

## Daemon API

- `GET /health`
- `GET /fingerprint/collect`
- `POST /fingerprint/apply`
- `POST /fingerprint/set`
- `POST /automation/run`
- `POST /frida/start`
- `POST /frida/stop`
- `POST /input/tap`
- `GET /ota/check`
- `POST /ota/apply`

## Environment hiding

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
```

The daemon exposes the stable host/MCP policy facade. Runtime hiding is enforced by prop-area, bind overlays, kmod/eBPF, and zygote preload; Magisk/Zygisk is not part of the production path.

## Backend modes

Xenoid supports two primary runtime backends:

- `colima-docker`: starts an ARM64 Colima VM on Apple Silicon macOS and runs redroid through Docker.
- `linux-docker`: runs redroid through a local or remote Linux ARM Docker engine.

Config examples:

```bash
cp examples/config-macos-colima.json .xenoid/config.json
cp examples/config-linux-arm.json .xenoid/config.json
```

Build a custom runtime image containing Xenoid payloads:

```bash
./xenoid runtime-context
./xenoid runtime-build-image --dry-run
./xenoid runtime-build-image --tag xenoid/redroid:local
```

When `auto_build_runtime_image=true`, `xenoid start` plans to use `runtime_image_tag` as the effective Android image.

## Runtime preflight

`xenoid start --dry-run` and `xenoid doctor` report:

- host OS/arch
- Docker daemon availability
- Colima availability on macOS
- binder/binderfs and ashmem/memfd assumptions for redroid
- ADB availability

This makes startup failures actionable before trying to boot Android.

## Docker Compose for Linux ARM

`xenoid runtime-compose` generates a compose file with privileged redroid container, ADB/daemon ports, persistent data volume, binderfs mount, and `androidboot.use_memfd=true`.
