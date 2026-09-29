# Xenoid

[Chinese Version](README_CN.md)

[Changelog](CHANGELOG.md)

Xenoid is a controlled Android 13 ARM64 runtime for mobile security work on Apple Silicon macOS and Linux ARM64. It turns redroid into a persistent Raven-class device with one production entrypoint:

```bash
./xenoid up
```

A successful `up` means the runtime, daemon, device profile, protection, storage, and configured services are ready. Partial readiness is failure. Unsupported hosts, ambiguous ownership, and stale artifacts are rejected rather than guessed through.

## Capabilities

- Persistent Android 13 `arm64-v8a` instances backed by redroid `64only`.
- Idempotent, resumable convergence with content-addressed artifacts and runtime images.
- Coherent Pixel 6 Pro (`raven`) identity across framework, property, HAL, procfs, sysfs, filesystem, cellular, and raw-syscall surfaces.
- Independent country, locale, timezone, SIM, carrier, APN, and LTE-cell profiles.
- Fail-closed global proxying for SOCKS5, HTTP(S), Clash, URI lists, and subscriptions.
- Token-gated root operations without an application-visible `su` path.
- KeyMint/keybox, camera media injection, sensor, radio, input, application, automation, OTA, Frida, and MCP controls.
- Engine-scoped kmod/eBPF protection shared safely across multiple instances.
- Image-bound composite microG runtime enabled by default for new instances.

Frida is an explicit inspection capability. It is never part of normal production startup. Credentials, proxy sources, keyboxes, imported Google binaries, captures, and runtime state remain local and untracked.

## Requirements

### Apple Silicon macOS

- Apple Silicon Mac
- macOS with Homebrew
- Python 3.9 or newer
- At least 8 GiB allocatable memory

### Linux ARM64

- Ubuntu 22.04 or 24.04 ARM64
- Docker Engine
- Root or sudo access
- A kernel with `binder_linux`/binderfs support

Xenoid supports one production architecture: an ARM64 host running Android 13 `64only`. x86 and 32-bit Android are not compatibility targets.

## Quick Start

### macOS

```bash
./xenoid install-runtime
./xenoid init --config examples/config-macos-colima.json
```

### Linux ARM64

```bash
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
```

New instances enable Google services by default. The first `up` downloads the exact pinned third-party assets over HTTPS, verifies all release, hash, certificate, package, signer, SDK, and ABI contracts, and keeps the bytes only in ignored `.xenoid/` state:

```bash
./xenoid up
./xenoid view
```

Run `init` once per instance. Later calls to `up` reuse healthy artifacts, images, storage, and containers.

## Common Operations

This section covers the everyday subset. The [command reference](docs/commands.md) lists every command and subcommand.

### Runtime

```bash
./xenoid up
./xenoid up --dry-run
./xenoid up --skip-build
./xenoid status
./xenoid doctor --require-runtime
./xenoid logs
./xenoid view
./xenoid stop
./xenoid adb shell getprop ro.product.model
```

`--dry-run` is observational. `--skip-build` still validates source, tools, artifact records, outputs, and image identity; stale or missing work fails instead of compiling.

### Instances

```bash
./xenoid instance list
./xenoid --instance phone-a init --config examples/config-macos-colima.json --no-google-services
./xenoid --instance phone-a up
./xenoid --instance phone-a status
./xenoid --instance phone-a delete --dry-run
./xenoid --instance phone-a delete
```

Without `--instance`, Xenoid selects `default`. `delete` irreversibly
destroys the instance's Android user data and releases its container, data
volume, Docker network, ports, and registry lease; shared runtime images and
engine-host protection are retained. `--dry-run` reports the plan without
deleting.

### Device and Location Identity

```bash
./xenoid location list
./xenoid location set US
./xenoid location status --check

./xenoid device collect --out /tmp/device-profile.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid device regenerate
```

`device regenerate` rotates device, SIM, boot, storage, Google, and application identity in place — one soft reboot, no container recreation — while preserving user data and installed applications. It accepts `--dry-run`, not `--skip-build`; `up --skip-build` remains available. Completed microG regeneration uses `googleIdentityMode=offline-seeded`, so FCM registration and delivery are unavailable.

### Global Proxy

```bash
./xenoid proxy set --prompt
./xenoid proxy on
./xenoid proxy status --check
./xenoid proxy off

chmod 600 /path/to/proxy-source
./xenoid proxy import /path/to/proxy-source
```

Secrets do not belong in command arguments. Proxy failure retains quarantine instead of silently exposing direct egress.

### Root, Applications, Camera, and Inspection

```bash
./xenoid root status
./xenoid root exec id

./xenoid app install /path/to/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid input tap 540 1800

./xenoid camera set photo /path/to/image.png
./xenoid camera status --check

python -m pip install frida-tools
./xenoid frida install
./xenoid frida start
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

### Google Services

New instances default to `microg` release `microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`; use `init --no-google-services` to disable it explicitly. The first `up` securely acquires and verifies the pinned assets; details and manual fallback commands are in [operations](docs/operations.md#google-play-services-default).


### MCP, Build, and Verification

```bash
./xenoid mcp-config
./xenoid-mcp

./xenoid build all
./scripts/verify.sh --fresh
./xenoid package-release --version 0.9.2
./xenoid verify-release dist/release/xenoid-0.9.2.tar.gz
```

Detailed contracts:

- [Command reference](docs/commands.md)
- [Architecture](docs/architecture.md)
- [Operations](docs/operations.md)
- [Build and release](docs/build.md)
- [MCP tools](docs/mcp-tools.md)
- [Remote service](docs/remote-service.md)

Use each command's `--help` output as the authoritative parameter reference.

## License

Xenoid original source is licensed under `GPL-3.0-or-later`. More-specific and third-party terms are listed in [NOTICE](NOTICE) and remain controlling for their covered material.

## Acknowledgments

Xenoid stands on upstream work. Credit belongs where it was earned:

- [Android Open Source Project](https://source.android.com/)
- [redroid](https://github.com/remote-android/redroid-doc)
- [microG](https://microg.org/)
- [LineageOS for microG](https://github.com/lineageos4microg)
- [MindTheGapps](https://gitlab.com/MindTheGapps/vendor_gapps)
- [TEESimulator](https://github.com/JingMatrix/TEESimulator)
- [Frida](https://frida.re/)

Third-party components remain under their respective licenses.
