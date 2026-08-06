# Xenoid

[Chinese version](README_CN.md)

Xenoid orchestrates an Android cloud-phone runtime on Apple Silicon macOS and Linux ARM hosts. It is based on 64-bit redroid Android 13 and provides one control surface for startup, device profiles, a transparent global proxy, environment hiding, controlled root, Frida, eBPF, automation, OTA, CLI, and MCP operations.

The production path is:

- **macOS:** an ARM64 Colima VM with the Docker CLI;
- **Linux ARM / ARM ECS:** native Docker with binderfs;
- **Android:** the redroid 13 `64only` image;
- **control plane:** the `xenoid` CLI, `xenoid-mcp`, and the Android daemon;
- **privilege boundary:** the daemon issues short-lived tokens that rootd validates before execution; no persistent application-visible `su` path is exposed;
- **environment shaping:** rootfs/data images, mount namespaces, overlays, property-area changes, kmod/eBPF, the zygote shim, and framework/HAL patches work together.

## Quick start

### Apple Silicon macOS

Requirements: Apple Silicon, macOS, Homebrew, Python 3.9 or newer, and at least 8 GB of allocatable memory.

Clone this repository as `xenoid`, then:

```bash
cd xenoid
./xenoid install-runtime
./xenoid up
./xenoid view
```

`install-runtime` installs and validates the macOS host toolchain, prepares Colima and binderfs, and creates `.xenoid/config.json` from the macOS template when no local configuration exists. It does not start Android.

`up` is the user-facing startup command. It builds and starts the complete runtime, deploys the daemon and native helpers, applies the device profile and hiding policy, loads eBPF, and finishes with the same live-runtime validation used by `doctor --require-runtime`. If startup fails, `up` collects the standalone doctor report before returning the original failure.

No separate `doctor` command is required before or after a normal startup.

### Linux ARM / ARM ECS

Requirements: Ubuntu 22.04 or 24.04 ARM64, Python 3.9 or newer, Docker Engine, root or sudo access, and a kernel that can load `binder_linux`. Source builds also require JDK 17, Android SDK platform 35, Android build-tools 35.0.0, and Android NDK 27.2.12479018 or a compatible newer NDK.

Clone this repository as `xenoid`, then:

```bash
cd xenoid
mkdir -p .xenoid
cp examples/config-linux-arm.json .xenoid/config.json
sudo ./scripts/setup-linux-binderfs.sh
./xenoid up
```

A remote Docker context can be selected before startup:

```bash
./xenoid config set --backend linux-docker --docker-context CONTEXT_NAME
./xenoid up
```

Linux hosts must expose binderfs devices to redroid. ARM64 hosts must use the `64only` redroid image; an x86_64 image is not a substitute.

## Diagnostics

`doctor` is the standalone diagnostic and evidence command. It is not part of the normal user command sequence because `up` already uses the same checks internally.

Run a non-invasive host and runtime diagnosis:

```bash
./xenoid doctor
```

Require a live Android runtime:

```bash
./xenoid doctor --require-runtime
```

Run builds, OTA checks, runtime-context checks, hook-surface checks, and the complete live-runtime smoke path:

```bash
./xenoid doctor --full --require-runtime
```

Save the JSON report:

```bash
./xenoid doctor --out /tmp/xenoid-doctor.json
```

Important report fields:

- `ok`: every check requested by this invocation passed;
- `complete`: a real Android runtime is online and all executed checks passed;
- `runtimeAvailable`: the runtime container is running;
- `checks`: concise per-section results;
- `sections`: auditable detailed evidence;
- `nextActions`: recovery commands for failures.

The default doctor does not start Android or inject Frida. If Android is offline, host checks can pass while `complete` remains `false` and `nextActions` recommends `./xenoid up`.

## Lifecycle

```bash
./xenoid up
./xenoid status
./xenoid logs
./xenoid view
./xenoid stop
```

Common operations:

```bash
# Show the complete convergence plan without changing the runtime.
./xenoid up --dry-run

# Use prebuilt release artifacts instead of rebuilding them.
./xenoid up --skip-build

# Run an ADB command directly.
./xenoid adb shell getprop ro.product.model
```

## Global proxy

Configure the saved proxy source in the Android Xenoid settings screen or through the host CLI. Source values and credentials never belong in command arguments:

```bash
# SOCKS5, HTTP, or HTTPS endpoint; input is read without terminal echo.
./xenoid proxy set --prompt

# A direct HTTP endpoint cannot relay UDP.
./xenoid proxy set --prompt --no-udp

# Clash YAML/JSON, URI lists, and base64 URI subscriptions.
chmod 600 /path/to/proxy-source
./xenoid proxy import /path/to/proxy-source

# Online configuration URL; HTTPS is required by default.
./xenoid proxy subscribe --prompt
```

The compiler accepts SOCKS5, HTTP/HTTPS, Shadowsocks, ShadowsocksR, Trojan, VMess, VLESS, Hysteria 1/2, TUIC, AnyTLS, Mieru, and Snell nodes. Clash `proxy-providers` are fetched and merged; unsupported rules, listeners, groups, and provider settings are discarded rather than passed through to the engine.

Manage the active source and inspect redacted readiness evidence:

```bash
./xenoid proxy status --check
./xenoid proxy list
./xenoid proxy select NAME
./xenoid proxy off
./xenoid proxy on
./xenoid proxy export --out /path/to/private-backup
./xenoid proxy clear
```

Proxying is global by default. The Docker engine host transparently captures the Android container's IPv4/IPv6 DNS, TCP, and permitted UDP flows before they leave the bridge, so Java clients, native libraries, and raw sockets use the same path without Android proxy properties, a VPN transport, or a TUN device in the Android network namespace. Activation is fail-closed: traffic remains quarantined until an instance/runtime-bound ordinary-app check proves the requested data plane. `./xenoid up` restores and validates the saved desired state.


## Root

Root access is provided through the daemon and token-gated rootd; users do not need an Android root shell.

```bash
./xenoid daemon health
./xenoid root status
./xenoid root exec id
./xenoid root exec 'cat /proc/version'
```

The production rootfs contains no persistent application-visible `su` path. The CLI and MCP share the same privilege boundary.

## Camera media

Xenoid's Android settings screen and host CLI can configure a photo, a video, or both as the source for the two ordinary Camera2 devices:

```bash
./xenoid camera status
./xenoid camera set photo FILE
./xenoid camera set video FILE
./xenoid camera mode naturalized
./xenoid camera mode faithful
./xenoid camera clear photo
./xenoid camera clear all
./xenoid camera apply
./xenoid camera status --check
```

`naturalized` adds subtle frame-to-frame sensor variation; `faithful` preserves decoded source pixels apart from required scaling and camera transforms. Imports are validated and copied into private Android storage: the original host path and filename are not retained or returned. Saved camera state survives daemon and runtime restarts, while changes take effect on the next camera open.

`up` republishes the saved source state and completes an ordinary-app YUV/JPEG capture through both cameras. A source-free runtime is valid and uses the built-in fallback scene. The runtime also publishes coherent framework camcorder profiles, so the stock Android Camera app can open, capture photos, and record H.264 video without a configured source.

## Frida

Frida is an explicit analysis capability, not part of production startup. `up` stops and removes stale frida-server processes and temporary payloads.

```bash
python -m pip install frida-tools
./xenoid frida install
./xenoid frida start
./xenoid frida status
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

`frida install` matches the installed host `frida-tools` version, downloads the corresponding `android-arm64` server, and deploys it through daemon/rootd. An existing server binary can also be deployed directly:

```bash
./xenoid frida deploy /path/to/frida-server
./xenoid frida deploy-scripts
```

Frida is appropriate for dynamic app-process analysis and app-layer hooks. Filesystem, mount, Binder, HAL, and kernel-visible surfaces are handled at system layers.

## Device profiles

Collect the current profile:

```bash
./xenoid device collect --out /tmp/device-profile.json
```

Apply a profile and regenerate unique identifiers:

```bash
./xenoid device apply examples/fingerprints/sample-profile.json
```

Apply the profile's explicit unique identifiers without generating replacement values:

```bash
./xenoid device apply examples/fingerprints/sample-profile.json --keep-unique
```

Generate app-layer and service-layer Frida profiles:

```bash
./xenoid device generate-frida examples/fingerprints/sample-profile.json --out /tmp/device-profile.js
./xenoid device generate-service-frida examples/fingerprints/sample-profile.json --out /tmp/service-profile.js
```

`device apply` synchronizes daemon profile state, SettingsProvider, property-area state, and reboot-persistent data. After changing profiles, cold-start the target application and recollect the complete profile; one `getprop` value is not sufficient evidence.

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

Low-level input uses the `/dev/uinput` helper through the daemon. Automation supports ordered actions and host-side execution. Use each subcommand's `--help` output as the authoritative parameter reference.

## Network identity

```bash
./xenoid netctl status --ifname eth0
./xenoid netctl set-mac 02:00:00:00:00:01 --ifname eth0
```

A coherent network profile includes interfaces, routes, namespaces, MAC addresses, and framework-visible values; changing one property is insufficient.

## OTA

```bash
./xenoid ota make --version 0.1.0
./xenoid ota install-bundle dist/ota/xenoid-0.1.0.tar.gz
./xenoid ota check
./xenoid ota apply
```

An OTA bundle contains the daemon and native runtime helpers plus manifest/hash metadata. Frida server and scripts remain separate, explicit analysis installs.

## MCP

Generate a stdio MCP configuration:

```bash
./xenoid mcp-config
```

Or start the server directly:

```bash
./xenoid-mcp
```

Representative tools include:

- `xenoid_doctor` with `full` and `requireRuntime`;
- `xenoid_up_plan` for a non-mutating full-startup plan;
- `xenoid_stop` and `xenoid_status` for runtime lifecycle control;
- `xenoid_root_status` and `xenoid_root_exec`;
- `xenoid_frida_install` and `xenoid_frida_load_script`;
- `xenoid_device_collect` and `xenoid_device_apply`;
- `xenoid_automation_run` and `xenoid_input_tap`.

MCP does not bypass daemon tokens, backend constraints, or runtime preconditions. Before granting an agent mutating tools, define the target runtime, package, and permitted operation scope.

See [`docs/mcp-tools.md`](docs/mcp-tools.md) for the complete tool contract.

## Configuration

```bash
./xenoid config show
./xenoid config set --backend colima-docker
./xenoid init --backend colima-docker
```

Configuration examples:

- `examples/config-macos-colima.json`
- `examples/config-linux-arm.json`

Local configuration is stored in `.xenoid/config.json`. Never commit credentials, tokens, private image addresses, or workstation-specific absolute paths.

## Build and release

```bash
./xenoid build all
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Build individual components:

```bash
./xenoid build daemon
./xenoid build input
./xenoid build profile
./xenoid build netctl
```

Release bundles contain the CLI, MCP server, runtime assets, daemon APK, native helpers, configuration examples, skill files, `doctor.json`, and a SHA-256 manifest.

## Roadmap

- [ ] Add a programmable host eBPF hook interface for trusted operators: user-owned CO-RE programs, isolated lifecycle and event streams, atomic replacement, rollback, and optional startup restoration without replacing Xenoid's built-in runtime protections.

## Architecture and detailed documentation

- [`docs/architecture.md`](docs/architecture.md): architecture and trust boundaries;
- [`docs/operations.md`](docs/operations.md): runtime, troubleshooting, and release operations;
- [`docs/profile-and-hiding.md`](docs/profile-and-hiding.md): device profiles and environment hiding;
- [`docs/build.md`](docs/build.md): build artifacts and dependencies;
- [`docs/mcp-tools.md`](docs/mcp-tools.md): MCP tool parameters.
