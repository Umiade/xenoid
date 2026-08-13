# Xenoid Operator Skill

Use this skill to install, start, inspect, and operate a Xenoid Android runtime through the CLI or MCP server.

## Supported hosts

- Apple Silicon macOS with Homebrew and Colima.
- Linux ARM64 with Docker Engine and binderfs.

Android runs from the configured 64-bit redroid Android 13 image. Local state belongs under `.xenoid/`.

## Default workflow

On Apple Silicon macOS:

```bash
./xenoid install-runtime
./xenoid up
./xenoid view
```

On Linux ARM64, prepare binderfs and initialize the default instance from the template:

```bash
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
./xenoid up
```

`up` owns runtime preflight, build or artifact validation, Android startup, daemon deployment, device-profile application, production protection activation, and the final live-runtime check. A successful return means the complete configured runtime is ready.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop`, repeated `up`, container recreate, and `colima stop/start` preserve the data volume. `colima delete`, external volume deletion/prune, or loss of the host instance state will cause Xenoid to fail hard on next startup rather than silently create an empty disk.

Cache and login state are stored in the same `/data` partition and persist across restarts. Android's own storage pressure and app cache-clearing semantics still apply; Xenoid does not add a separate wipe-on-start mode.

Raven applications observe the profile-owned f2fs contract across mount records, the userdata by-name alias, libc filesystem calls, and direct raw syscalls. Root maintenance continues to inspect the real ext4 backing image.

## Multi-instance operation

Multiple instances share one Colima VM (macOS) or one Docker engine/binderfs (Linux ARM). Each instance gets a unique container, volume, network, MAC, IPv4/IPv6, host ADB/daemon port, and proxy routing table from the operator registry.

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

Device identity (Android ID, serial, IMEI/IMEISV) is generated once per instance and persisted in `~/.xenoid/instances/<UUID>/device-identity.json`. Boot-scoped values (`boot_id`, `random_uuid`) rotate on container recreation. Explicit rotation via `device apply --keep-unique` or `device set` updates the same host state so the next `up` does not revert identity.

## Runtime inspection

```bash
./xenoid status
./xenoid doctor
./xenoid logs
./xenoid view
./xenoid stop
```

Use `doctor --require-runtime` when an online Android instance is mandatory. Use `doctor --full --require-runtime` only when exhaustive build and runtime evidence is required.

## Optional Google services

Google services are disabled by default and may be selected only before an instance has Android storage. The sole known release is `MindTheGapps-13.0.0-arm64-20231025_200931`. Import the official ZIP and matching `release.x509.pem` locally, then enable and converge:

```bash
./xenoid --instance play google-services import-mindthegapps \
  /path/to/MindTheGapps-13.0.0-arm64-20231025_200931.zip \
  /path/to/release.x509.pem
./xenoid --instance play google-services enable
./xenoid --instance play up
./xenoid --instance play google-services status --require-runtime
```

Never download the payload implicitly, pass import paths through MCP, copy private Google assets out of `.xenoid/`, or claim Play Integrity/device certification from package presence. A provider change after data creation requires a new instance. Account login remains manual.

## Device and application operations

```bash
./xenoid device collect --out .xenoid/current-device.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid app install /path/on/host/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid app uninstall com.example.app
```

Profile application regenerates unique identifiers unless `--keep-unique` is selected.

## Location identity

```bash
./xenoid location list
./xenoid location status --check
./xenoid location set US
```

Location selects the device's country profile (locale, timezone, USIM, carrier, LTE cell) and is fully independent of the global proxy. A fresh instance defaults to Singapore on the first `up`. Re-selecting the current country is a no-op; changing it recreates the owned container exactly once and restores the original identity when switching back to a previously used country. After a standalone `location set`, run `up` again for full production validation. Proxy operations never change location, and location changes never inspect proxy egress.

## Camera media

```bash
./xenoid camera status
./xenoid camera set photo FILE
./xenoid camera set video FILE
./xenoid camera mode naturalized
./xenoid camera mode faithful
./xenoid camera clear all
./xenoid camera apply
./xenoid camera status --check
```

The daemon validates imports, stores them on persistent Android `/data`, and never retains the original host path. Changes apply on the next camera open. `up` republishes saved state and runs the ordinary-app Camera2 self-test; a source-free fallback is a ready state.

## Input and automation

```bash
./xenoid input tap 540 1800
./xenoid input swipe 540 1600 540 400 500
./xenoid automation plan examples/automation/ordered-task.js
./xenoid automation run examples/automation/ordered-task.js
```

Automation scripts should use the Xenoid task API. `templates/automation-script.js` is the local template.

## Root boundary

Privileged Android operations pass through the daemon and token-gated root helper:

```bash
./xenoid root status
./xenoid root exec id
```

Do not create persistent `su` paths or bypass the daemon token boundary.

## Frida

Frida is explicit and is not active after normal production startup:

```bash
./xenoid frida install
./xenoid frida start
./xenoid frida load-script com.example.app frida/scripts/xenoid-default.js --spawn
./xenoid frida stop
```

Run `up` again to restore the complete production state after an analysis session.

## MCP

Generate a stdio MCP configuration:

```bash
./xenoid mcp-config
```

The MCP server exposes the same runtime and daemon boundaries as the CLI. Mutating calls require an explicit target and should not receive credentials or unrestricted host paths.

## Configuration and release

```bash
./xenoid config show
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Never place credentials, access tokens, private registry addresses, personal paths, or device dumps in tracked files.
