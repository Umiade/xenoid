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

`up` is the sole production convergence owner. It emits `inspecting|resuming started` before hashing, then automatically chooses no-op, journal resume, start of a matching stopped container, create, or recreate only for boot-critical drift. Daemon/helper/proxy/component drift is repaired in place when safe. A successful final `dev.xenoid.convergence/v1` document means fresh non-converging `LiveAcceptance` passed for the final immutable runtime.

Use `up --dry-run` for the exact read-only plan. `up --skip-build` validates every required content-addressed artifact record/object and fails on stale/missing inputs; it does not compile or trust loose binaries. Long phases emit sanitized `dev.xenoid.progress/v1` JSONL heartbeats to stderr at least every five seconds, while stdout remains one final JSON document. Never parse child log text as status.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop` quarantines, syncs, and stops the owned container without deleting it. The immutable container ID and data volume persist, so the next `up` starts that container. Explicit recreate/regenerate may change the ID but preserve data. External volume/state loss fails closed rather than silently creating a new device.

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

Device identity is generated once per instance. `device regenerate` records every stable/network/SIM/data/rootfs target once in a private v2 journal, then invokes the same in-process convergence executor and clears configured Google packages only after fresh pre-Google acceptance. Plain `up` or `device regenerate` resumes the same fixed targets after interruption. A legacy v1 journal is never guessed through: ordinary `up` returns `device_regeneration_legacy_pending`; only `device regenerate --restart-legacy-transaction` preserves v1 evidence and publishes a complete v2 target before mutation.

## Runtime inspection

```bash
./xenoid status
./xenoid doctor
./xenoid logs
./xenoid view
./xenoid stop
```

`status` is strictly observational. Read `recommendedAction`, drift reasons, cache/image/protection digests, and any pending journal phase. It never starts Activity/rootd, builds, retags, or reconciles; a valid stopped container remains valid and recommends `start`.

`doctor` combines digest-aware GateRunner records with a fresh read-only `LiveAcceptance` observation of an already-running instance. `doctor --full` only selects the broader doctor-safe record set; it never calls `up`, ensures daemon/rootd, builds/packages, invokes mutating gates, or recursively runs a suite. Use `--require-runtime` when `complete=true` is mandatory. Use `./scripts/verify.sh --fresh` for fresh static evidence.

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
./xenoid device regenerate
./xenoid app install /path/on/host/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid app uninstall com.example.app
```

Profile application regenerates unique identifiers unless `--keep-unique` is selected. `device regenerate` fixes all targets before mutation, preserves user data/apps/keystore/location country and configured proxy/Keybox semantics, and resumes idempotently from its v2 journal through final fresh acceptance. `--skip-build` validates existing records and `--dry-run` only returns the plan. The explicit `--restart-legacy-transaction` escape is required for v1-only journals and may rotate already-changed factors once more.

## Android 13 KeyMint keybox

Keybox operations are trusted-local CLI only:

```bash
chmod 600 /secure/local/keybox.xml
./xenoid device keybox set /secure/local/keybox.xml
./xenoid device keybox status
./xenoid device keybox clear
```

The source must be a current-user-owned nonempty regular file, not a symlink, no larger than 8 MiB, with no group/world permission bits. Never publish keybox XML, DER/private keys, digests, staging paths, or app-private state. Listener startup is independent: transport binds first, then the bounded bootstrap worker reconciles Keybox after authenticated root. Keybox state and proxy encryption state are separate transactions; failure in one remains visible without mutating or hiding the other.

This workflow is Android 13 ARM64 only and affects `com.google.android.gms` and `com.android.vending`; other callers keep the stock path. Generated attestation is software-executed even though it reports the configured KeyMint TEE security-level metadata. Do not describe it as hardware key custody, Play Integrity support, or Google device certification.

## Location identity

```bash
./xenoid location list
./xenoid location status --check
./xenoid location set US
```

Location selects the device's country profile (locale, timezone, USIM, carrier, LTE cell) and is fully independent of the global proxy. A fresh instance defaults to Singapore on the first `up`. Re-selecting the current country is a no-op; changing it recreates the owned container exactly once and restores the identity of a previously used country within the same SIM epoch (`device regenerate` rotates the SIM epoch). After a standalone `location set`, run `up` again for full production validation. Proxy operations never change location, and location changes never inspect proxy egress.

## Global proxy recovery

Proxy desired state uses an app-private v2 transaction store and independent AES-256-GCM key, never the KeyMint keybox. Every lifecycle mutation quarantines first and releases only after an exact generation/runtime data-plane proof.

If status reports unreadable state, never treat it as disabled. Recover by authenticated `proxy import FILE`, or explicitly run:

```bash
./xenoid proxy clear --discard-unreadable-state
```

That operation preserves hash evidence and quarantines invalid control bytes before a cryptographic clear. Ordinary `proxy clear` refuses unreadable state and never silently releases direct egress.

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

Privileged Android operations pass through the daemon and loopback-only token-gated root helper:

```bash
./xenoid root status
./xenoid root exec id
```

The only durable credential is app-private. The host may hold it only in a container-ID-bound memory buffer and passes it to rootd through stdin; it never persists a host token file/cache or exposes it in argv, results, progress, or logs. Missing/malformed credentials, failed root proof, and unowned listeners fail closed. Do not create `su` paths or bypass this boundary.

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
Put the repository `xenoid-mcp` launcher on the MCP client's `PATH`; generated
configuration deliberately contains no absolute workspace path.


The stdio MCP server is trusted-local and fixed to one instance. Use `xenoid_up` when complete production readiness is required; it accepts only optional boolean `skipBuild`, calls the shared executor directly, and returns safe phase summaries in one final result. Reuse is automatic. `xenoid_status` remains observational, and `xenoid_doctor` never converges.

For remote multi-instance access, create a scoped token and keep the service on
loopback behind SSH/VPN or a trusted TLS/OAuth gateway:

```bash
./xenoid-service token create \
  --name operator --all-instances --scope read --scope control
./xenoid-service serve --bind 127.0.0.1 --port 8765
```

Temporary testing on an explicitly trusted LAN may instead bind `0.0.0.0` with
an exact `--allow-host` and `--allow-insecure-http`. This opt-in sends bearer
tokens and MCP traffic in plaintext and is not a production deployment mode.

The network catalog requires an explicit authorized `instance` for every
instance tool and intentionally omits arbitrary host paths, host scripts,
build/package/deploy, binderfs, and host protection operations. Grant `root` and
`inspect` separately from ordinary `control`. Run the service as the same OS
user/HOME as the CLI and Colima/Docker state; use a macOS user LaunchAgent or a
Linux ARM64 systemd unit with that fixed identity. Follow
[`docs/remote-service.md`](../../docs/remote-service.md) for TLS, Origin/Host,
token rotation, and service-manager examples.

The remote service adds required `instance` to each instance tool. Remote `xenoid_up` has the same optional `skipBuild` field and never spawns/parses a nested CLI. Network results exclude credentials, proxy/Keybox/SIM bytes, private paths/endpoints, raw streams/commands/responses, captures, and assessment details.

## Configuration and release

```bash
./xenoid config show
./xenoid build all
./xenoid build all --force
./scripts/verify.sh --fresh
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Normal builds reuse content-addressed records; force requires deterministic output for unchanged inputs. Runtime images are published under content-derived tags from immutable base/artifact/tool/Google identities, with a separate boot-compatible daemon seed digest. Release packaging runs fresh non-recursive gates, snapshots validated artifacts, produces canonical archives under `SOURCE_DATE_EPOCH`, and verifies the candidate before publication. Packaged `doctor.json` is offline evidence with `complete=false`.

Shared kmod/eBPF protection is one digest-bound engine-host deployment. `stop` never unloads it; when active sibling runtimes prevent safe replacement, stop all owned runtimes and rerun `up`. Direct unload requires explicit maintenance and zero active runtimes.

Never place credentials, access tokens/cookies, private registry/endpoint details, personal paths, proxy/Keybox material, imported proprietary assets, device captures/identifiers, runtime state, or assessment details in tracked or released files.
