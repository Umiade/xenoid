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

`up` is the sole production convergence owner. It emits `inspecting|resuming started` before hashing, then automatically chooses no-op, journal resume, start of a matching stopped container, create, or recreate only for boot-critical drift. Daemon/helper/proxy/component drift is repaired in place when safe. With no regeneration pending, a successful final `dev.xenoid.convergence/v1` document means fresh non-converging `LiveAcceptance` passed for the final immutable runtime. When resuming a valid pending regeneration, the final result is canonical top-level `dev.xenoid.device-regenerate/v3` instead.

Use `up --dry-run` for the exact read-only plan. `up --skip-build` validates every required content-addressed artifact record/object and fails on stale/missing inputs; it does not compile or trust loose binaries. Long phases emit sanitized `dev.xenoid.progress/v1` JSONL heartbeats to stderr at least every five seconds, while stdout remains one final JSON document. Never parse child log text as status.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop` quarantines, syncs, and stops the owned container without deleting it. The immutable container ID and data volume persist, so the next `up` starts that container. Only explicit recreate may change the ID; `device regenerate` keeps the same container and rotates identity in place. External volume/state loss fails closed rather than silently creating a new device.

`delete` destroys an instance irreversibly: it removes the owned container, data volume, and Docker network, runs proxy cleanup, then drops the private control state, instance config, and operator registry lease. Any resource whose ownership labels do not match the lease aborts before removal; shared runtime images and engine-host protection are retained. Use `--dry-run` to inspect the plan first.

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

Device identity is generated once per instance. `device regenerate` records each stable, SIM, boot, storage, DRM, and Google-binding target once in a private `dev.xenoid.device-regenerate/v3` journal, commits them without stopping/removing/recreating the container, and runs one host-driven soft reboot (`rild` + `zygote`, then `keystore2` after the replacement `system_server` is live). After the replacement daemon is healthy, it deterministically derives and publishes the exact GSF Android ID offline while GmsCore is force-stopped and microG check-in is disabled. GAID is an opaque microG-generated postcondition, not a journal target: it must be nonzero and differ from the pre-transaction observation, but later GmsCore recreation may rekey it because the pinned in-memory configuration has no setter. The GAID digest is observation evidence; the GSF digest proves the exact derived target. Plain `up` resumes the same fixed v3 targets after interruption; legacy v1/v2 journals fail with `device_regeneration_legacy_pending`.

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

## Google services

New instances default to production provider/release `microg`/`microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`: official microG GmsCore `v0.3.15.250932`, official GsfProxy `v0.1.0`, and the Google-signed Phonesky `30.4.17` factory seed from retired MindTheGapps source. Use `init --no-google-services` only for an explicit no-GMS instance. The first ordinary `up` automatically acquires and verifies both private sources; the trusted-local commands below are manual/offline fallback:

```bash
./xenoid --instance play google-services import-mindthegapps \
  /path/to/MindTheGapps-13.0.0-arm64-20231025_200931.zip \
  /path/to/release.x509.pem
./xenoid --instance play google-services import-microg \
  /path/to/com.google.android.gms-250932030.apk \
  /path/to/com.google.android.gsf-8.apk
./xenoid --instance play up
./xenoid --instance play google-services status --require-runtime
```

Only the first ordinary `up` may acquire missing payloads, and only from the pinned GitHub release URLs before full importer verification. Never fetch mutable/unpinned assets, pass import paths/bytes through MCP or remote control, or copy private Google assets out of `.xenoid/`. MindTheGapps is importable only as the Phonesky/policy source and is never newly selectable; an old configured instance fails `google_services_release_retired`. Any provider, release, policy, or signer rotation requires a new instance, and `/data` is never migrated.

Restricted spoofing applies only to official microG `com.google.android.gms`: API-visible `signatures`, `signingInfo`, and `forceQueryable` use an exact package/real-signer/fake-certificate predicate while the on-disk signer remains microG. Phonesky and GsfProxy stay signer-coherent. In `googleIdentityMode=provider-managed`, `up` requires runtime-tier `googlePlayServices`, `accountAuth`, `cloudMessaging`, `fusedLocation`, and `playStore`. After `device regenerate`, `offline-seeded` mode removes `cloudMessaging` from the required set and reports it `unsupported` with `offline-checkin-disabled`; FCM registration and delivery are unavailable. Release-tier cloud/API claims require the packaged attestation. Maps is `microg-mapbox-maplibre`. Never claim Google equivalence. `playIntegrity`, `deviceCertification`, DRM playback/provisioning, and `antiCheat` are unsupported. No Google SetupWizard is installed; setup-wizard mode is unchanged and AOSP `Provision` remains.

## Device and application operations

```bash
./xenoid device collect --out .xenoid/current-device.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid device regenerate
./xenoid app install /path/on/host/app.apk
./xenoid app launch com.example.app/.MainActivity
./xenoid app uninstall com.example.app
```

Profile application regenerates unique identifiers unless `--keep-unique` is selected. `device regenerate` first rejects any checkout/runtime state that would require convergence (`./xenoid up` is the recovery), then fixes all deterministic targets before mutation, rotates them in place through one soft reboot (no container recreation), preserves user data/apps/keystore/location country and configured proxy/Keybox semantics, and resumes idempotently from its v3 journal through final fail-closed read-back. It accepts `--dry-run` but no longer accepts `--skip-build`; `up --skip-build` remains available. A completed regeneration enters `googleIdentityMode=offline-seeded`, so FCM registration/delivery are unavailable. Legacy v1/v2 journals block with `device_regeneration_legacy_pending`; delete the recorded legacy files and rerun.

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
./xenoid package-release --version 0.9.2
./xenoid verify-release dist/release/xenoid-0.9.2.tar.gz
```

Normal builds reuse content-addressed records; force requires deterministic output for unchanged inputs. Runtime images are published under content-derived tags from immutable base/artifact/tool/Google identities, with a separate boot-compatible daemon seed digest. Release packaging runs fresh non-recursive gates, snapshots validated artifacts, produces canonical archives under `SOURCE_DATE_EPOCH`, and verifies the candidate before publication. Packaged `doctor.json` is offline evidence with `complete=false`.

Shared kmod/eBPF protection is one digest-bound engine-host deployment. `stop` never unloads it; when active sibling runtimes prevent safe replacement, stop all owned runtimes and rerun `up`. Direct unload requires explicit maintenance and zero active runtimes.

Never place credentials, access tokens/cookies, private registry/endpoint details, personal paths, proxy/Keybox material, imported proprietary assets, device captures/identifiers, runtime state, or assessment details in tracked or released files.
