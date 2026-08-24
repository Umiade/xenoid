# Xenoid Architecture

Xenoid is split into four layers:

1. **Local host layer** (`src/xenoid`) — CLI and fixed-instance stdio MCP for trusted local agents/users.
2. **Remote service layer** (`src/xenoid/remote_service.py`) — authenticated, scope-filtered multi-instance MCP Streamable HTTP for one fixed project.
3. **Runtime layer** — Android container backend through Docker/Colima on Apple Silicon macOS or Docker on Linux ARM.
4. **Android control layer** (`daemon`) — daemon APK exposing authenticated JSON APIs for root, global proxy desired state, camera media, Frida, profiles, automation, and OTA.

## Why a Linux VM on macOS

Android container runtimes depend on Linux kernel facilities and device namespaces. macOS does not expose those interfaces directly, so Xenoid runs an ARM64 Linux VM through Colima and starts the Android container with Docker inside it.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop` quarantines, syncs, and stops the owned container without deleting it. Its immutable container ID and data volume survive, so the next `up` starts the same container. Repeated `up`, explicit recreate, and `colima stop/start` preserve the data volume; external volume deletion or loss of private instance state fails closed instead of creating an empty disk.

Cache and login state are stored in the same `/data` partition and persist across restarts. Android's own storage pressure and app cache-clearing semantics still apply; Xenoid does not add a separate wipe-on-start mode.

The storage owner deliberately separates persistence format from device view. Host recovery and growth operate on the ext4 backing image; unprivileged Raven processes observe f2fs consistently through the canonical mount records, userdata by-name alias, libc calls, and the kernel `vfs_statfs` producer used by direct syscalls. UID-below-10000 maintenance paths retain the real backing view.

The runtime preserves Android's per-app SSAID store instead of rewriting it during profile convergence; each signing identity therefore keeps the value Android generated for that device. Profile application updates only the device-wide secure Android ID. The runtime PackageManager patch tolerates only redroid's known unsupported SELinux `restorecon` result while recovering existing `/data` app directories; every other `installd` failure remains fatal.

## Convergence ownership and recovery

`ConvergencePlanner` and `ConvergenceExecutor` are the only production convergence owners. `up` first emits a sanitized `dev.xenoid.progress/v1` `inspecting` or `resuming` event, then selects the minimum safe runtime action: `reuse`, `start`, `create`, `restart`, or `recreate`. Artifact, daemon, helper, identity, location, Keybox, camera, Google, proxy, and protection actions are independent plan fields, so component drift cannot force an unrelated image rebuild or container replacement. A healthy repeated `up` performs no compile, install, upload, recreate, or protection reload.

Before the first mutation that could expose Android egress, the executor writes a private, strict `dev.xenoid.convergence-journal/v1` record and resolves proxy quarantine for the recorded data UUID. When an image is required, the durable phase order is `planned -> quarantined -> image_ensured` before any runtime replacement. Each later phase records immutable container/image IDs, filesystem UUIDs, component generations, and the sanitized live resolution. Retry re-inspects those identities and resumes the first incomplete idempotent phase; an unrecorded third state returns `convergence_state_conflict`. The journal is deleted only after fresh final acceptance.

`status` reads this state without mutation and maps it to `recommendedAction=no-op|resume|start|create|recreate|image-required|daemon-only|daemon-incompatible|helper-only|proxy-recovery|protection-maintenance|legacy-regeneration-recovery|resource-conflict`. It never builds, retags, launches Activity/rootd, reconciles a component, or treats a valid stopped container as an error. `up --dry-run` is the actionable full plan; `up --skip-build` validates all required artifact records and fails on any stale/missing input or object.

Long convergence phases publish sanitized `running` heartbeats at least every five seconds under one outer deadline. CLI stderr carries only progress JSONL; stdout carries one final `dev.xenoid.convergence/v1` document. MCP and remote adapters call the same executor in process and return bounded safe phase summaries rather than spawning and parsing another CLI.

## Content-addressed artifacts and runtime images

`ArtifactBuilder` owns the declared build graph. Each successful `dev.xenoid.artifact/v1` record binds a target's source/command/environment/tool input digests to every output path, mode, size, architecture, and SHA-256. Output bytes are imported into immutable SHA-256 objects; consumers stage a validated `runtimeContext`, `liveDeploy`, or `release` snapshot from those objects rather than reading mutable public outputs. Normal `build all` and `up` reuse valid records and rematerialize missing public files without compilation. `build all --force` rebuilds and requires byte-for-byte deterministic outputs for the same input identity.

`RuntimeImageBuilder` hashes the immutable ARM64 base image ID, validated runtime-context artifact closure, canonical recipes/context, builder/tool identities, and the complete Google payload identity. For microG this includes the public composite metadata, both private import manifests, all three component byte/signer/path identities, the framework-policy commits and certificates, and every product-policy input and output. `inputSha256` identifies the complete image; `bootInputSha256` replaces ordinary daemon APK bytes with the verified daemon seed integration contract, allowing compatible daemon-only updates without recreate. The configured runtime tag supplies only a repository namespace; publication uses `<repository>:xenoid-<first-32-input-hex>` plus full identity labels under an engine-host lock. Xenoid never implicitly pulls a mutable base tag, accepts an occupied conflicting content tag, or retags a running instance in place. Context and JAR archives are canonicalized before hashing.

## Listener-first Android bootstrap

The daemon validates or creates its only durable credential in app-private storage, binds `GET /bootstrap/transport`, and begins accepting loopback requests before any component manager performs recovery. The host launches the Activity at most once when transport is absent, reads the credential through a metadata-validated bounded engine pipe into a container-ID-bound memory buffer, provisions authenticated rootd, and submits one generation-scoped reconcile request. No credential is persisted in host instance state, argv, environment, generic command output, progress, or logs.

Authenticated bootstrap status is schema `dev.xenoid.daemon-bootstrap/v1` with fixed `root`, `keybox`, `proxy`, `location`, and `camera` components. The coordinator reconciles them in a bounded worker; a degraded component cannot prevent the listener or unrelated managers from reporting their safe status. Enabled proxy may remain explicitly quarantined/deferred until the later host data-plane phase. Aggregate `GET /health` is final production acceptance only and is never a bootstrap prerequisite. Missing/malformed credentials, root UID/authentication failure, and unowned listeners fail closed.

## Observation and validation ownership

`LiveAcceptance` is the sole fresh production observer for an already-running owned runtime. It checks immutable runtime/storage identity, ADB boot, daemon transport and authenticated component snapshot, rootd, location/camera, proxy data-plane proof, Google binding and status-v2 minimal live checks, aggregate health, and shared-protection digest. It is read-only: it never calls `up`, daemon/rootd ensure, build/image code, doctor, gates, or a suite.

`GateRunner` owns the acyclic validation DAG. Only successful runtime-free checks may be cached by their complete source/tool/artifact input digest; `--fresh` ignores prior successes, and sensitive-data inventory is always recomputed. `doctor` consumes selected GateRunner records plus a fresh LiveAcceptance observation. Even `doctor --full` remains observational: it never converges, builds, packages, invokes a mutating gate, or recursively launches verify/CI. Runtime absence may yield `ok=true, complete=false` unless `--require-runtime` is selected.

## Default Google services runtime

Google services are image-bound and enabled for new instances by default rather than installed after boot; `init --no-google-services` is the explicit opt-out. The production release is provider `microg`, release `microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`, for Android 13/API 33 ARM64 and the `raven` product profile. It combines official microG GmsCore `v0.3.15.250932`, official GsfProxy `v0.1.0`, and the Google-signed Phonesky `30.4.17` factory seed. MindTheGapps `MindTheGapps-13.0.0-arm64-20231025_200931` remains registered only as a retired private source for that Phonesky member and its exact Store policy blocks. It is loadable for observation but never newly selectable.

The first ordinary `up` acquires the pinned third-party assets over HTTPS and publishes them through the same deep importer used by the trusted-local manual commands. MCP and remote control never accept import paths or bytes. Runtime-context generation stages exactly GmsCore, GsfProxy, Phonesky, and the generated product policy from invocation-owned sources; temporary payload, framework-resource, download, and context directories are destroyed. No Google SetupWizard is installed, `ro.setupwizard.mode` remains `UNCHANGED`, and AOSP `Provision` remains in the microG rootfs.

The services framework ports the restricted behavior from LineageOS commits `6d2955f0bd55e9938d5d49415182c27b50900b95` and `53e2f4b85ce836360dd58bdb2f0d7f42dc796443`. Only official microG `com.google.android.gms` with the pinned real microG signer and pinned requested Google certificate receives API-visible spoofing through `signatures` and `signingInfo`, plus matching `forceQueryable` treatment; its on-disk signer remains microG. GsfProxy and Phonesky retain coherent API-visible/on-disk signers. This narrow, detectable exception is not Google equivalence and grants no general signature-spoofing permission.

Status schema `dev.xenoid.google-services-status/v2` reports the three factory/effective components, `implementation=microg`, `signatureModel=restricted-spoofing`, and `storeImplementation=google-play`. `up` requires immutable identity plus minimal live acceptance for `googlePlayServices`, `accountAuth`, `cloudMessaging`, `fusedLocation`, and `playStore`. Full `fcmDelivery`, `fusedLocationBehavior`, `maps`, `auth`, and `playStoreOperations` are release-tier claims available only from the packaged release attestation; Maps is `microg-mapbox-maplibre`. `playIntegrity`, `deviceCertification`, `drm`, and `antiCheat` remain explicitly unsupported.

Each instance commits a two-phase Google binding containing the provider, release, specification fingerprint, and data-compatibility fingerprint. The same identity is carried by the managed image, container labels, rootfs source marker, status, and doctor output. Any provider, release, policy, or signer rotation requires a new instance before Android data exists. A retired MindTheGapps configuration fails with `google_services_release_retired`; every other incompatible transition fails closed without wiping, rewriting, or migrating `/data`.

## Multi-instance operation

Multiple instances share one Colima VM (macOS) or one Docker engine/binderfs (Linux ARM). Each instance gets a unique container, volume, network, MAC, IPv4/IPv6, host ADB/daemon port, and proxy routing table from the operator registry.

Runtime artifact builds use content-addressed records and normalized output-directory locks, so disjoint targets and instances may progress concurrently while shared output directories serialize. Runtime images are content-derived and shared safely by immutable input identity rather than per-instance mutable tags. Rootfs extraction streams directly to the Docker engine host and uses invocation-private work state.

Protection is one Docker-engine-host deployment, not per-instance startup state. `SharedProtectionManager` binds kmod/eBPF source/tool/kernel/engine identities to a root-owned `dev.xenoid.shared-protection/v1` record and one lock. A matching module/link/map inventory is reused across instances. eBPF replacement is staged and swapped transactionally; kmod replacement requires zero active owned runtimes. If siblings are active or ownership is ambiguous, convergence returns maintenance-required without unloading the verified deployment or disrupting another instance. `stop` never unloads shared protection.

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json --no-google-services
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

Device identity is generated once per instance. `device regenerate` publishes every stable/network/SIM/data/rootfs target once in a strict `dev.xenoid.device-regenerate/v2` journal, then the same convergence executor resumes the fixed transaction through fresh pre-/post-Google observations. Plain `up` resumes a validated v2 transaction. A legacy v1 journal lacks target values and therefore blocks with `device_regeneration_legacy_pending`; only explicit `device regenerate --restart-legacy-transaction` preserves its digest as evidence and publishes a complete v2 target before mutation.

## Remote multi-instance control plane

`xenoid-service` fixes its project root at process startup and enumerates only
that project's `.xenoid/instances/` inventory. The global operator registry does
not retain enough project identity to safely enumerate instances across unrelated
projects, so cross-project discovery is intentionally not inferred.

Access tokens are project-scoped, stored only as SHA-256 digests, and bind a set
of scopes to exact instance UUIDs or an explicit all-instance wildcard. The
remote tool catalog is derived from the local MCP catalog and then reduced by a
static policy. Build/package, host-path, host-code, deployment, binderfs, and
kernel protection operations stay local. Each advertised instance tool adds a
required `instance` schema property; protocol parameter headers and the JSON body
must agree before dispatch.

The service holds no long-lived runtime manager, daemon client, config, or lease. It resolves them again for every call. Mutations take the same per-instance operation lock as the CLI and stdio MCP, then re-resolve and verify the instance UUID inside the lock. Different instances can progress concurrently; shared artifact output locks, runtime-image publication locks, and the engine-host protection lock serialize only their actual shared resources. Remote `xenoid_up` invokes the shared executor directly, so service exit cannot create a second convergence path.

Remote reads do not implicitly repair or start the daemon. Clients explicitly
call `xenoid_up` when full convergence is required. Network results pass through
a redaction boundary before serialization, and the remote catalog excludes
unrestricted host inputs even when equivalent trusted-local CLI/MCP tools exist.

The HTTP adapter is stateless MCP 2026-07-28 at one `/mcp` POST endpoint. Its
outer trust boundary requires a bearer grant, exact Host/Origin policy, bounded
body/concurrency/rate and connection limits, short TLS/header deadlines, closed
HTTP connections, absolute external-command budgets, and matching
protocol/method/name/instance headers.
Non-loopback listeners require TLS by default. An explicit test-only insecure
HTTP opt-in retains authentication and Host/Origin guards but cannot provide
transport confidentiality. See
[`remote-service.md`](remote-service.md) for deployment and scope details.

## Host API

```bash
xenoid up
xenoid up --dry-run
xenoid doctor
xenoid init
xenoid start
xenoid stop
xenoid status
xenoid daemon health
xenoid device collect --out .xenoid/device.json
xenoid device apply examples/fingerprints/pixel-raven-android13.json
xenoid device regenerate
xenoid automation run examples/automation/tap-home.js
xenoid camera status --check
xenoid proxy status --check
xenoid device keybox status
xenoid ota check
xenoid mcp-config
```

## Daemon API

- `GET /health`
- `GET /bootstrap/transport` (public transport readiness only)
- authenticated `POST /bootstrap/reconcile`
- authenticated `GET /bootstrap/status`
- authenticated generation-matching `POST /bootstrap/cancel`
- `GET /fingerprint/collect`
- `POST /fingerprint/apply`
- `POST /fingerprint/set`
- `POST /automation/run`
- `POST /frida/start`
- `POST /frida/stop`
- `POST /input/tap`
- `POST /input/swipe`
- `GET /ota/check`
- `POST /ota/apply`
- `GET /camera/status`
- `POST /camera/source`
- `POST /camera/settings`
- `POST /camera/clear`
- `POST /camera/apply`
- `POST /camera/self-test/start`
- `GET /camera/self-test/status`
- `GET /keybox/status`
- `POST /keybox/source` with exactly `{stagingPath,size,sha256}`
- `POST /keybox/clear` with an empty object
- `GET /proxy/status`
- `POST /proxy/source`
- `POST /proxy/enabled`
- `POST /proxy/select`
- `POST /proxy/clear`
- `POST /proxy/check`
- `GET /proxy/export`
- `GET /location/status`
- `POST /location/stage`
- `POST /location/verify`


Bootstrap endpoints deliberately expose only safe schema/state/component fields. They never return daemon/root credentials, proxy-agent keys or sources, raw SIM identity, Keybox bytes/XML/digests, private paths, exception text, or raw commands. Component commands require their own authenticated component prerequisite, while `GET /health` remains the aggregate final check.
## Android 13 KeyMint HAL service

The image installs a standalone Android 13 ARM64 KeyMint HAL service, `/system/bin/hw/android.hardware.security.keymint-service`, started by init as the `keystore` user ahead of `keystore2` and declared in the vendor VINTF manifest as `android.hardware.security.keymint.IKeyMintDevice/default`. keystore2 resolves a declared AIDL KeyMint HAL in preference to its in-process km_compat fallback, so every TrustedEnvironment-level KeyMint request reaches the service over ordinary binder IPC. The service embeds TEESimulator's router and the in-process reference KeyMint TA. Because this runtime has no hardware KeyMint to forward non-target requests to, the daemon's profile targets `*` and the TA serves every caller; the stock HIDL Keymaster 4.1 service remains only for explicit SOFTWARE-level requests. The binary is an immutable, non-secret release artifact. There is no injection, no LD_PRELOAD, no ptrace, no Frida dependency, no Magisk/WebUI module, no legacy Android 10/11 keystore path, no new privileged helper, and no second daemon.

The trusted-local CLI stages a validated keybox source with strict ownership, mode, no-follow, size, and stable-file checks. Only bounded staging metadata crosses the authenticated daemon API; public status is limited to safe readiness/algorithm/count fields and never returns filenames, paths, digests, XML, DER, or private-key data. Keybox operations remain absent from MCP and remote catalogs.

Keybox initialization is independent of rootd and proxy state. The listener-first bootstrap worker reconciles a configured keybox under its own deadline after authenticated root is available; an unconfigured inactive state is healthy. A set/clear transaction never rotates or repairs the proxy encryption key, and Keybox failure remains visible without hiding proxy/root/location/camera diagnostics.

Profile `default` uses generation mode, attestation version 200, configured TEE security level 1, Verified/device-locked boot metadata, the current build identity and patch level, and no StrongBox. A daemon-private random verified-boot seed persists in no-backup storage so generated blobs remain decryptable after restart. Routing covers every caller (target `*`); the Play apps' installed UIDs stay listed so a set deletes their pre-service legacy attestation keys and they are recreated TA-backed. The configured TEE value is attestation metadata: TEESimulator executes in software, does not provide hardware key custody, and does not establish Play Integrity or Google device certification.

## Location identity

The instance's location identity (country, locale, timezone, single USIM, carrier, APN, registered LTE cell) is owned by a 0600 host state file under `.xenoid/instances/<instance>/location-identity.json`. One master seed deterministically derives a cached profile per country through domain-separated HMAC, scoped by a SIM epoch that `device regenerate` rotates (the current country then gets a fresh IMSI/ICCID/MSISDN/cell while country facts stay); the pinned dataset in `data/cellular/` (MCC/MNC, APN, LTE bands, CLDR locales, IANA timezones, libphonenumber MSISDN templates) is the only source of country facts. A version-15 legacy vendor RIL and the RadioConfig HAL produce all radio state from the staged binary profile; the image's telephony band bridge derives the app-visible LTE band from EARFCN for the legacy conversion.

Country changes are one pending transaction: stage the profile to the daemon, arm it against the runtime epoch derived from the owned container ID, recreate the container exactly once, then verify — SIM state, subscription, PLMN, LTE cell, `rmnet_data0` connectivity, locale, timezone, and provisioning are read back from framework surfaces before promotion. Crashes resume the pending transaction without regenerating identity or repeating a completed restart. The proxy data plane never observes, gates, or mutates this identity, and proxy mutations never restart the runtime.

## Camera data plane

The host streams camera media to a random, mode-`0600` ADB staging file and sends only its Android path, size, kind, and SHA-256 digest through the authenticated daemon API. The daemon validates and normalizes the import in app-private storage, then uses token-gated rootd to atomically publish a root-owned generation under `/data/misc/camera/source`. Public status omits source names, paths, and digests.

The stable-AIDL camera provider snapshots one published generation when a camera opens. Its ordered worker writes preview, YUV, and JPEG buffers, emits a monotonic shutter timestamp, and then returns matching result metadata, including coherent AE/AWB lock state used by legacy camera clients. The runtime supplies matching framework camcorder profiles for both cameras. The image-matched legacy allocator remains the sole graphics allocator; its camera-only handle extension supports flexible YUV and JPEG BLOB buffers while retaining the original RGB/framebuffer handle layout.

Photo requests fall back to the first video frame, video requests fall back to the photo, and a source-free runtime uses a generated sensor-like scene. Source changes therefore never invalidate an active session and become visible only on the next open.

## Global proxy data plane

The daemon owns encrypted desired state and exposes only redacted status. The host controller compiles endpoint, URI-list, subscription, or Clash input into a deterministic Mihomo configuration. Compilation uses a strict protocol/key allowlist and replaces source routing with one fixed `MATCH,GLOBAL` route; source rules, listeners, controller settings, and direct fallbacks do not cross the boundary. Remote subscriptions and Clash providers use bounded HTTPS fetches with public-address pinning, TLS verification, redirect revalidation, media-type checks, and a private cache.

Proxy desired state is persisted by one app-private v2 transaction owner with an independent AES-256-GCM key, immutable key/state objects, an atomic active pointer, hash-only evidence, quarantine objects, and a bounded crash-resume journal. It is cryptographically independent of KeyMint. Startup never constructs an empty state over malformed or unreadable bytes. Unreadable state leaves proxy unready and host egress quarantined until authenticated import activates a new source or explicit `proxy clear --discard-unreadable-state` performs evidence-preserving source-less recovery; ordinary clear never discards unreadable state.

Each Android instance has one root-owned reconciliation agent on the Docker engine host. The engine binds the manifest to the current container ID, runtime epoch, bridge, IPv4/IPv6 addresses, and MAC address. It creates the transparent proxy listener in a separate host network namespace and captures only that container's bridge traffic with per-instance netfilter chains. Android keeps its ordinary `rmnet_data0`, route, DNS configuration, proxy properties, and cellular network capabilities; no proxy process, TUN device, VPN transport, listening port, or proxy routing rule is added to the Android namespace. Framework and libc interface identity remains coherent for applications, while raw `RTM_GETLINK` is a privileged control-plane operation. The kernel protection module enforces that Android 13 boundary at `security_socket_create` and `security_netlink_send`: isolated processes cannot create non-Unix sockets, and ordinary app `RTM_GETLINK` sends fail with `EACCES` before the message reaches rtnetlink. Root/system `xenoid-netctl` retains ioctl and rtnetlink GET/SETLINK access, and host or unrelated container network namespaces are not changed. Xenoid's procfs/sysfs cellular identity exposure is intentionally stronger than stock Android policy; it exists to keep the regional profile coherent, not to grant raw privileged link reads to apps.

The engine installs a quarantine before configuration or lifecycle changes and opens the data plane only after the daemon's ordinary-app probe proves every requested IPv4/IPv6 DNS, TCP, and UDP capability for the exact instance, generation, check ID, and runtime epoch. A stale report cannot release a newer generation. Disable and clear operations remove owned rules and namespaces; failures remain fail-closed. Root/agent messages use direction-bound authenticated encryption with replay rejection, and unprivileged compiler/fetch workers run under separate bounded service accounts.


## Environment hiding

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
```

The daemon exposes the stable host/MCP policy facade. Runtime hiding is enforced by prop-area, bind overlays, kmod/eBPF, and the ordinary `app_process64` compatibility dependency; Magisk/Zygisk and app-wide linker preload state are not part of the production path.

## Backend modes

Xenoid supports two primary runtime backends:

- `colima-docker`: starts an ARM64 Colima VM on Apple Silicon macOS and runs redroid through Docker.
- `linux-docker`: runs redroid through a local or remote Linux ARM Docker engine.

Config examples:

```bash
./xenoid init --config examples/config-macos-colima.json
./xenoid init --config examples/config-linux-arm.json
```

```bash
./xenoid runtime-context
./xenoid runtime-build-image --dry-run
./xenoid runtime-build-image
```

Both commands consume validated artifact/object snapshots. Runtime-context generation never compiles missing artifacts, and runtime-image ensure publishes/selects the content-derived tag under an engine-host lock. Low-level `start --recreate` consumes an already verified image and never builds one; normal production callers use `up`.

## Runtime preflight

`xenoid start --dry-run` and `xenoid doctor` report:

- host OS/arch
- Docker daemon availability
- Colima availability on macOS
- binder/binderfs and ashmem/memfd assumptions for redroid
- ADB availability

This makes startup failures actionable before trying to boot Android.
