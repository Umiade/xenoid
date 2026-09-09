# Xenoid Operations

## Apple Silicon macOS

Requirements: Apple Silicon, macOS, Homebrew, Python 3.9 or newer, and at least 8 GB of allocatable memory.

Clone this repository as `xenoid`, then:
```bash
cd xenoid
./xenoid install-runtime
./xenoid init --config examples/config-macos-colima.json
./xenoid up
./xenoid view
```

`install-runtime` installs and validates Docker CLI, Colima, ADB, scrcpy, JDK 17, Android SDK platform/build-tools 35, and Android NDK. It prepares the ARM64 Colima VM and binderfs and explicitly pulls the canonical ARM64 redroid base at its pinned image identity. If direct Docker Hub access is unavailable, it uses a content-addressed mirror and rejects any identity mismatch; `up` never implicitly refreshes the base and `init` remains the explicit instance-creation step.

`up` is the sole production convergence owner. It validates/reuses artifacts, ensures a content-addressed image only when needed, selects the minimum safe runtime action, reconciles independent components, and returns success only after fresh `LiveAcceptance` for the final runtime. Healthy repeated runs are no-ops apart from fresh observation; daemon/helper/proxy-only drift does not recreate the container.

When the configured engine is stopped — Colima VM after a macOS reboot, or the local docker service on Linux — `up` starts it before observing; remote engines and first-time installation are never attempted (that stays with `install-runtime`/`init`). The same phase ensures the engine host's kernel-matched prerequisites: the binder module is loaded before protection maintenance, and missing `linux-headers-$(uname -r)` are installed on apt-managed engine hosts before the kmod build. A retained convergence journal whose recorded inputs no longer match the environment is discarded and replanned fresh rather than failing `convergence_inputs_changed`.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a grow-only sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop` installs/verifies proxy quarantine, syncs, and stops the owned container without removing it. The immutable container ID and data volume survive, so `stop -> up` starts the same container. Explicit recreate and regenerate may change the ID but preserve the data volume. External volume deletion/prune or loss of private host state fails closed rather than creating an empty disk.

Cache and login state are stored in the same `/data` partition and persist across restarts. Android's own storage pressure and app cache-clearing semantics still apply; Xenoid does not add a separate wipe-on-start mode.

The canonical Raven profile requests a 128,000,000,000-byte logical data device and an Android-facing f2fs contract. Xenoid grows an existing smaller ext4 backing image transactionally before startup, preserves its filesystem UUID and data, and resumes or rolls back an interrupted host-side growth transaction. It never shrinks, recreates, or silently replaces a committed image. After profile convergence, `/proc/partitions`, `/proc/diskstats`, `/dev/block/sda`, the Raven userdata by-name alias, block sysfs, mount records, and unprivileged libc/raw-syscall filesystem magic must agree. Privileged maintenance still sees ext4.

Sparse capacity is not host-space preallocation. `doctor` reports conservative Docker/Colima backing-store headroom; if the backing filesystem is exhausted, Android writes fail with `ENOSPC` while the image and UUID remain intact. The 12 GiB Android memory view is likewise independent of the lower host/Colima runtime allocation.

## Multi-instance operation

Multiple instances share one Colima VM (macOS) or one Docker engine/binderfs (Linux ARM). Each instance gets a unique container, volume, network, MAC, IPv4/IPv6, host ADB/daemon port, and proxy routing table from the operator registry.

Artifact builds use content-addressed records plus output-directory locks: disjoint targets/instances can proceed concurrently, while shared output directories serialize. Runtime images are shared by immutable content identity rather than per-instance mutable tags. Shared kmod/eBPF protection is deployed once per Docker engine host and reused by all matching instances.

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json --no-google-services
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

Device identity is generated once per instance. `device regenerate` publishes all stable/network/SIM/data/rootfs targets once in a v2 journal, then recreates and converges through the shared executor; for any configured non-`none` Google provider, fresh pre-Google acceptance gates clearing exactly `com.google.android.gms`, `com.google.android.gsf`, and `com.android.vending`. Plain `up` resumes a validated v2 transaction. A v1-only journal blocks until the operator explicitly runs `device regenerate --restart-legacy-transaction`.

## Linux ARM

Requirements: Ubuntu 22.04 or 24.04 ARM64, Python 3.9 or newer, Docker Engine, root or sudo access, and a kernel with `binder_linux`. Source builds also require JDK 17, Android SDK platform 35, Android build-tools 35.0.0, and Android NDK 27.2.12479018 or a compatible newer release.

```bash
cd xenoid
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
./xenoid up
```

Release bundles can require prebuilt evidence:

```bash
./xenoid up --skip-build
```

This validates every required artifact record and immutable object, including current source/tool inputs and output mode/size/architecture/digest. Missing or stale data fails; it never compiles or trusts an arbitrary public output.

Linux ARM hosts must expose binderfs to the Android container and use the redroid Android 13 `64only` image.

## Lifecycle

```bash
./xenoid up
./xenoid status
./xenoid logs --out-dir .xenoid/logs
./xenoid view
./xenoid stop
```

`up` automatically chooses `no-op`, journal `resume`, `start` for a matching stopped container, `create`, or `recreate` for boot/create-spec/storage drift. Compatible daemon APK and helper drift is deployed in place; proxy, identity, location, Keybox, camera, Google, and protection have independent actions. `start` is the low-level container control and is not a production-ready contract.

Before an operation can expose Android egress, the executor persists the plan and proves proxy quarantine against the same data UUID. If a desired image is needed, it records `quarantined` before `image_ensured`, and only then quiesces/removes/creates runtime state. A failure or interruption preserves the journal, selected immutable image identity, and quarantine for retry.

`status` is strictly observational. Read `recommendedAction`, `driftReasons`, cache/image/protection digests, and `pendingJournalPhase`; it never starts Activity/rootd, builds, retags, reconciles, or changes exit status merely because a valid container is stopped. Use `up --dry-run` for the exact actionable initial or resume plan.

Before any hashing, stderr receives a `dev.xenoid.progress/v1` `inspecting` or `resuming` `started` event. Long phases publish sanitized `running` heartbeats at least every five seconds. Stdout remains one final `dev.xenoid.convergence/v1` JSON document with the plan, `resumed`, safe phase results, immutable before/after IDs, and `nextActions`; no credential, private path, raw command/response, or successful child tail is retained.

## Diagnostics and validation

```bash
./xenoid doctor
./xenoid doctor --require-runtime
./xenoid doctor --full --require-runtime
./xenoid doctor --out /tmp/xenoid-doctor.json
```

- `GateRunner` supplies digest-aware static gate records; local verify/doctor may reuse a matching successful runtime-free record.
- `LiveAcceptance` freshly and read-only observes an already-running owned runtime. It never converges or calls doctor/gates.
- `doctor` composes those two sources without starting/repairing daemon/rootd, calling `up`, building an artifact/image, packaging, or invoking another suite.
- `--full` selects the broader doctor-safe record set and fresh live observation; it does not execute mutating CI/release gates.
- Runtime absence may be `ok=true, complete=false`; `--require-runtime` fails it. A cache hit can never make `complete=true`.

For fresh static evidence, use `./scripts/verify.sh --fresh`. CI and release select the same acyclic GateRunner catalog; no audit-bypass variable or recursive verify/CI/doctor invocation exists.

## Listener-first bootstrap and final acceptance

When daemon transport is absent, `up` launches the Activity at most once and waits for public `GET /bootstrap/transport`. After the listener answers, it reads the strictly validated app-private credential into a bounded in-memory buffer, proves authenticated UID-0 rootd, posts one generation-scoped reconcile request, and polls `dev.xenoid.daemon-bootstrap/v1`.

Bootstrap reports fixed `root`, `keybox`, `proxy`, `location`, and `camera` component states. A failed component cannot suppress transport or unrelated diagnostics; an enabled proxy may remain quarantined/deferred until the later host data-plane phase. Aggregate `GET /health` is checked only during final acceptance and never gates bootstrap recovery. Transport, root, worker, boot, and proxy waits have named bounded deadlines; interruption preserves journals/quarantine for resume.

Bootstrap/status/results never expose daemon/root credentials, proxy-agent keys or source, raw SIM identity, Keybox XML/DER/digests, private paths, exception text, or raw daemon responses. Missing/malformed credentials, 401 root authentication, unsafe legacy state, and unowned listener conflicts return stable fail-closed codes.

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

## Google Play services (default)

New instances default to provider/release `microg`/`microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0` for Android 13/API 33, `arm64-v8a`, and product `raven`. Use `init --no-google-services` only when an instance must be created without GMS. The retired `mindthegapps` pair remains loadable for observation and private source verification, but is never selectable as a runtime.

Xenoid does not redistribute proprietary Google binaries in source or release archives. On the first ordinary `up`, it automatically downloads these exact upstream assets over HTTPS into ignored local state and validates every registered size, SHA-256, certificate, package, signer, SDK, ABI, fake-signature, and Maps-flavor contract before publishing them:

- [`MindTheGapps-13.0.0-arm64-20231025_200931`](https://github.com/MindTheGapps/13.0.0-arm64/releases/tag/MindTheGapps-13.0.0-arm64-20231025_200931): `MindTheGapps-13.0.0-arm64-20231025_200931.zip` and `release.x509.pem`, used only as the retired Phonesky/Store-policy source;
- [microG GmsCore `v0.3.15.250932`](https://github.com/microg/GmsCore/releases/tag/v0.3.15.250932): the standard `com.google.android.gms-250932030.apk` asset, not the `-hw` or user-preview variant;
- [microG GsfProxy `v0.1.0`](https://github.com/microg/GsfProxy/releases/tag/v0.1.0): download `GsfProxy.apk` and rename it to the pinned import basename `com.google.android.gsf-8.apk`;
- JDK `keytool`/`jarsigner` and Android SDK `aapt2`/`apksigner`, installed and checked by `./xenoid install-runtime`.

Manual or offline pre-staging remains available:

```bash
./xenoid --instance play init --config examples/config-macos-colima.json
./xenoid --instance play google-services import-mindthegapps \
  /path/to/MindTheGapps-13.0.0-arm64-20231025_200931.zip \
  /path/to/release.x509.pem
./xenoid --instance play google-services import-microg \
  /path/to/com.google.android.gms-250932030.apk \
  /path/to/com.google.android.gsf-8.apk
./xenoid --instance play up
./xenoid --instance play google-services status --require-runtime
```

For an explicit no-GMS instance:

```bash
./xenoid --instance no-gms init \
  --config examples/config-macos-colima.json \
  --no-google-services
./xenoid --instance no-gms up
```

Automatic acquisition and manual imports are project-scoped, repeatable, and converge through the same deep validation and atomic `0700`/`0600` publication path. Automatic acquisition accepts only the metadata-derived pinned GitHub release URLs; manual imports perform no network access. MCP and remote control never accept import paths or bytes. Failure output uses stable error codes and never returns stored paths.

`enable` remains available only for a fresh instance that was explicitly created without GMS. When an image is required, `up` publishes a content-addressed image whose immutable record binds both source releases, all component bytes/signers/paths, framework signature policy, product policy, artifact closure, and boot policy. Any provider, release, policy, or signer change after data creation requires a new instance; Xenoid never wipes or migrates `/data`. An old MindTheGapps-configured instance fails with `google_services_release_retired` and a create-new-instance action without touching its data.

The image applies `restricted-spoofing` only to the official microG `com.google.android.gms`, using the behavior pinned from LineageOS commits `6d2955f0bd55e9938d5d49415182c27b50900b95` and `53e2f4b85ce836360dd58bdb2f0d7f42dc796443`. PackageManager `signatures`, `signingInfo`, and `forceQueryable` are changed only when the package, real microG signer, and requested Google certificate all match. The APK remains microG-signed on disk; GsfProxy and Phonesky keep matching API-visible/on-disk signers. This detectable exception is not Google equivalence.

No Google SetupWizard is installed. `ro.setupwizard.mode` remains unchanged and AOSP `Provision` remains installed. Product policy enables the required account, background-service, messaging, location, and Store integration without granting a general signature-spoofing permission.

Status v2 reports `implementation=microg`, `signatureModel=restricted-spoofing`, `storeImplementation=google-play`, exact factory/effective components, immutable binding and image/rootfs identity, live checks, and capability state. Ordinary `up` requires minimal live health for runtime-tier `googlePlayServices`, `accountAuth`, `cloudMessaging`, `fusedLocation`, and `playStore`; it does not run cloud/API tests. Full release-tier `fcmDelivery`, `fusedLocationBehavior`, `maps`, `auth`, and `playStoreOperations` are claimed only by the packaged release attestation, and Maps uses `microg-mapbox-maplibre`. `playIntegrity`, `deviceCertification`, `drm`, and `antiCheat` are always `unsupported`.

Focused smoke commands are explicit validation operations. They do not call doctor from inside the runtime transaction, and production convergence/regeneration never calls them:

```bash
./scripts/smoke-google-services-runtime.sh --instance play
./scripts/smoke-google-services-convergence.sh --instance play
```

The runtime smoke uses an ordinary non-debuggable probe to validate component/signature policy, authenticator, broker, FCM registrar, fused provider, Store launcher, process stability, and the negative signature-spoof boundary. Once-per-release cloud/API and Play Store operations are separate release-gate inputs and may be reflected publicly only through sanitized `evidence/google-services-release.json`.

Xenoid publishes only verification metadata and a normalized release attestation needed for reproducibility. Imported APK/ZIP/certificate bytes and private test evidence remain local and are never included in Xenoid source, release archives, or OTA bundles.

## Remote Linux Docker engine

```bash
docker context create linux-arm --docker host=ssh://user@server
./xenoid config set --backend linux-docker --docker-context linux-arm
./xenoid up
```

With `backend=linux-docker`, Xenoid prepares binder and runtime protection on the selected Docker engine host and does not start local Colima.

## Remote Xenoid service

A remote Docker context is a backend transport for a trusted local CLI; it does
not publish a Xenoid API. To let remote users or model clients operate every
initialized instance on the Mac/Linux ARM host, run `xenoid-service` on that
host under the same operator user and `HOME` as the CLI:

```bash
./xenoid-service token create \
  --name operator --all-instances --scope read --scope control
./xenoid-service serve --bind 127.0.0.1 --port 8765
```

Use loopback through SSH/VPN or a trusted TLS/OAuth gateway. Direct non-loopback
listeners require a TLS certificate/key and an explicit Host allowlist by
default. Temporary trusted-network cleartext testing additionally requires
`--allow-insecure-http`; its bearer tokens and requests are unencrypted. Browser
Origins are denied unless explicitly allowed. Token grants can target immutable
instance UUIDs or an all-instance wildcard, and `root`/`inspect` remain separate
from ordinary control.

The service manages one fixed project and only instances already initialized in
that project. It re-resolves state for every request and serializes mutations per
instance. Use the remote `xenoid_up` tool for complete production convergence;
lower-level status/control calls never mean the full `up` contract succeeded.

Remote `xenoid_up` accepts only the optional boolean `skipBuild` (plus the service-added required `instance`). It calls the shared in-process convergence executor and returns sanitized phase summaries in one final result; it does not spawn/parse a nested CLI or expose stderr/stdout tails. `xenoid_status` remains observational.

On macOS, install it as a user LaunchAgent so it retains access to the user's
Colima VM and `~/.xenoid`. On Linux ARM64, set the systemd `User`, `HOME`, and
`WorkingDirectory` to the existing Xenoid operator. Full unit examples, token
rotation, protocol headers, and reverse-proxy guidance are in
[`remote-service.md`](remote-service.md).

## Location identity

One persistent per-instance profile owns the country, system locale list, IANA timezone, single USIM, carrier, APN, and registered LTE cell. The legacy vendor RIL and the RadioConfig HAL are the only producers of radio data; the daemon publishes the profile, converges provisioning and the APN, and verifies framework, subscription, cell, and connectivity surfaces before the identity counts as active.

```bash
./xenoid location list              # supported countries: AU DE GB HK JP SG US
./xenoid location status            # masked host and Android state
./xenoid location status --check    # require active digests to match in the current epoch
./xenoid location set US            # select a country and converge
```

A new instance applies Singapore on the first `./xenoid up`; later runs keep the persisted selection. Re-selecting the current country is a no-op. Changing the country stages the new profile and recreates the owned container exactly once — the restart is atomic across crashes, so retrying a failed `location set` resumes the same pending identity instead of generating a new one or restarting twice. Each used country's identity is cached from the instance master seed, so returning to a previous country restores its SIM, phone number, and cell within the same SIM epoch; `device regenerate` rotates the SIM epoch (a fresh SIM for the current country). Hardware identifiers never change with location. Numbers follow pinned libphonenumber mobile metadata for shape and length; they are synthetic and cannot originate calls or SMS. A standalone `./xenoid location set` performs its own container recreate; run `./xenoid up` afterwards for a full production validation. Location never reads proxy egress, and proxy operations never read or mutate the location identity.

## Global proxy

The Android Xenoid settings screen and host CLI modify the same daemon-owned desired state. Keep credentials out of argv, shell history, public configuration, and tracked files:

```bash
# Read one endpoint or URI without terminal echo.
./xenoid proxy set --prompt

# Import Clash YAML/JSON, a URI list, or a base64 URI subscription.
chmod 600 /path/to/proxy-source
./xenoid proxy import /path/to/proxy-source

# Save an online configuration URL. HTTPS is mandatory by default.
./xenoid proxy subscribe --prompt

# Show redacted state and run a new data-plane proof.
./xenoid proxy status --check
```

`set` and `import` infer `endpoint`, `uri_list`, or `clash`; use `--kind` only to resolve ambiguous input. `subscribe` fetches a bounded online source and detects Clash, URI-list, and base64 URI-list bodies. Plain HTTP fetches require `--allow-insecure-http` and cannot carry query credentials. Imports and URL files must be regular, non-symlink, current-user-owned mode-`0600` files. `export --out FILE` creates a private mode-`0600` backup atomically and refuses unsafe output paths.

Supported URI/Clash node types are HTTP/HTTPS, SOCKS5, Shadowsocks, ShadowsocksR, Trojan, VMess, VLESS, Hysteria 1/2, TUIC, AnyTLS, Mieru, and Snell. Direct HTTP/HTTPS endpoint input requires `--no-udp`; other sources allow UDP by default and accept `--no-udp` to force TCP/DNS-only operation. Input Clash rules, groups, listeners, controller fields, direct fallbacks, and unsupported proxy/provider keys are rejected or discarded; the generated engine policy is always `MATCH,GLOBAL`.

Node and lifecycle commands:

```bash
./xenoid proxy list
./xenoid proxy select NAME
./xenoid proxy off       # preserve the source; remove the active data plane
./xenoid proxy on
./xenoid proxy export --out /path/to/private-backup
./xenoid proxy clear     # disable and erase the saved source
./xenoid proxy prepare   # preinstall the pinned engine asset
```

`set`, `subscribe`, and `import` enable by default; add `--no-enable` to stage a source. `list`, `status`, MCP results, and daemon status never return source values, credentials, provider URLs, cache keys, paths, or configuration digests. `./xenoid up` converges any saved enabled source before declaring the runtime ready.

Proxy desired-state v2 is encrypted by its own app-private AES-256-GCM key and crash-resume transaction store; it is independent of the KeyMint keybox. If proxy state is unreadable, status reports a safe error and host quarantine remains installed. Recover only by authenticated `proxy import FILE` or by the explicit evidence-preserving source-less operation:

```bash
./xenoid proxy clear --discard-unreadable-state
```

Ordinary `proxy clear` refuses unreadable state. It never silently generates an empty state or releases direct egress. A proxy failure cannot hide Keybox/location/camera/root diagnostics, and a Keybox failure cannot modify proxy generations or keys.

The Docker engine host must provide root/sudo, systemd, Python 3, iproute2, and IPv4/IPv6 netfilter support. Xenoid installs missing supported distro packages and a digest-pinned Mihomo binary on first use. The proxy namespace and listener stay on that host, including with a remote Linux Docker context; Android retains its normal cellular data interface (`rmnet_data0`) and route.

If activation returns `data_plane_unverified`, inspect `./xenoid proxy status --check`. The per-instance quarantine intentionally remains closed until the exact current generation proves every requested IPv4/IPv6 DNS, TCP, and UDP capability. A stopped daemon, engine dependency failure, mismatched container identity, stale check, or inaccessible upstream cannot fall back to direct traffic. Use `./xenoid proxy off` to make an explicit fail-open operator decision, or fix the source/upstream and run `./xenoid proxy on`.

Android application network checks treat raw route-netlink `RTM_GETLINK` `EACCES` as the expected Android 13 permission result, not as a network outage. Ordinary applications still use TCP/UDP, `RTM_GETADDR`, `RTM_GETROUTE`, Bionic `getifaddrs`, and Java `NetworkInterface`; isolated processes cannot create new non-Unix sockets. Privileged cellular verification belongs to `/system/bin/xenoid-netctl status rmnet_data0`, whose ioctl and rtnetlink results must remain successful and identical.

## Root control

```bash
./xenoid daemon health
./xenoid root status
./xenoid root exec id
```

Privileged operations pass through the daemon and loopback-only `xenoid-rootd`. The only durable credential is a strictly validated app-private daemon file. The host reads it only through a metadata-validated bounded engine pipe into a container-ID-bound memory buffer, passes it to rootd on stdin, then zeroizes it; no host token file/cache, argv/environment value, generic result, or progress field exists. Missing/malformed credentials, failed root UID/authentication proof, and unowned listener conflicts fail closed.

## Android 13 KeyMint keybox

Operate keyboxes only from the trusted local CLI:

```bash
chmod 600 /secure/local/keybox.xml
./xenoid device keybox set /secure/local/keybox.xml
./xenoid device keybox status
./xenoid device keybox clear
```

The source must be a nonempty regular file owned by the current user, not a symlink, no larger than 8 MiB, and have no group or world permission bits. The set command opens with no-follow, hashes while streaming, and rejects any device, inode, size, or modification-time change. ADB staging uses a random shell-owned mode-`0600` `/data/local/tmp/.keybox-upload-<32 lowercase hex>` name and is cleaned in a `finally` path. Do not put keybox XML, DER, private keys, digests, or Android staging/private paths in shell variables, logs, tracked files, support bundles, image contexts, or command arguments.

The CLI sends only staging metadata through the authenticated daemon and token-gated rootd boundary. The raw keybox is retained only in daemon app-private no-backup storage with mode `0600`; the transient encoded configuration exists only for the one-shot local control transaction. `status` is intentionally redacted and reports only configured/ready/active state, fixed safe errors, algorithm availability, and certificate-chain counts. There is no keybox MCP tool or remote-service operation.

Listener startup and Keybox recovery are separate. The daemon binds transport before constructing/reconciling components; the bounded bootstrap worker later reconciles Keybox after authenticated root is available. An unconfigured inactive keybox is healthy. Configured failure is reported independently and can fail final `up`, but it cannot prevent proxy/root/location/camera diagnosis or mutate proxy encryption state.

This path supports only Android 13 ARM64 and scopes generated attestations to `com.google.android.gms` and `com.android.vending` (with installed UID fallback). The simulator executes key operations in software while reporting the configured KeyMint TEE metadata; it is not hardware-backed key custody and does not prove Play Integrity or Google device certification. Other packages continue through stock KeyMint behavior.

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
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json --keep-unique
./xenoid device regenerate
./xenoid profile status
```

The production template is Android 13 Pixel 6 Pro `raven`, model `G8V0U`, build `TP1A.221005.002`/`9012097`, shipping API 31. Profile application converges SettingsProvider, partition/property-area identity, display/input, native sensor and camera HAL inputs, battery, memory/storage, and reboot-persistent data. Recollect the complete profile after a change.

`device regenerate` creates a private `dev.xenoid.device-regenerate/v2` transaction and generates every stable/network/SIM/data/rootfs target exactly once before mutation. It quarantines, removes the owned container, commits each fixed target idempotently, and invokes the convergence executor directly. For any configured non-`none` Google provider, fresh pre-Google acceptance gates clearing exactly `com.google.android.gms`, `com.google.android.gsf`, and `com.android.vending`; fresh final acceptance gates journal deletion. User data, installed apps, keystore state, proxy/Keybox semantics, and location country/carrier are preserved.

An interrupted v2 transaction is resumable by either `device regenerate` or plain `up`; both reuse recorded targets and completed phases. A legacy v1 journal lacks the values required for exactly-once recovery, so ordinary `up` fails `device_regeneration_legacy_pending`. The only destructive escape is `./xenoid device regenerate --restart-legacy-transaction`, which records a digest of the v1 evidence and atomically publishes a complete v2 target before mutation; factors already changed by v1 may rotate once more.

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

The daemon requires the init-managed native input service. Its persistent profile-backed touchscreen writes Linux `input_event` records through `/dev/uinput`; Android InputReader consumes the published `/dev/input/event*` node. Tap and swipe never fall back to the framework `input` command, accessibility, or instrumentation.

## Shared protection policy

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
./xenoid ebpf status
```

`SharedProtectionManager` owns one root-managed kmod/eBPF deployment per selected Docker engine host. Its digest binds the engine/kernel/config/BTF/headers, source/build scripts, tools/loader, attach mode, and probe contract. Status reports safe engine hash, expected/current digest, reuse/replacement state, and maintenance requirement—never endpoints, host paths, tokens, or instance-private data.

A matching module/link/map inventory is reused across instances. eBPF replacement stages transactional pins before swapping; kmod replacement requires zero active owned runtimes and restores a digest-matched last-known-good module on failure. If a sibling runtime is active, `up` returns `shared_protection_reload_requires_maintenance` without disrupting it. Stop every owned runtime, then rerun `up`; public `stop` never unloads protection. Direct eBPF unload is maintenance-only and requires `./xenoid ebpf unload --maintenance` with zero active runtimes.

## Build and release

```bash
./xenoid build all
./xenoid build all --force
./scripts/verify.sh --fresh
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Normal builds reuse content-addressed artifact records; `--force` rebuilds and rejects nondeterministic output for an unchanged input/tool identity. Release packaging runs the non-recursive release gate profile fresh, stages validated immutable objects, creates canonical OTA/package archives with fixed `SOURCE_DATE_EPOCH`, and requires `verify-release` on the candidate before publication. A selectable microG provider requires the fresh `release-google` profile and packages only its normalized `evidence/google-services-release.json`; ordinary offline evidence never claims live Google capability.

Public releases exclude imported Google bytes, credentials/tokens/cookies, private registry/endpoint details, proxy sources or keys, Keybox bytes, raw/private Google acceptance evidence, runtime state, captures/device identifiers, workstation paths, and assessment details. The sanitized Google release attestation may contain only immutable identities, artifact/reproducibility proofs, bounded versions, and capability booleans.

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
Put the repository `xenoid-mcp` launcher on the MCP client's `PATH`.
`mcp-config` deliberately emits no absolute workspace path.


`xenoid-mcp` is a trusted-local, fixed-instance stdio adapter. The networked,
scope-filtered multi-instance adapter is `xenoid-service` at `POST /mcp`. Both
use the same backend, daemon token, and runtime preconditions as the CLI. See
[`mcp-tools.md`](mcp-tools.md) for the tool contract and
[`remote-service.md`](remote-service.md) for remote deployment.
