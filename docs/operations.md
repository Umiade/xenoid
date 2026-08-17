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

`install-runtime` installs and validates Docker CLI, Colima, ADB, scrcpy, JDK 17, Android SDK platform/build-tools 35, and Android NDK. It prepares the ARM64 Colima VM and binderfs and initializes the `default` instance from `examples/config-macos-colima.json` when absent. It does not start Android.

`up` builds the configured artifacts, starts Android, deploys the daemon and native helpers, applies the device profile and protection policy, activates system protection, and validates the live runtime. It returns nonzero if convergence or validation fails.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a grow-only sparse ext4 backing image (`xenoid-data.img`) that is bind-mounted as the container's `/data`.

`stop`, repeated `up`, container recreate, and `colima stop/start` preserve the data volume. `colima delete`, external volume deletion/prune, or loss of the host instance state will cause Xenoid to fail hard on next startup rather than silently create an empty disk.

Cache and login state are stored in the same `/data` partition and persist across restarts. Android's own storage pressure and app cache-clearing semantics still apply; Xenoid does not add a separate wipe-on-start mode.

The canonical Raven profile requests a 128,000,000,000-byte logical data device and an Android-facing f2fs contract. Xenoid grows an existing smaller ext4 backing image transactionally before startup, preserves its filesystem UUID and data, and resumes or rolls back an interrupted host-side growth transaction. It never shrinks, recreates, or silently replaces a committed image. After profile convergence, `/proc/partitions`, `/proc/diskstats`, `/dev/block/sda`, the Raven userdata by-name alias, block sysfs, mount records, and unprivileged libc/raw-syscall filesystem magic must agree. Privileged maintenance still sees ext4.

Sparse capacity is not host-space preallocation. `doctor` reports conservative Docker/Colima backing-store headroom; if the backing filesystem is exhausted, Android writes fail with `ENOSPC` while the image and UUID remain intact. The 12 GiB Android memory view is likewise independent of the lower host/Colima runtime allocation.

## Multi-instance operation

Multiple instances share one Colima VM (macOS) or one Docker engine/binderfs (Linux ARM). Each instance gets a unique container, volume, network, MAC, IPv4/IPv6, host ADB/daemon port, and proxy routing table from the operator registry.

Source-based `up` operations for the same project wait on one build/convergence lock because they share generated native artifacts. Each instance still runs concurrently after convergence and uses its own auto-built runtime image tag. Rootfs preparation streams to the Docker engine host, so macOS does not need temporary space for a complete rootfs tar.

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

Device identity (Android ID, serial, IMEI/IMEISV) is generated once per instance and persisted in `~/.xenoid/instances/<UUID>/device-identity.json`. Boot-scoped values (`boot_id`, `random_uuid`) rotate on container recreation. Explicit rotation via `device apply --keep-unique` or `device set` updates the same host state so the next `up` does not revert identity. `./xenoid device regenerate` goes further: it rotates the stable identifiers, the lease network epoch (container MAC), the boot-scoped values, the data/rootfs filesystem UUIDs, the per-app SSAID store, and the SIM identity (new IMSI/ICCID/MSISDN/cell for the same country) on a live instance — and on GMS instances clears the Google services apps so the app-readable advertising ID regenerates — then recreates the container and re-converges through the standard `up` pipeline, making the instance present as a brand-new same-model device while preserving user data and the location country/carrier.

## Linux ARM

Requirements: Ubuntu 22.04 or 24.04 ARM64, Python 3.9 or newer, Docker Engine, root or sudo access, and a kernel with `binder_linux`. Source builds also require JDK 17, Android SDK platform 35, Android build-tools 35.0.0, and Android NDK 27.2.12479018 or a compatible newer release.

```bash
cd xenoid
sudo ./scripts/setup-linux-binderfs.sh
./xenoid init --config examples/config-linux-arm.json
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

## Optional Google Play services

The default provider/release pair is `none`/`none`. The only accepted enabled pair is `mindthegapps`/`MindTheGapps-13.0.0-arm64-20231025_200931`. The runtime must remain Android 13/API 33, `arm64-v8a`, and product `raven`; custom Docker arguments are rejected because they would make container identity ambiguous.

Prerequisites:

- the official `MindTheGapps-13.0.0-arm64-20231025_200931.zip`;
- the `release.x509.pem` asset from the same [upstream GitHub release](https://github.com/MindTheGapps/13.0.0-arm64/releases/tag/MindTheGapps-13.0.0-arm64-20231025_200931);
- JDK `keytool`/`jarsigner` and Android SDK `aapt2`/`apksigner` (installed and checked by `./xenoid install-runtime`);
- a fresh initialized instance with no Docker data volume or Android storage state.

```bash
./xenoid --instance play init --config examples/config-macos-colima.json
./xenoid --instance play google-services import-mindthegapps \
  /path/to/MindTheGapps-13.0.0-arm64-20231025_200931.zip \
  /path/to/release.x509.pem
./xenoid --instance play google-services enable
./xenoid --instance play up
./xenoid --instance play google-services status --require-runtime
```

Import is project-scoped and repeatable. It accepts only the exact pinned filenames and bytes, copies from regular non-symlink sources, performs no network access, uses `0700` directories and `0600` files, and publishes the final private asset directory atomically. Failure output uses stable error codes and never returns source or stored paths.

`enable` also sets `auto_build_runtime_image=true`. The first `up` builds a specification-addressed image, writes the same provider/release/specification/data-compatibility identity to image and container labels, creates rootfs from that exact image, and commits the instance binding only after PackageManager reports GMS Core, Google Services Framework, and Play Store ready. A later provider/release mismatch fails without touching `/data`; create a new instance instead. `disable` has the same fresh-instance restriction.

For ordinary convergence, use `up`. `up --reuse-runtime --skip-build` is an explicit no-build path and succeeds only when the owned running container, immutable binding, managed labels/command, image ID, rootfs source image ID, PackageManager state, and platform ABI already match.

```bash
./scripts/smoke-google-services-runtime.sh --instance play
./scripts/smoke-google-services-convergence.sh --instance play
./xenoid --instance play doctor --full --require-runtime
```

The focused smoke installs an ordinary non-debuggable app that verifies the three packages, discovers the framework `com.google` account authenticator, binds GMS Core through its exported service, and resolves the Play Store launcher. It does not submit account credentials; account login remains a manual acceptance step. Play Integrity verdicts and Google device certification are explicitly `unsupported`/`notEvaluated` until separately proven. If Google reports the device as uncertified, follow Google's [uncertified-device registration](https://www.google.com/android/uncertified/) process; Xenoid does not automate it.

Xenoid publishes only the verification metadata needed for reproducibility. Google application binaries remain subject to their upstream terms and are never included in Xenoid source, release archives, or OTA bundles.

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

The Docker engine host must provide root/sudo, systemd, Python 3, iproute2, and IPv4/IPv6 netfilter support. Xenoid installs missing supported distro packages and a digest-pinned Mihomo binary on first use. The proxy namespace and listener stay on that host, including with a remote Linux Docker context; Android retains its normal cellular data interface (`rmnet_data0`) and route.

If activation returns `data_plane_unverified`, inspect `./xenoid proxy status --check`. The per-instance quarantine intentionally remains closed until the exact current generation proves every requested IPv4/IPv6 DNS, TCP, and UDP capability. A stopped daemon, engine dependency failure, mismatched container identity, stale check, or inaccessible upstream cannot fall back to direct traffic. Use `./xenoid proxy off` to make an explicit fail-open operator decision, or fix the source/upstream and run `./xenoid proxy on`.

Android application network checks treat raw route-netlink `RTM_GETLINK` `EACCES` as the expected Android 13 permission result, not as a network outage. Ordinary applications still use TCP/UDP, `RTM_GETADDR`, `RTM_GETROUTE`, Bionic `getifaddrs`, and Java `NetworkInterface`; isolated processes cannot create new non-Unix sockets. Privileged cellular verification belongs to `/system/bin/xenoid-netctl status rmnet_data0`, whose ioctl and rtnetlink results must remain successful and identical.

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
./xenoid device apply examples/fingerprints/pixel-raven-android13.json
./xenoid device apply examples/fingerprints/pixel-raven-android13.json --keep-unique
./xenoid device regenerate
./xenoid profile status
```

The production template is Android 13 Pixel 6 Pro `raven`, model `G8V0U`, build `TP1A.221005.002`/`9012097`, shipping API 31. Profile application converges SettingsProvider, partition/property-area identity, display/input, native sensor and camera HAL inputs, battery, memory/storage, and reboot-persistent data. Recollect the complete profile after a change.

`device regenerate` performs the one-shot new-device rotation on a live instance: stable identifiers, the lease network epoch (container MAC), boot-scoped values, data/rootfs filesystem UUIDs, the per-app SSAID store, and the SIM identity (new IMSI/ICCID/MSISDN/cell, same country) all rotate; on GMS instances the Google services apps are cleared so the advertising ID regenerates. The container is recreated and the full `up` convergence and validation re-run. User data, installed apps, keystore state, and the location country/carrier are preserved. An interrupted regenerate is journaled: `start`/`up` fail closed with `device_regeneration_pending` until `device regenerate` is re-run to completion.

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

## Protection policy

```bash
./xenoid hide status
./xenoid hide apply examples/hide/default-policy.json
./xenoid ebpf status
```

Production protection combines image state, property-area normalization, mount overlays, the zygote compatibility layer, eBPF/kernel enforcement, and framework/HAL services. Kmod/eBPF own SELinux compatibility metadata, ordinary-app access denial, and isolated-app ptrace parity; per-instance overlays do not remount SELinux controls. `up` owns deployment and activation; individual build/load commands are for diagnosis and development.

## Build and release

```bash
./xenoid build all
./xenoid package-release --version 0.1.0
./xenoid verify-release dist/release/xenoid-0.1.0.tar.gz
```

Release bundles include the CLI, MCP server, non-proprietary runtime assets, daemon APK, native helpers, configuration examples, public Google release metadata, skill files, doctor metadata, and SHA-256 manifests. Imported Google archives, certificates, and expanded payloads are excluded.

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

`xenoid-mcp` is a trusted-local, fixed-instance stdio adapter. The networked,
scope-filtered multi-instance adapter is `xenoid-service` at `POST /mcp`. Both
use the same backend, daemon token, and runtime preconditions as the CLI. See
[`mcp-tools.md`](mcp-tools.md) for the tool contract and
[`remote-service.md`](remote-service.md) for remote deployment.
