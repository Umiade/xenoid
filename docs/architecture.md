# Xenoid Architecture

Xenoid is split into three layers:

1. **Host layer** (`src/xenoid`) — CLI and MCP server for local agents/users.
2. **Runtime layer** — Android container backend through Docker/Colima on Apple Silicon macOS or Docker on Linux ARM.
3. **Android control layer** (`daemon`) — daemon APK exposing authenticated JSON APIs for root, global proxy desired state, camera media, Frida, profiles, automation, and OTA.

## Why a Linux VM on macOS

Android container runtimes depend on Linux kernel facilities and device namespaces. macOS does not expose those interfaces directly, so Xenoid runs an ARM64 Linux VM through Colima and starts the Android container with Docker inside it.

## Instance lifecycle and data persistence

Each instance is a logical device with three persistent components:

1. **Instance config** at `.xenoid/instances/<name>/config.json` (project root);
2. **Private control state** at `~/.xenoid/instances/<UUID>/` (operator state);
3. **Android user data** in a Docker engine named volume (`xenoid-data-<tag>`), containing a sparse ext4 `xenoid-data.img` that is bind-mounted as the container's `/data`.

`stop`, repeated `up`, container recreate, and `colima stop/start` preserve the data volume. `colima delete`, external volume deletion/prune, or loss of the host instance state will cause Xenoid to fail hard on next startup rather than silently create an empty disk.

Cache and login state are stored in the same `/data` partition and persist across restarts. Android's own storage pressure and app cache-clearing semantics still apply; Xenoid does not add a separate wipe-on-start mode.

The runtime preserves Android's per-app SSAID store instead of rewriting it during profile convergence; each signing identity therefore keeps the value Android generated for that device. Profile application updates only the device-wide secure Android ID. The runtime PackageManager patch tolerates only redroid's known unsupported SELinux `restorecon` result while recovering existing `/data` app directories; every other `installd` failure remains fatal.

## Multi-instance operation

Multiple instances share one Colima VM (macOS) or one Docker engine/binderfs (Linux ARM). Each instance gets a unique container, volume, network, MAC, IPv4/IPv6, host ADB/daemon port, and proxy routing table from the operator registry.

Auto-built runtime images are tagged per instance (`<configured-tag>-<resource-tag>`), so one instance can never retag the image used by a sibling. Full `up` convergence is serialized per project because native generated sources are shared; already-running instances remain concurrent. Rootfs extraction streams directly to the Docker engine host and uses an invocation-private work directory instead of staging a multi-gigabyte tar on the CLI host.

Kernel protection is engine-host scoped and is loaded once, then reused while instances are running. Each Android overlay helper makes its `/sys` mount private before applying sysfs identity binds, preventing one instance's battery, thermal, or SELinux views from propagating into a sibling container.

```bash
./xenoid --instance phone-a init --config examples/config-macos-colima.json
./xenoid --instance phone-b init --from phone-a
./xenoid --instance phone-a up
./xenoid --instance phone-b up
./xenoid --instance phone-a stop
```

Device identity (Android ID, serial, IMEI/IMEISV) is generated once per instance and persisted in `~/.xenoid/instances/<UUID>/device-identity.json`. Boot-scoped values (`boot_id`, `random_uuid`) rotate on container recreation. Explicit rotation via `device apply --keep-unique` or `device set` updates the same host state so the next `up` does not revert identity.

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
xenoid camera status --check
xenoid proxy status --check
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
- `GET /camera/status`
- `POST /camera/source`
- `POST /camera/settings`
- `POST /camera/clear`
- `POST /camera/apply`
- `POST /camera/self-test/start`
- `GET /camera/self-test/status`
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

## Location identity

The instance's location identity (country, locale, timezone, single USIM, carrier, APN, registered LTE cell) is owned by a 0600 host state file under `.xenoid/instances/<instance>/location-identity.json`. One master seed deterministically derives a cached profile per country through domain-separated HMAC; the pinned dataset in `data/cellular/` (MCC/MNC, APN, LTE bands, CLDR locales, IANA timezones, libphonenumber MSISDN templates) is the only source of country facts. A version-15 legacy vendor RIL and the RadioConfig HAL produce all radio state from the staged binary profile; the image's telephony band bridge derives the app-visible LTE band from EARFCN for the legacy conversion.

Country changes are one pending transaction: stage the profile to the daemon, arm it against the runtime epoch derived from the owned container ID, recreate the container exactly once, then verify — SIM state, subscription, PLMN, LTE cell, `rmnet_data0` connectivity, locale, timezone, and provisioning are read back from framework surfaces before promotion. Crashes resume the pending transaction without regenerating identity or repeating a completed restart. The proxy data plane never observes, gates, or mutates this identity, and proxy mutations never restart the runtime.

## Camera data plane

The host streams camera media to a random, mode-`0600` ADB staging file and sends only its Android path, size, kind, and SHA-256 digest through the authenticated daemon API. The daemon validates and normalizes the import in app-private storage, then uses token-gated rootd to atomically publish a root-owned generation under `/data/misc/camera/source`. Public status omits source names, paths, and digests.

The stable-AIDL camera provider snapshots one published generation when a camera opens. Its ordered worker writes preview, YUV, and JPEG buffers, emits a monotonic shutter timestamp, and then returns matching result metadata, including coherent AE/AWB lock state used by legacy camera clients. The runtime supplies matching framework camcorder profiles for both cameras. The image-matched legacy allocator remains the sole graphics allocator; its camera-only handle extension supports flexible YUV and JPEG BLOB buffers while retaining the original RGB/framebuffer handle layout.

Photo requests fall back to the first video frame, video requests fall back to the photo, and a source-free runtime uses a generated sensor-like scene. Source changes therefore never invalidate an active session and become visible only on the next open.

## Global proxy data plane

The daemon owns encrypted desired state and exposes only redacted status. The host controller compiles endpoint, URI-list, subscription, or Clash input into a deterministic Mihomo configuration. Compilation uses a strict protocol/key allowlist and replaces source routing with one fixed `MATCH,GLOBAL` route; source rules, listeners, controller settings, and direct fallbacks do not cross the boundary. Remote subscriptions and Clash providers use bounded HTTPS fetches with public-address pinning, TLS verification, redirect revalidation, media-type checks, and a private cache.

Each Android instance has one root-owned reconciliation agent on the Docker engine host. The engine binds the manifest to the current container ID, runtime epoch, bridge, IPv4/IPv6 addresses, and MAC address. It creates the transparent proxy listener in a separate host network namespace and captures only that container's bridge traffic with per-instance netfilter chains. Android keeps its ordinary `rmnet_data0`, route, DNS configuration, proxy properties, and cellular network capabilities; no proxy process, TUN device, VPN transport, listening port, or proxy routing rule is added to the Android namespace. Framework and libc interface identity remains coherent for applications, while raw `RTM_GETLINK` is a privileged control-plane operation. The kernel protection module enforces that Android 13 boundary at `security_socket_create` and `security_netlink_send`: isolated processes cannot create non-Unix sockets, and ordinary app `RTM_GETLINK` sends fail with `EACCES` before the message reaches rtnetlink. Root/system `xenoid-netctl` retains ioctl and rtnetlink GET/SETLINK access, and host or unrelated container network namespaces are not changed. Xenoid's procfs/sysfs cellular identity exposure is intentionally stronger than stock Android policy; it exists to keep the regional profile coherent, not to grant raw privileged link reads to apps.

The engine installs a quarantine before configuration or lifecycle changes and opens the data plane only after the daemon's ordinary-app probe proves every requested IPv4/IPv6 DNS, TCP, and UDP capability for the exact instance, generation, check ID, and runtime epoch. A stale report cannot release a newer generation. Disable and clear operations remove owned rules and namespaces; failures remain fail-closed. Root/agent messages use direction-bound authenticated encryption with replay rejection, and unprivileged compiler/fetch workers run under separate bounded service accounts.


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
./xenoid init --config examples/config-macos-colima.json
./xenoid init --config examples/config-linux-arm.json
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
