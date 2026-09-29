# Changelog

[Chinese Version](CHANGELOG_CN.md)

All notable changes to Xenoid are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases are tagged
`xenoid-<version>` and the daemon `versionCode` is
`major * 10000 + minor * 100 + patch`.

## [Unreleased]

### Added

- `xenoid --instance <name> delete`: irreversibly deletes the
  selected instance and frees its owned engine resources. The command
  quiesces and removes the owned container, removes the owned data volume
  and Docker network, runs proxy cleanup, then drops the private control
  state, instance config, and operator registry lease (slot, host ports,
  subnets, route tables). It fails closed when any engine resource's
  ownership labels do not match the lease, always retains shared runtime
  images and engine-host protection, is idempotent across interruptions,
  and supports `--dry-run` to report the plan without mutating.

## [0.9.2] - 2026-09-18

In-place runtime device regeneration. `xenoid device regenerate` no longer
recreates the container: it commits fixed identity targets against the live
runtime, runs one host-driven soft reboot, then rotates the Google identity
in place through microG once the replacement daemon is healthy, and verifies
every factor by fail-closed read-back. The container, data volume, user
data, installed apps, keystore state, and location country/carrier are all
preserved.

### Added

- Runtime-image payload verification: after `buildx` exports `image.tar`,
  the builder replays the exported layers and hashes every payload
  destination produced by the Dockerfile `COPY` rules against the digests in
  `context-manifest.json`, failing with `runtime_image_payload_mismatch` on
  any divergence. A stale BuildKit local-context/blob cache hit can no longer
  publish an image whose payload bytes disagree with its records (observed
  with same-size, content-only payload changes).
  The replay also hashes each compressed layer blob against its OCI
  descriptor, accepts legal `./` root records, retires descendants when a
  wanted ancestor is replaced by a non-directory, and enforces layer,
  member, and decompression budgets with deadline/cancellation checks. The
  verification contract is mixed into `inputSha256`, so content labels
  minted before a contract change are never reused.
- In-process Widevine DRM identity: the `xenoid-zygote` preload serves a
  synthetic `IDrm` factory (`android::DrmUtils::MakeDrm` is an exported,
  interposable cross-DSO symbol in `libmediadrm.so`), so both Java `MediaDrm`
  and NDK `AMediaDrm_*` callers in every app process resolve the same
  implementation. It reports vendor `Google`, description `Widevine CDM`,
  algorithms, `securityLevel=L1`, and a `deviceUniqueId` read per call from
  the dedicated staged system property (mirrored to the profile file), so
  DRM identity can rotate without a userspace restart. This is an identity
  surface only: DRM playback and provisioning remain unsupported and the
  `drm` capability stays `unsupported`. `persist.xenoid.drm.id` has no
  explicit `property_contexts` mapping and inherits the base policy's
  default property label. The `ci-full` DRM gate transiently builds, installs,
  and removes an untracked ordinary-app probe that asserts Java/NDK agreement
  and per-call rotation, then restores the original property.

### Changed

- `xenoid device regenerate` is runtime-only. It publishes each fixed journal
  target once (GAID is the explicit postcondition exception described below)
  in a strict `dev.xenoid.device-regenerate/v3` journal (`prepared`, `staged`,
  `props_committed`, `settings_committed`, `radio_committed`,
  `storage_identity_committed`, `soft_rebooted`, `google_reset`, `verified`,
  `committed`), keeps its command name and backward-compatible nested
  `regeneration` object, and uses the same canonical top-level v3 result for
  direct success and crash-resume cleanup. It reports `runtimeOnly=true` /
  `containerRecreated=false`. Rotated factors:
  device-wide `ANDROID_ID`; per-app SSAID (the `settings_ssaid.xml` store is
  deleted and Android recreates it); `Build.SERIAL` / `ro.serialno` /
  `ro.boot.serialno`; `boot_id`; IMEI/IMEISV; SIM identity (IMSI, ICCID,
  MSISDN, LTE cell) via SIM-epoch rotation; `/data` `statfs` `f_fsid`;
  Bluetooth address; device name and network hostname; GAID and GSF Android
  ID (rotated through microG without clearing any Google package or running
  network check-in); and the DRM `deviceUniqueId`. Model, fingerprint, and
  build properties are unchanged.
- Google identity rotation runs entirely against the live microG runtime.
  One positive decimal GSF Android ID is deterministically derived from the
  regeneration transaction and committed Google binding. While GmsCore is
  force-stopped, microG check-in is disabled atomically
  (`com.google.android.gms_preferences.xml` `checkin_enable_service=false`),
  the exact target is published to `shared_prefs/checkin.xml`, the local
  `gservices.db` v3 schema (`main`/`overrides`/`saved_system`/`saved_secure`
  plus the `android_id` row), and the staged profile. `CheckinService` is
  never started and no network check-in is initiated or awaited. This
  `googleIdentityMode=offline-seeded` policy means regenerated instances do
  not support FCM registration or delivery; Google status reports
  `cloudMessaging=unsupported` with `offline-checkin-disabled` evidence and
  removes it from that instance's required runtime capabilities.
  GAID is deliberately not a fixed journal target. The daemon calls
  `IAdvertisingIdService.resetAdvertisingId` (Binder transaction 3) and
  disables global ad-tracking-limited (transaction 4), then accepts only a
  nonzero app-facing GAID different from its pre-transaction observation.
  The returned SHA-256 digest is observation evidence, not a target. Because
  the pinned microG `MemoryAdvertisingIdConfiguration` has no setter, later
  microG service/process recreation may rekey GAID again. Fail-closed
  verification requires both identifiers to differ from before and the GSF
  digest to equal its fixed target. Provider `none` skips the step; a
  configured non-microG provider fails unsupported. This phase runs after the
  soft reboot because the in-memory advertising-ID state is recreated by the
  zygote/GmsCore restart.
- The soft reboot is host-driven through the token-gated rootd path: `rild`
  and `zygote` restart first, and `keystore2` restarts only after the
  replacement `system_server`/PackageManager is live, so it never retains a
  stale binder handle and key-attestation binding is preserved. Readiness is
  observed as a genuine `sys.boot_completed` clear-to-set transition plus
  daemon health.
- The journal pins the original container ID/epoch. `up` resumes a stopped
  `--restart=no` runtime only by starting that exact container, and every
  final read-back rejects replacement. A rootd receipt, written only after
  SSAID deletion and RIL/zygote restart dispatch, distinguishes the requested
  reboot from unrelated `system_server` or container restarts.
- Bluetooth identity now uses Android 13's user-0 `Settings.Secure`
  `bluetooth_address` plus `bluetooth_addr_valid`. The generated hostname is
  staged privately and replayed with display runtime state after each ordinary
  container restart.
- `/data` `f_fsid` is now a runtime input: writable kernel-module parameters
  feed the `vfs_statfs` shaping and the same value is mirrored into the
  shim/zygote staging file, so kmod, shim, zygote, and raw `statfs` syscalls
  all agree. The on-disk ext4 UUID is no longer app-visible.
- Legacy v1/v2 regeneration journals are still detected but are no longer
  resumable: they fail with `device_regeneration_legacy_pending`, and
  recovery is to delete the recorded legacy journal files and rerun
  `device regenerate`.
- The daemon builds as `versionName 0.9.2` / `versionCode 902`.

### Removed

- `/proc/sys/kernel/random/uuid` overlay faking (a fixed kernel entropy
  source is itself an anomaly); `randomUuid` is gone from the identity model.
- Offline ext4 UUID rotation: `scripts/rotate-storage-identity.sh`, the
  storage-rotation backend path, and the `rotationTargetUuid` /
  `rotationTargetRootfsUuid` state fields. The instance-storage schema v5
  upgrade transparently drops empty legacy fields from ordinary v3/v4 records,
  but preserves crash-window evidence: any valid non-empty legacy rotation
  target fails closed with `storage_legacy_rotation_pending` and leaves the
  original state file byte-for-byte untouched.
- The container-recreate regeneration path and the
  `device regenerate --restart-legacy-transaction` escape.
- `device regenerate --skip-build`; regeneration now performs a mandatory
  runtime-only convergence preflight against existing validated artifacts.
  `up --skip-build` remains supported.

### Fixed

- The microG live gate now probes the pinned GmsCore release's actual
  `com.google.android.gms` process in both provider-managed and offline-seeded
  modes; it no longer waits for a nonexistent `:persistent` process after a
  userspace reboot.
- Google signature-policy verification now validates the image actually
  backing the running owned container (its immutable image ID plus the
  pinned Google labels) instead of the runtime image selected for the
  current full source tree, so a live-deployable daemon-only update no
  longer fails `google_services_runtime_not_ready` merely because unrelated
  current runtime-image inputs have no newly built image.
- Ordinary `up` crash-resume after `container_created` now starts the exact
  journaled container while validating both recorded runtime-image digest
  labels; it no longer requires an image-ID field that convergence journals
  do not store.
- The native DRM bridge clears byte-vector outputs before repeated Widevine
  identity reads and delegates stock non-Widevine key and crypto operations,
  preserving ClearKey behavior while the synthetic identity remains stable
  within one transaction.
- Overlay apply, cleanup, and revert now detach the retired
  `/proc/sys/kernel/random/uuid` bind mount left by older deployments.
- First-time `up` of a freshly initialized instance no longer fails with
  `storage_identity_mismatch`: fresh storage pending records now carry the
  convergence journal's pinned data UUID (and the rootfs pin is enforced at
  the initialize action), so the boot-seed target, the committed record, and
  the resume validator all agree. Previously the fresh image got a silently
  generated divergent UUID and every resume failed closed.
- Regeneration resume is engine-reboot safe: it restores the exact
  journal-pinned shared-protection deployment (recorded in the journal's
  before-state) while no runtime is active, re-runs bootstrap/rootd
  provisioning and the single-user guard before rehydrating, and a checkout
  change mid-transaction fails closed as inputs-changed. Radio rotation on
  resume now verifies the journaled profile digest before any
  LocationStateStore write, including the already-rotated retry path.
- `f_fsid` republish after a container start now waits for the ext4 `/data`
  pivot mount before classifying the staged leaf, so a fast `docker exec`
  can no longer read the pre-pivot outer `/data` and leave the kernel
  parameter at zero. The netns exclusivity proof enumerates every engine
  container, not only labeled ones.
- A journaled soft-reboot completion that later userspace-restarts (zygote
  crash) no longer triggers a second destructive zygote restart with SSAID
  re-wipe; the recorded receipt plus completion epoch prove exactly-once.
- `up --dry-run` holds the instance operation lock across the journal
  decision, unrelated mutators get the canonical v3 envelope for
  legacy/malformed journals instead of a bare identity error, and
  `xenoid_up` (MCP/remote) starts a cold engine host before the executor
  while `xenoid_up_plan` routes a pending regeneration journal to the same
  canonical v3 dry-run envelope as the real run.
- Fresh instances now seed a persistent synthetic Widevine `deviceUniqueId`
  during ordinary identity convergence instead of reporting Widevine
  unsupported until the first regeneration.
- The Google identity healer no longer retries forever when GMS is absent
  (provider `none` or the package removed): that surface is terminal, while
  transient rootd/service loss keeps bounded deduplicated backoff.
- Native DRM bridge correctness against the real Android 13 IDrm ABI: the
  real-factory bridge accepts the partial-backend `-ENODEV` initCheck the
  stock factory accepts (ClearKey delegation works on this HIDL-only guest);
  `requiresSecureDecoder` reads the mime as `const char*` (verified against
  the guest `DrmHal` signatures) instead of crashing; HDCP and security
  levels use the 1-based framework enums (`HDCP_V2_2=5`,
  `HW_SECURE_ALL=5`); and the `getKeyRequest` delegate trampoline forwards
  the ninth argument passed on the stack per AAPCS, so ClearKey key
  requests return correctly instead of `unknown key request type`.
  ClearKey assertions in the DRM smoke now match the platform's actual
  contract: enumeration and key flow work through the delegate, while the
  lazy HAL's timing-dependent static support query, unimplemented
  `removeKeys`, vendor/description property read, and direct CryptoSession
  algorithm setup (rejected `ERROR_DRM_CANNOT_HANDLE` by design) are
  tolerated exactly as stock behaves.

### Known issues

- Phonesky self-update: the Play Store may self-update the pinned Phonesky
  seed (30.4.17 to a newer release) on its own schedule, independently of
  regeneration — `device regenerate` neither clears nor launches Phonesky and
  does not initiate the update. The update is signed by a different Google
  certificate than the pinned seed's lineage, so component verification
  rejects it and `up` fails with `google_services_runtime_not_ready`.
  Recovery: `pm uninstall com.android.vending` rolls the Store back to the
  verified factory seed.

## [0.9.1] - 2026-09-18

First versioned record of the runtime as shipped today. No behaviour change
beyond the version plumbing itself.

Baseline: one production entrypoint, `./xenoid up`, converges the redroid
`64only` Android 13 ARM64 runtime, the token-gated daemon, the Raven
(Pixel 6 Pro) device profile, the protection layers (property area, overlay
mounts, kernel module, eBPF, servicemanager interposition, zygote preload),
storage, and the configured services. Device identity stays coherent across
framework APIs, properties, files, services, HALs, procfs, sysfs, and raw
syscalls. `xenoid device regenerate` rotates identity by recreating the
container. Google services run on the bundled microG; DRM playback and
provisioning are not supported. Frida remains an explicit, opt-in inspection
capability and is never part of normal production startup.

### Added

- Version plumbing: `./xenoid --version` prints the shared package version;
  the daemon builds as `versionName 0.9.1` / `versionCode 901`.
- `version-contract` CI gate keeping the four version strings, the
  formula-derived version code, and both changelogs in lockstep.
- This bilingual changelog, linked from both READMEs.

### Changed

- `xenoid-service` reports the shared package version instead of a
  hard-coded string.
