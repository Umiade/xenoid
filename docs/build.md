# Build Xenoid Components

## Artifact records and reuse

All production build consumers use `ArtifactBuilder`; no image, OTA, package, deploy, or `up` path silently compiles a second artifact set. The 20 public targets are published as `dev.xenoid.artifact/v1` records over immutable SHA-256 objects. Each record binds declared sources, command/flags, normalized build environment, resolved toolchain identities, and every output path, mode, size, architecture, and digest. The aggregate manifest digest excludes timestamps and logs.

Normal `./xenoid build all` hashes inputs and reuses valid records. Missing mutable public outputs are rematerialized from the immutable objects without compilation. Stale targets build under normalized output-directory locks with at most four workers and a shared CPU-slot budget; disjoint targets may run concurrently, while helpers that share an output directory serialize. Failed targets publish no record, and dependents are reported blocked.

`./xenoid build all --force` deliberately rebuilds every target. If the same input/tool identity produces different bytes, modes, or sizes, it fails `artifact_nondeterministic` and retains the prior successful record. `./xenoid up --skip-build` is validation-only: it refuses missing/stale records, unsafe or changed objects, wrong modes/architecture, and source/tool drift instead of compiling.

The `runtimeContext`, `liveDeploy`, and `release` consumers stage only validated record/object snapshots. Generated runtime contexts are canonical: paths are sorted, modes and timestamps are fixed, symlinks/special files are rejected, and `context-manifest.json` records each relative path/type/mode/size/SHA-256. Both patched JAR producers use the same pinned apktool and canonical ZIP writer.

## Content-addressed runtime images

`./xenoid runtime-build-image` and production `up` share `RuntimeImageBuilder`. Its full `inputSha256` covers the immutable ARM64 base image ID, validated runtime-context artifact tuples, canonical recipes and redroid sources, Python/zlib/Java/BuildKit identities, pinned apktool, and sorted Google inputs. For microG those inputs include both source releases, the two private import manifests, all three component byte/signer/path identities, framework policy commits/certificates, and every product-policy input/output. `bootInputSha256` substitutes the daemon seed integration contract for ordinary daemon APK bytes, so an update-compatible APK-only change can be live-installed without recreating storage ownership.

The configured `runtime_image_tag` is a repository namespace, not a mutable effective tag. Publication uses `<repository>:xenoid-<first-32-input-hex>` and labels the full input, boot input, and immutable base ID under an engine-host lock. Production base references should be digest-pinned. Mutable tags remain explicit locally observed update inputs and are never implicitly pulled by `up`; an explicit digest must match. A conflicting occupied content tag, changed base/input during build, or unsupported reproducibility control fails without replacing the prior image. `start --recreate` consumes a verified image and never builds one.

## Host CLI/MCP

No external Python dependencies are required.

```bash
./xenoid doctor
```

The remote service is also Python 3.9 standard-library only. Its runtime-free
contracts cover access-store permissions, token/instance ACLs, scope-filtered
catalogs, fresh instance resolution, same-instance locking, cross-instance
parallelism, CLI/stdio lock sharing, MCP 2026-07-28 HTTP headers, Host/Origin
checks, redaction, bounded command execution, connection/request admission,
short-body rejection, deferred TLS handshakes, default non-loopback TLS guards,
and the explicit insecure-HTTP test opt-in:

```bash
python3 scripts/test-mcp-contract.py
python3 scripts/test-remote-service.py
```

The HTTP contract opens a temporary loopback listener. Sandboxed development
environments must permit binding `127.0.0.1`; it never requires an Android
runtime or an external network.

## Instance storage contracts

```bash
python3 scripts/test-instance-storage.py
```

Profile-driven Android storage surfaces:

```bash
python3 scripts/smoke-storage-surfaces.py
```

Covers fresh initialization, pending recovery, tagged adoption, committed hard-failure, legacy migration with backup, safe container removal order, and dual-instance isolation.

## Global proxy runtime

Proxy source compilation and authenticated control contracts are runtime-free:

```bash
python3 scripts/test-proxy-compiler.py
```

The transparent data plane runs on the selected Docker engine host. On first `proxy prepare`, `proxy set`, or enabled-state convergence, Xenoid installs the root engine helper, per-instance systemd agent, unprivileged compiler/fetch workers, and required distro packages. It downloads Mihomo `v1.19.29` only from the pinned release URL and verifies both the compressed archive and extracted ARM64 binary SHA-256 digests. The binary is host state under `/usr/lib/xenoid/proxy`; it is not a tracked or packaged build artifact.

The daemon APK contains the encrypted desired-state manager and ordinary-app IPv4/IPv6 DNS, TCP, and UDP probes. Host Python modules and the engine/agent scripts are included in release bundles.

The daemon's proxy desired state uses its own app-private v2 AES-256-GCM key and crash-resume transaction store; it has no build-time or KeyMint-key dependency. No proxy source, URL credential, private cache, quarantine byte, key material, or evidence object may enter an artifact record, context, image, package, or log. Unreadable state is recovered only by authenticated import or explicit evidence-preserving discard.


## Daemon APK

Preferred:

```bash
./xenoid build daemon
```

The build script first tries Gradle/Android Gradle Plugin. If Gradle is unavailable, it falls back to a standalone Android SDK build using:

- `aapt2`
- `javac`
- `d8`
- `zipalign`
- `apksigner`

Output:

```text
daemon/app/build/outputs/apk/debug/app-debug.apk
```

The mock daemon API smoke is runtime-free and uses generated dummy keybox bytes only. It verifies exact request/status schemas, safe errors and redaction, CLI parser/file boundaries, staging cleanup, and clear idempotence:

```bash
scripts/smoke-daemon-api.sh --mock
```

Daemon startup is listener-first. Transport binds before component reconciliation; the host then authenticates rootd and joins one bounded generation for root, Keybox, proxy, location, and camera. Aggregate `/health` remains a final acceptance check, not a prerequisite. The host never creates or caches daemon/root tokens, and artifacts/progress/results must not contain those credentials.

## Android 13 KeyMint HAL service

Release users consume the validated Android ARM64 prebuilt:

```text
native/xenoid-keymint/xenoid-keymint
```

The implementation lives in-tree under `native/xenoid-keymint/`: the C++ HAL service and router in `src/` and the Rust glue crate in `rust/teesim-km` derive from [TEESimulator](https://github.com/JingMatrix/TEESimulator) (the glue crate is `GPL-3.0-or-later`, so redistributing source or prebuilt binaries requires corresponding license and source compliance); the in-process reference KeyMint TA is compiled from a pinned AOSP checkout with the patches in `rust/patches/` applied. AOSP and BoringSSL dependencies are not vendored: `scripts/fetch-keymint-deps.sh` clones exact commits into the gitignored `native/xenoid-keymint/.deps/` with partial clone + sparse checkout.

Runtime-context generation requires the prebuilt, ships the VINTF fragment `native/xenoid-keymint/android.hardware.security.keymint.IKeyMintDevice.xml` (tracked), and generates `android.hardware.security.keymint-service.rc`, which starts the service as the `keystore` user in `class early_hal`; the rc filename sorts before `keystore2.rc` so the HAL registers in servicemanager first. The generated image installs the service at `/system/bin/hw/android.hardware.security.keymint-service` (mode `0755`), the rc under `/system/etc/init`, and the fragment under `/vendor/etc/vintf/manifest` (both mode `0644`). All VINTF fragments are normalized to mode `0644`: an unreadable fragment fails libvintf's whole-manifest parse in unprivileged readers such as `keystore2`.

Runtime-free prebuilt verification:

```bash
scripts/build-keymint.sh
```

The command validates the existing binary (ELF64 PIE, ARM64, dependency allowlist, no host paths or product markers) without rebuilding.

Source rebuilds are explicit and self-contained:

```bash
./xenoid build keymint
```

The first build fetches the pinned dependencies (network access to android.googlesource.com and boringssl.googlesource.com); later builds reuse them. Never encode a workstation checkout path in tracked files or release metadata. Release packaging includes the same validated binary under both `native/xenoid-keymint/` and `artifacts/`, and release verification requires them to match.

The build and runtime context contain no keybox. Raw keybox XML/DER/private keys, source/staging paths, digests, transient control JSON, and private daemon state must never be tracked or copied into the image or release bundle.

## Native low-level input helper

```bash
./xenoid build input
```

The script auto-discovers Android NDK under `$ANDROID_HOME`, `$ANDROID_SDK_ROOT`, or `$HOME/Library/Android/sdk/ndk`.

Output:

```text
native/xenoid-input/xenoid-input
```

## Camera provider and graphics allocator

```bash
scripts/build-gralloc.sh arm64
scripts/build-camera-hal.sh arm64
./xenoid build all
```

Outputs:

```text
native/xenoid-gralloc/gralloc.redroid.so
native/xenoid-camerahal/android.hardware.camera.provider-service-aidl
native/xenoid-camerahal/media_profiles_V1_0.xml
```

The runtime image installs the provider at `/system/bin/hw/android.hardware.camera.provider-service-aidl` and its framework camcorder profiles at `/vendor/etc/media_profiles_V1_0.xml`. The enhanced allocator replaces the owning `gralloc.redroid.so` and supplies the existing `gralloc.tensor.so` hardware-name alias from the same binary; it is not a second allocator.

The provider build generates the Android 13 stable-AIDL NDK bindings, links the matching platform camera metadata/Binder libraries, strips the service, and rejects product-specific marker strings in the runtime artifact.

## Hardware feature contract

```bash
python3 scripts/smoke-hardware-features.py
```

`runtime/redroid/xenoid-hardware-features.xml` is the PackageManager contract for the active camera and sensor HALs. Runtime-context generation validates the source, stages an identical payload, and emits a mandatory Dockerfile `COPY`; a missing, malformed, changed, or unstaged payload fails generation/build. Live runtime smoke validates both the installed XML and `pm list features`.

The contract requires the implemented back/front cameras, rear flash, accelerometer, barometer, compass, gyroscope, light, proximity, step-counter, and step-detector features. It removes inherited autofocus, full/manual/RAW/concurrent/external camera, NFC, UWB, fingerprint, HiFi sensor, and head-tracker claims.

## Build all

```bash
./xenoid build all
./xenoid build all --force
```

The result is one `dev.xenoid.artifacts/v1` JSON document with each target in `reused`, `built`, `failed`, or `blocked` state, duration, and the aggregate manifest digest. Only failed targets may carry sanitized bounded tails. A warm unchanged build launches no compiler/Gradle/Cargo child. `--force` is the clean deterministic evidence path for release/debug work; it is not the normal `up` behavior.

Runtime images do not read these mutable output paths. They consume the `runtimeContext` artifact snapshot and publish by verified content identity. Daemon-only full-image drift may remain deferred on a boot-compatible running image when PackageManager proves the seed contract and nondecreasing update compatibility; base/framework/HAL/Google component/policy/create-spec drift selects a new image and recreate, while any Google identity rotation also requires fresh instance data.

## OTA and release chain

```bash
./xenoid ota make --version 0.1.0-dev
./scripts/verify.sh --fresh
./xenoid package-release --version 0.1.0-dev
./xenoid verify-release dist/release/xenoid-0.1.0-dev.tar.gz
```

OTA/context/package consumers never compile a missing artifact. Release packaging runs the acyclic release gate profile with `--fresh`, stages an invocation-private validated artifact snapshot, creates canonical OTA and package archives with fixed `SOURCE_DATE_EPOCH`, and mandates `verify-release` on the candidate before atomic publication. A selectable microG provider selects `release-google` in the same invocation and packages its sanitized normalized acceptance as `evidence/google-services-release.json`; a disabled-clean provider selects the ordinary release profile. A second package operation with the same source/tool/epoch inputs must produce the same archive SHA-256.

The archive contains sanitized `dev.xenoid.gates/v1` evidence and an explicitly offline `doctor.json` with `complete=false`; only the Google release attestation may claim its bounded once-per-release capability checks. Public material may contain source commits, fixed tool/artifact/content digests, signer/package inventory, reproducibility and fresh-data proof hashes, versions, and booleans. It must not contain local paths, endpoints, credentials/tokens/cookies, proxy sources or keys, Keybox material, imported Google bytes, private/raw acceptance evidence, device captures/identifiers, runtime state, or assessment details.

## Hide helper and runtime context

```bash
./xenoid build hide
./xenoid runtime-context
```

`runtime-context` validates and stages the complete `runtimeContext` snapshot; it never invokes a fallback build. The canonical manifest and all staged bytes/modes/times must verify before image build.

Outputs:

```text
native/xenoid-hide/xenoid-hide
dist/runtime-context/Dockerfile
```

## Google runtime (default for new instances)

The production provider is `microg`, release `microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`. The image combines official microG GmsCore `v0.3.15.250932`, official GsfProxy `v0.1.0`, and the Google-signed Phonesky `30.4.17` factory seed extracted from retired source release `MindTheGapps-13.0.0-arm64-20231025_200931`. Google integration uses the host JDK (`keytool`, `jarsigner`) and Android SDK build tools (`aapt2`, `apksigner`).

`scripts/test-google-services.py` covers production/retired registry semantics, both import boundaries, composite metadata, component and policy identity, safe source copying, and immutable binding transitions without proprietary fixtures:

```bash
python3 scripts/test-google-services.py
tests/google-services-runtime-probe/build.sh
```

The first ordinary `up` automatically acquires the exact retired ZIP/certificate source and official GmsCore/GsfProxy release assets, then routes them through `import_mindthegapps` and `import_microg`. The trusted-local `google-services import-*` commands remain as offline/manual fallback; MCP and remote control never accept import paths or bytes. Runtime-context generation stages exactly GmsCore, GsfProxy, the pinned Phonesky member, and four canonical generated product-policy files; it includes no other MindTheGapps package, SetupWizard, overlay, recovery, or native member. `verify_context_copy` rejects missing/extra files, unsafe types/modes/timestamps, digest/signer/package/version drift, policy drift, Dockerfile-order errors, labels, or legacy payload.

The services patch implements restricted spoofing only for official microG `com.google.android.gms`, pinned to LineageOS source commits `6d2955f0bd55e9938d5d49415182c27b50900b95` and `53e2f4b85ce836360dd58bdb2f0d7f42dc796443`. Its exact package/real-signer/fake-certificate predicate owns API-visible `signatures`, `signingInfo`, and `forceQueryable`; the APK stays microG-signed on disk, while GsfProxy and Phonesky retain coherent signers. No general spoofing permission is added. Product policy is generated deterministically from the pinned GmsCore request set, API 33 permissions, four attributed upstream XML inputs, and the exact Phonesky policy blocks.

The microG rootfs keeps AOSP `Provision`, installs no Google SetupWizard, and leaves `ro.setupwizard.mode` unchanged. The standard GmsCore APK supplies Maps through `microg-mapbox-maplibre`; Companion is not a component.

Tracked inputs include both registered release metadata documents, the policy generator, the four upstream XML files and their notice, and reproducible framework permission inputs. Imported ZIP, PEM, APKs, expanded payload, policy private inputs, external cloud probe, and runtime context remain private or regenerable. Release packaging and verification reject `.xenoid/`, imported payload bytes, raw acceptance evidence, and unregistered Google metadata.

## Validation DAG and observational acceptance

`scripts/verify.sh` is a thin caller of the digest-aware `GateRunner` DAG. Successful runtime-free gates may be reused only when their complete source/data/tool/artifact input digest still matches. `--fresh` deliberately ignores prior successes; sensitive-data audit always recomputes the tracked/untracked candidate inventory and bytes. Independent gates run concurrently, dependencies block after failure, and stdout is one `dev.xenoid.verify/v1` document while stderr carries sanitized JSONL progress.

`scripts/ci.sh` selects the same non-recursive catalog: static by default, `--runtime` for explicit fresh convergence/protection/persistence/dual-instance work, and `--full` for additional cellular/camera/Google/release gates. Minimal production `up` checks runtime-tier `googlePlayServices`, `accountAuth`, `cloudMessaging`, `fusedLocation`, and `playStore`. Full `fcmDelivery`, `fusedLocationBehavior`, `maps`, `auth`, and `playStoreOperations` are release-tier and appear only in the packaged release attestation. `playIntegrity`, `deviceCertification`, `drm`, and `antiCheat` are unsupported.

`doctor` is observational. It consumes selected GateRunner records plus a fresh `LiveAcceptance` result for an already-running runtime. `doctor --full` selects the broader doctor-safe record set, but never builds artifacts/images, packages, calls `up`, ensures daemon/rootd, or invokes mutating runtime/release gates. Cache hits cannot make `complete=true`; only a fresh live observation can.

`LiveAcceptance` never converges. It reads immutable runtime/storage identity, ADB boot, daemon transport and component status, rootd, location/camera, exact proxy proof, Google status-v2 binding/minimal-live checks, aggregate health, and shared protection. Production convergence and regeneration journal acceptance only from that fresh observer, never from doctor or a suite.

Kmod/eBPF are one engine-host shared deployment. Their digest includes selected engine/kernel/config/BTF/header/source/tool/loader/probe inputs. Replacement artifacts are built and validated before the last-known-good deployment is touched. A matching module/link/map inventory is reused; eBPF stages transactional pins, while kmod replacement requires zero active owned runtimes. Active siblings yield `shared_protection_reload_requires_maintenance` without unloading protection. Direct unload requires explicit maintenance and zero active runtimes; `stop` never unloads it.

## Location cellular runtime (RIL / RadioConfig)

The cellular identity stack is a version-15 legacy vendor RIL plus an AIDL RadioConfig service; both are built from the pinned Android NDK:

```bash
scripts/build-ril.sh arm64
scripts/build-radio-config.sh arm64
```

Outputs:

```text
native/xenoid-ril/libxenoid-ril.so
native/xenoid-radio-config/android.hardware.radio.config-service.xenoid
```

Runtime-free contracts for the location identity layer:

```bash
python3 scripts/test-cellular-profile.py   # seven-country profiles, MSISDN templates, crash-safe state machine
python3 scripts/test-ril-source.py         # canonical binary profile and RIL/SIM-file source contracts
python3 scripts/test-proxy-control.py      # generation/check-bound proxy data-plane proof (no region evidence)
```

`test-cellular-profile.py` pins the libphonenumber-derived per-country MSISDN templates, the 3GPP EARFCN/band round-trip used by the image's telephony band bridge (`scripts/patch-telephony-legacy-lte-band.py`), profile digest stability, and the stage/arm/recreate/verify/promote transaction including crash resume. `scripts/smoke-cellular-runtime.sh` is the live counterpart: an ordinary + isolated-process probe APK checks SIM/subscription/LTE cell/MSISDN, the single `rmnet_data0` cellular network, and the raw-syscall interface views.

The carrier dataset remains LTE-only. Every active carrier band list must be a subset of the official Pixel 6 Pro `G8V0U` LTE matrix and every generated EARFCN must round-trip to that LTE band; NR and mmWave hardware bands are not advertised as working data paths.

## Native profile helper

```bash
./xenoid build profile
./xenoid build all
```

Output:

```text
native/xenoid-profile/xenoid-profile
```

## Native helpers (hide / overlay / prop-area / input / profile)

```bash
./xenoid build all
```

Outputs include:

```text
native/xenoid-hide/xenoid-hide
native/xenoid-hide/xenoid-overlay
native/xenoid-hide/xenoid-prop-area
native/xenoid-input/xenoid-input
native/xenoid-profile/xenoid-profile
```

The production privilege path uses token-gated `xenoid-rootd`; app-process instrumentation uses opt-in Frida, while system policy uses eBPF and the runtime protection layers.
