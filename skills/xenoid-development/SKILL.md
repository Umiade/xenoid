# Xenoid Development Skill

Use this skill when changing Xenoid source, runtime images, protection layers, device profiles, automation, release tooling, or engineering documentation.

## Mission

Maintain a coherent Android runtime whose public CLI is predictable, whose privilege boundary is explicit, and whose observable device state agrees across every layer. Correctness and end-to-end behavior take priority over isolated test success.

## System model

Treat Xenoid as one converged system rather than a collection of independent spoofing functions:

1. **Host convergence**: `src/xenoid/{convergence,artifacts,runtime_image,protection,process}.py`, Docker/Colima, binderfs, networking, persistent images, and resumable journals.
2. **Android control plane**: listener-first daemon bootstrap, token-gated loopback rootd, component managers, application/input/automation control, and no application-visible `su`.
3. **Filesystem and identity**: rootfs/data images, pivot/mount namespaces, overlays, property state, SettingsProvider, fixed-target regeneration, and storage provenance.
4. **Engine-host shared protection**: one digest-bound kmod/eBPF deployment for every owned runtime on the selected engine.
5. **Process-visible state**: zygote preload, libc interposition, framework behavior, package/service responses, and runtime mappings.
6. **Hardware-facing state**: sensors, camera, battery, key attestation, radio/location identity, and other HAL/service contracts.
7. **Evidence**: non-converging `LiveAcceptance`, digest-aware `GateRunner`, observational doctor, CI profiles, and deterministic release verification.

A fix is complete only when all readers of the same fact agree. Changing one API while leaving a contradictory file, property, service, or syscall result is a defect.

## Production ownership contracts

- `up` is the sole mutating production convergence owner. It plans before mutation and automatically chooses no-op, resume, start, create, restart, recreate, or component-only work. Never add a shell wrapper, nested CLI call, command-specific bootstrap chain, or runtime-reuse override.
- A private convergence journal is created only before mutation. Egress-sensitive order is `planned -> quarantined -> image_ensured` before runtime replacement. Retry must re-inspect recorded immutable IDs/UUIDs/generations and resume idempotently; a third state fails closed.
- `stop` quarantines, syncs, and stops the owned container without removing it. Replacement belongs only to explicit recreate or a planner-selected immutable mismatch; regeneration always rotates identity in place.
- `status` is strictly observational and reports one `recommendedAction`; `up --dry-run` is the actionable plan. `--skip-build` validates artifact records/objects and never compiles stale or missing work.
- Emit `dev.xenoid.progress/v1` `inspecting|resuming started` before hashing, then sanitized five-second heartbeats for long work. With no regeneration pending, CLI/MCP/remote `up` returns one final `dev.xenoid.convergence/v1` document. When resuming a valid pending transaction, it returns the canonical top-level `dev.xenoid.device-regenerate/v3` result instead. MCP/remote call the executor directly and return safe final summaries, not parsed child output.

## Build and image identity

- `ArtifactBuilder` is the only source-artifact owner. Records bind declared source/command/environment/tool identities to immutable SHA-256 objects and exact output path/mode/size/architecture/digest. Consumers stage validated `runtimeContext`, `liveDeploy`, or `release` snapshots; they never read mutable outputs behind the manifest or perform fallback builds.
- Normal builds reuse valid records. Forced builds must reproduce the same bytes for the same input identity or preserve the prior record and fail. Output-directory locks serialize only targets that genuinely share outputs.
- Runtime images are addressed by complete input digest over immutable base ID, validated artifact closure, canonical recipes/context, toolchain/builder identities, and Google inputs. A separate boot digest substitutes the daemon seed integration contract, allowing only verified update-compatible daemon-only live deployment.
- The configured tag is a repository namespace. Publish to the derived content tag under an engine-host lock; never implicitly pull a mutable base, overwrite a conflicting content tag, retag a running instance, or let low-level `start --recreate` compile.
- After `buildx` exports `image.tar`, every payload destination produced by the Dockerfile `COPY` rules is replayed from the archive layers and hashed against `context-manifest.json`; divergence fails with `runtime_image_payload_mismatch`. Never trust BuildKit local-context/blob reuse for same-size, content-only payload changes — it has silently shipped stale bytes whose labels claimed the new digest.
- The in-process DRM identity bridge and its sret assembly shim support production ARM64 only. `build-native-zygote.sh x86_64` must fail explicitly rather than compiling AArch64 assembly for x86. `ci-full` owns the transient ordinary-app DRM gate: build/install Java+NDK probe inputs from `tests/drm-identity-probe`, assert both APIs return the same rotating identity, restore runtime state, uninstall, and remove ignored APK output.

## Bootstrap and fail-closed components

- The daemon validates its app-private credential, binds transport, and accepts requests before any manager recovery. Host recovery is one bounded transport -> authenticated rootd -> generation-scoped component reconciliation sequence. Aggregate health is final acceptance, never bootstrap.
- The host may keep the credential only in a container-ID-bound secret memory buffer. Never persist a host token cache/file or expose credentials in argv, environment, generic process results/tails, progress, logs, MCP, or remote JSON.
- Root, Keybox, proxy, location, and camera report independent safe states. Failure in one cannot prevent constructing or diagnosing the others.
- Proxy desired-state v2 has its own app-private AES-256-GCM key and crash-resume journal, independent of KeyMint. Unreadable bytes are evidence, not “off”: retain quarantine and require authenticated import or explicit `clear --discard-unreadable-state`.
- Regeneration v3 fixes all stable, SIM, boot, storage, DRM, and Google-binding targets before mutation and commits them against the live runtime — never a container stop/remove/recreate — ending in one host-driven soft reboot and fail-closed read-back. The exact GSF Android ID is deterministically derived from the transaction and binding. GAID is not a journal target: reset microG's opaque value, require only nonzero and different-from-before, and treat its digest as observation evidence because GmsCore recreation may rekey it. Plain `up` resumes valid v3. Legacy v1/v2 journals block with `device_regeneration_legacy_pending`; the only recovery is deleting the recorded legacy files and rerunning `device regenerate`.
- Shared kmod/eBPF protection is one engine-host deployment. Matching digests/inventory reuse it. Active siblings block unsafe replacement; public stop never unloads, and maintenance unload requires explicit acknowledgement plus zero active runtimes.

## Required discovery

Before editing:

- Read the repository-level `AGENTS.md` and the relevant architecture and operations documentation.
- Locate the authoritative implementation, callers, configuration, build path, and existing smoke coverage.
- Use symbol-aware references before changing exported APIs.
- Check whether the runtime image contains the component; host-side source changes do not affect a running image until the build and deployment path installs them.
- Inspect ignored local guidance when it exists, but never copy local-only facts into tracked files.

## Change design

- Repair the owning layer. Framework inconsistency belongs in framework or service behavior; kernel-visible inconsistency belongs below libc; hardware contracts belong in HAL or service implementations.
- Reuse an existing profile, overlay, helper, daemon route, or verification path. A parallel configuration mechanism is prohibited.
- Keep production independent of third-party frameworks and persistent root artifacts.
- Do not patch syscall tables. Use stable kernel interfaces, eBPF attachment points, overlays, process hooks, or framework changes as appropriate.
- Avoid return-time rewrites of user buffers unless the design has a proven lifetime model. Prefer producer-side shaping before data is copied to userspace.
- Treat app, isolated, zygote, system-server, and privileged process views separately. A policy that is correct for an app may break Android initialization when applied globally.
- Remove obsolete implementations during cutover. Do not leave aliases, fallback paths, or dead scaffolding.

## Google runtime changes

- Keep Google binaries, release certificates, expanded payloads, private policy inputs, external cloud probes, and captures in ignored `.xenoid/` or operator-owned state. Public files may contain only pinned hashes, signer identities, package/version/ABI inventory, source commits, policy attribution, reproducibility metadata, normalized release-attestation booleans/identities, and operator guidance.
- The production identity is `microg`/`microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0`: official microG GmsCore `v0.3.15.250932`, official GsfProxy `v0.1.0`, and the Google-signed Phonesky `30.4.17` factory seed. MindTheGapps is a retired, importable source for only that seed and its exact Store policy blocks; never make it selectable or migrate an old instance.
- Do not add an automatic downloader, broad GApps version matcher, late APK installer, Magisk/runtime hook, or MCP/remote host-path import. The trusted-local CLI must import the retired MindTheGapps source first and the exact official microG/GsfProxy APKs second.
- Treat provider, release, specification fingerprint, data-compatibility fingerprint, all component/source/policy/signer inputs, image ID, rootfs source ID, container labels/command, and per-instance binding as one immutable identity. Any transition after Android data exists requires a new instance and must fail without erasing or migrating data.
- Restricted spoofing is a framework policy for only official microG `com.google.android.gms`, bound to the exact package, real microG signer, and requested Google certificate for `signatures`, `signingInfo`, and `forceQueryable`. Keep its on-disk signer real and keep GsfProxy/Phonesky API/on-disk signers coherent. Never add a general spoofing permission or describe the exception as Google equivalence.
- The microG image keeps AOSP `Provision`, leaves `ro.setupwizard.mode` unchanged, and installs no Google SetupWizard. Generate the least-privilege product policy from pinned, attributed inputs; do not hand-maintain a second policy path.
- Verify importer/policy boundaries with focused runtime-free contracts, then use explicit fresh gates and the applicable live smoke on an enabled fresh instance. `LiveAcceptance`/doctor may observe the final runtime, but production convergence and regeneration never invoke doctor, `--full`, a smoke suite, CI, or build as a nested acceptance path.
- In `googleIdentityMode=provider-managed`, minimal `up` acceptance requires runtime-tier `googlePlayServices`, `accountAuth`, `cloudMessaging`, `fusedLocation`, and `playStore`. In regeneration's `offline-seeded` mode, require the other four and report `cloudMessaging=unsupported` with `offline-checkin-disabled`; FCM registration/delivery are unavailable. Only packaged release attestation may claim `fcmDelivery`, `fusedLocationBehavior`, `maps`, `auth`, or `playStoreOperations`; Maps is `microg-mapbox-maplibre`. `playIntegrity`, `deviceCertification`, DRM playback/provisioning, and `antiCheat` are always unsupported.

## Android 13 KeyMint changes

- Support only Android 13 ARM64 stock `keystore2`. The production integration is the init-managed standalone AIDL KeyMint service with its VINTF declaration; do not add a second HAL path, ptrace injector, Frida dependency, Magisk/WebUI module, legacy Android 10/11 keystore route, application-visible helper, or second daemon.
- Treat TEESimulator as an external/prebuilt boundary. Source rebuilds receive its checkout only through `TEESIMULATOR_SOURCE`; never write a workstation path into tracked files. The `teesim-km` Rust crate is GPL-3.0-or-later, so every distributed prebuilt must retain the corresponding license and source-compliance obligations. Do not copy that crate's source into Xenoid.
- Keep raw keybox XML/DER/private keys exclusively in daemon app-private no-backup mode-`0600` storage. Host imports enforce strict ownership/type/mode/size/stability and clean bounded staging. Public status exposes only safe configured/ready/active, error-code, algorithm, and count fields—never bytes, filenames, paths, digests, XML/DER, or private-key material.
- Listener startup is independent of Keybox. The bounded bootstrap worker reconciles configured state after authenticated root becomes available; unconfigured inactive is healthy. Keybox set/clear and proxy source/select/on/off/clear are independent transactions and never rotate, repair, or delete each other's key/state.
- Keep keybox operations out of MCP and remote-service catalogs. Never let Keybox failure hide root/proxy/location/camera diagnostics.
- Generation profile `default` is limited to `com.google.android.gms` and `com.android.vending` by package and installed UID fallback. It uses Android 13 attestation version 200, configured TEE security level 1, current build/patch identity, Verified/device-locked boot metadata, a stable private verified-boot seed, and no StrongBox. Execution remains software-only: never claim hardware private-key custody, Play Integrity support, or Google device certification.
- Contract tests use generated dummy files/material only. Cover parser registration, local file permissions/symlinks/stability, exact daemon route schemas and redaction, init-rc patch idempotence/rejection, both shared-library manifests, and absence from MCP/remote catalogs. Never place a real keybox or private certificate in fixtures.

## Behavioral research workflow

When compatibility depends on undocumented third-party behavior:

1. Establish a clean black-box baseline using the original software and record machine-readable outputs.
2. Map each observation to its data source, process, predicate, return contract, and user-visible result.
3. Recover control flow statically. For flattened or opaque control flow, combine branch relationships, data flow, instruction semantics, strings, cross-references, and call-site evidence.
4. Use dynamic probes only to resolve uncertain inputs, branches, and sinks. Instrumentation output is evidence, not a production dependency.
5. Build an independent behavioral model that reproduces clean, dirty, boundary, and error cases before changing Xenoid.
6. Repair the lowest coherent layer and migrate every affected reader.
7. Remove probes, stop inspection services, restart the complete runtime, and repeat acceptance with the original software.

Maintain a compact evidence map for each behavior:

```text
entry point -> data source -> predicate -> process -> repair layer -> static evidence -> runtime evidence -> replica
```

Do not claim coverage from strings alone. Every covered predicate needs a control-flow basis and either a runtime observation or a deterministic replica contract.

## Evidence ownership and validation DAG

Choose evidence that exercises the real contract:

- **Pure source change**: the narrow source/contract gate through `GateRunner`.
- **CLI or daemon behavior**: invoke the real command and inspect its one structured final result, progress ordering, deadlines, redaction, and failure semantics.
- **Image-bound component**: ensure its artifact record, ensure the content-addressed image only when boot inputs require it, converge through `up`, and verify the deployed digest.
- **UI or application behavior**: cold-start the original application, wait for terminal state, and collect bounded machine-readable evidence.
- **Kernel-visible behavior**: test libc and raw-syscall paths from ordinary and isolated unprivileged Android contexts; exercise the selected Docker engine host rather than local-host assumptions.
- **Production acceptance**: `LiveAcceptance.observe` freshly inspects an already-running owned runtime. It never mutates, ensures bootstrap, invokes gates/doctor/verify/CI, or builds.

Validation owners:

- `scripts/verify.sh` is a thin `GateRunner` profile. Matching successful runtime-free records may be reused; `--fresh` ignores them. Sensitive-data inventory always recomputes.
- `scripts/ci.sh` selects the same acyclic catalog (`static`, explicit runtime, or full); gates never recursively invoke verify, CI, doctor, or themselves, and there is no audit bypass.
- `doctor` combines selected GateRunner records with fresh LiveAcceptance. Even `doctor --full` remains observational and excludes mutating convergence/build/release gates. Runtime absence can be `ok=true, complete=false` unless required.
- Release runs fresh gates, validated artifact snapshots, canonical OTA/package staging under `SOURCE_DATE_EPOCH`, and mandatory candidate verification. Offline packaged doctor evidence always has `complete=false`.

Typical explicit commands:

```bash
./scripts/verify.sh --fresh
./scripts/ci.sh
./xenoid doctor --require-runtime
```

## Instrumentation hygiene

- Start instrumentation explicitly and only for a bounded question.
- Capture attach time and process identity in logs so pre-attach results remain distinguishable.
- Never use post-attach observations as clean-production evidence without preserving the pre-attach result boundary.
- Instrumentation can leave processes, files, executable mappings, or inherited zygote state. Stopping a client is not sufficient cleanup.
- Remove deployed payloads, stop helper processes, and restart Xenoid before final acceptance.

## Kernel safety

- Test kernel changes in an isolated runtime before making convergence depend on them.
- Build and validate replacement artifacts before touching the verified engine-host deployment.
- A hang, unbounded retry, unknown/restored-but-unverified digest, or disruption of sibling runtimes invalidates the design.
- Exercise repeated reads, concurrent readers, ordinary and isolated Android UIDs, cold starts, and sustained runtime load through the selected engine transport.
- eBPF replacement uses staged transaction pins; kmod replacement requires zero active owned runtimes and a digest-matched last-known-good rollback. Never ship a fallback protection path or unload shared protection on ordinary stop.

## Privacy boundary

Tracked GitHub content may include architecture, supported workflows, public schemas, generic engineering methods, fixed content/tool digests, and reproducibility metadata.

Keep private and ignored:

- credentials, tokens, cookies, private registry or endpoint details, and workstation paths/identities;
- proxy sources, URLs, keys, cache/quarantine bytes, and evidence objects;
- Keybox XML/DER/private keys, daemon/root credentials, staging/private paths, and raw control messages;
- imported Google binaries/certificates/expanded payloads and other third-party samples;
- device dumps, logs, screenshots, maps, memory captures, raw SIM/device identifiers, and runtime state;
- assessment targets, captures, investigation records, predicates, offsets, and result matrices;
- internal articles, cached references, and session-specific continuation notes.

Public progress/results/docs must use stable safe codes, content digests, counts, booleans, and bounded sanitized diagnostics. Successful phases retain no child tails. Never publish absolute private paths, raw commands/responses, URI userinfo/query, source credentials, or a live-acceptance claim from offline packaging.

Before committing, inspect the complete prospective tree rather than only the diff:

```bash
python3 scripts/audit-sensitive-data.py
git diff --cached --check
```

## Commit and handoff

- Configure the repository-local author identity supplied by the owner; never copy it into tracked guidance.
- Use lowercase English Angular headers. The hook accepts `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- A handoff must state the invariant changed, exact files and symbols, deployed state, commands run, observed results, remaining risk, and whether instrumentation was active.
- Mark unobserved conclusions as inference. Never convert a partial experiment into a completion claim.
