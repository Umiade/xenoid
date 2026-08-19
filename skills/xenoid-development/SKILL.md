# Xenoid Development Skill

Use this skill when changing Xenoid source, runtime images, protection layers, device profiles, automation, release tooling, or engineering documentation.

## Mission

Maintain a coherent Android runtime whose public CLI is predictable, whose privilege boundary is explicit, and whose observable device state agrees across every layer. Correctness and end-to-end behavior take priority over isolated test success.

## System model

Treat Xenoid as one converged system rather than a collection of independent spoofing functions:

1. **Host orchestration**: `src/xenoid/`, `scripts/xenoid-up.sh`, Colima or Docker, binderfs, networking, and persistent images.
2. **Android control plane**: the daemon, rootd, token-gated privileged operations, application management, input, and automation.
3. **Filesystem and identity**: rootfs/data images, pivot and mount namespaces, overlays, property files, property-area state, SettingsProvider, and generated identifiers.
4. **Kernel-visible state**: kmod and eBPF behavior for procfs, sysfs, paths, UTS data, and raw syscall consumers.
5. **Process-visible state**: zygote preload, libc interposition, framework behavior, package/service responses, and runtime mappings.
6. **Hardware-facing state**: sensors, camera, battery, key attestation, and other HAL or service contracts.

A fix is complete only when all readers of the same fact agree. Changing one API while leaving a contradictory file, property, service, or syscall result is a defect.

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

- Keep Google binaries, release certificates, expanded payloads, and captures in ignored `.xenoid/` state. Public files may contain only pinned hashes, signer identities, package/version/ABI inventory, reproducibility metadata, and operator guidance.
- Do not add an automatic downloader, broad GApps version matcher, late APK installer, Magisk module, or MCP host-path import. The one registered release must remain an explicit local import.
- Treat provider, release, specification fingerprint, data-compatibility fingerprint, image ID, rootfs source ID, container labels/command, and per-instance binding as one immutable identity. A transition after any Android data exists must fail without erasing or migrating data.
- Verify importer boundary changes with `python3 scripts/test-google-services.py`. Verify image/runtime changes with `scripts/smoke-google-services-runtime.sh`, two-pass `scripts/smoke-google-services-convergence.sh`, and `./xenoid doctor --full --require-runtime` on an enabled fresh instance.
- Package presence and a Play Store launcher prove only runtime bootstrap. Google account login is operator-driven; Play Integrity and device certification remain unsupported/not evaluated unless an independent capability probe proves them.

## Android 13 KeyMint changes

- Support only Android 13 ARM64 stock `keystore2`. The one production integration is an init `LD_PRELOAD` of `/system/lib64/libxenoid_keymint_bootstrap.so`; the bootstrap has a direct `DT_NEEDED` on `/system/lib64/libteesim_keymint.so` and its constructor calls `entry(NULL)`. Do not add a direct HAL replacement, ptrace injector, Frida dependency, Magisk/WebUI/service module, legacy Android 10/11 keystore path, new privileged helper, or second daemon.
- Treat TEESimulator as an external/prebuilt boundary. Source rebuilds receive its checkout only through `TEESIMULATOR_SOURCE`; never write a workstation path into tracked files. The `teesim-km` Rust crate is GPL-3.0-or-later, so every distributed prebuilt must retain the corresponding license and source-compliance obligations. Do not copy that crate's source into Xenoid.
- Keep raw keybox XML/DER/private keys exclusively in daemon app-private no-backup mode-`0600` storage. Host imports must enforce current-user ownership, regular non-symlink identity, no group/world permission bits, nonempty size at most 8 MiB, no-follow open, and stable device/inode/size/mtime while hashing. Only exact staging path/size/SHA-256 metadata may cross the authenticated daemon route; always clean the random shell-owned mode-`0600` staging file.
- Keep the control transaction one-shot and local: transient encoded config, root `app_process`, abstract `@teesim`, big-endian `u32` frame length, UTF-8 JSON at most 8 MiB, native root reverse-auth, and client verification of peer UID 1017. An acknowledgement must replace exactly one complete profile before set is ready; clear must acknowledge zero profiles before deleting state. Startup synchronously reapplies desired configured state.
- Keep keybox operations out of MCP and remote-service catalogs. Status may expose only configured/ready/active booleans, fixed safe error codes, algorithm booleans, and chain counts—never bytes, XML, DER, private-key data, filenames, paths, or digests.
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

## Verification ladder

Choose evidence that exercises the real contract:

- **Pure source change**: syntax or compile check plus the narrow source smoke.
- **CLI or daemon behavior**: invoke the real command and inspect structured output and failure semantics.
- **Image-bound component**: rebuild the component, rebuild or refresh the runtime context, start through `./xenoid up`, and verify the deployed artifact.
- **UI or application behavior**: cold-start the original application, wait for terminal state, collect machine-readable UI or backing-store evidence, and inspect fatal/ANR logs.
- **Kernel-visible behavior**: test libc and raw syscall paths from an unprivileged app context; include isolated processes when access rules differ. For Android 13 route netlink, the expected matrix is ordinary app socket creation succeeds but `RTM_GETLINK` send returns `EACCES`; ordinary `RTM_GETADDR`/`RTM_GETROUTE`, TCP/UDP, Bionic `getifaddrs`, and Java interface enumeration succeed; isolated process non-Unix socket creation returns `EACCES` while AF_UNIX/Binder/inherited descriptors remain usable; UID-below-10000 control paths such as `xenoid-netctl` keep rtnetlink access. Never use a broad app-UID socket denial to satisfy this matrix.
- **Production acceptance**: no probes or inspection servers, a fresh runtime restart, repeated cold starts, and `./xenoid doctor --require-runtime`.

Repository checks:

```bash
./scripts/ci.sh
python3 scripts/audit-sensitive-data.py
./xenoid doctor --require-runtime
```

Use `./xenoid doctor --full --require-runtime` when a change affects build orchestration, runtime images, protection activation, or several layers at once.

## Instrumentation hygiene

- Start instrumentation explicitly and only for a bounded question.
- Capture attach time and process identity in logs so pre-attach results remain distinguishable.
- Never use post-attach observations as clean-production evidence without preserving the pre-attach result boundary.
- Instrumentation can leave processes, files, executable mappings, or inherited zygote state. Stopping a client is not sufficient cleanup.
- Remove deployed payloads, stop helper processes, and restart Xenoid before final acceptance.

## Kernel safety

- Test kernel changes in an isolated runtime before making startup depend on them.
- Build and load failures must be hard startup failures when the layer is required.
- A hang, unbounded retry, or unstable kernel path invalidates the design even if a narrow detector result improves.
- Exercise repeated reads, concurrent readers, app and isolated UIDs, cold starts, and sustained runtime load.
- Keep an explicit fallback design for risky kernel experiments, but do not ship both paths.

## Privacy boundary

Tracked GitHub content may include architecture, supported workflows, public APIs, generic engineering methods, and reproducible validation commands.

Keep the following ignored and local:

- third-party binaries and decompilation outputs;
- device dumps, logs, screenshots, maps, memory captures, and identifiers;
- assessment-target names, versions, predicates, offsets, and result matrices;
- workstation paths, credentials, tokens, private endpoints, and account metadata;
- per-instance location identity state (master seed, full SIM/MSISDN values); only masked location views belong in outputs;
- internal articles, cached references, and session-specific continuation notes.

Use `.skills/` for local agent handoff, `.doc/` for local references, `.tmp/` for disposable evidence, and `.xenoid/` for runtime state. These directories must remain ignored.

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
