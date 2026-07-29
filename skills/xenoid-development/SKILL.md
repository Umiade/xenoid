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
- **Kernel-visible behavior**: test libc and raw syscall paths from an unprivileged app context; include isolated processes when access rules differ.
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
