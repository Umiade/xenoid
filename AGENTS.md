# Agent Instructions

These instructions apply to the entire repository.

## Start here

1. Read `README.md`, `docs/architecture.md`, `docs/operations.md`, and `docs/build.md` before changing code.
2. Read `skills/xenoid/SKILL.md` for operator workflows.
3. Read `skills/xenoid-development/SKILL.md` for engineering, validation, privacy, and handoff rules.
4. Inspect the current implementation and reuse its conventions before proposing a second mechanism.

## Product invariants

- Xenoid provides one production path for Apple Silicon macOS and Linux ARM64 hosts running a 64-bit Android 13 runtime.
- `./xenoid up` owns convergence. A successful return means the configured runtime, daemon, profile, protection layers, and live checks are ready.
- Privileged Android operations stay behind the daemon and token-gated root helper. Do not add an application-visible `su` path.
- Frida is an explicit inspection capability and is never part of normal production startup.
- Device identity must remain coherent across framework APIs, properties, files, services, HALs, procfs, sysfs, and raw syscall-visible surfaces.
- Prefer source-level fixes at the layer that owns the data. Do not add detector-specific return-value patches to production code.

## Engineering workflow

- Scope the affected layers and call sites before editing.
- Keep the implementation boring: update existing mechanisms, remove obsolete paths, and avoid compatibility shims unless the public contract requires one.
- Validate the changed path with the narrowest real scenario first, then run repository checks.
- Runtime or protection changes require `./xenoid doctor --require-runtime`; use `--full` only when exhaustive build evidence is needed.
- Kernel-visible changes must be exercised through the same interface an unprivileged Android process uses, including raw syscalls where applicable.
- After any instrumentation session, stop instrumentation and restart the complete runtime before production acceptance.

## Privacy and publication

- Public tracked files must contain only user-facing or developer-facing material suitable for GitHub.
- Keep runtime state, device captures, third-party samples, investigation records, and local handoff data in ignored dot-directories.
- Never commit credentials, personal paths, workstation identities, private endpoints, APKs, memory dumps, generated binaries, or assessment-target details.
- Run `python3 scripts/audit-sensitive-data.py` before every commit.

## Git

- Commit headers use lowercase English Angular format: `type(scope): subject`.
- The versioned commit hook is `.githooks/commit-msg`; enable it with `git config core.hooksPath .githooks`.
- Do not bypass hooks. Do not rewrite published history unless the repository owner explicitly requests it.
