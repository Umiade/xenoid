# Changelog

[Chinese Version](CHANGELOG_CN.md)

All notable changes to Xenoid are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases are tagged
`xenoid-<version>` and the daemon `versionCode` is
`major * 10000 + minor * 100 + patch`.

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
