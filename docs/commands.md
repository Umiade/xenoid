# Xenoid Command Reference

Every `./xenoid` command, grouped by function. Task-oriented walkthroughs live in [operations](operations.md); this document is the flat inventory.

Global options, valid before any command:

```bash
./xenoid --instance NAME <command>   # select an instance (default: $XENOID_INSTANCE, then "default")
./xenoid <command> --help            # authoritative flag reference for that command
```

Commands marked *(internal)* run as part of `up` convergence and are not everyday operator entrypoints.

## Host setup and lifecycle

- `./xenoid install-runtime [--dry-run]` — install macOS runtime dependencies via Homebrew and start Colima.
- `./xenoid linux-binderfs [--dry-run]` — set up Linux binderfs devices for redroid.
- `./xenoid init [--image IMAGE] [--backend BACKEND] [--config CONFIG] [--from FROM_INSTANCE] [--no-google-services]` — initialize the selected immutable instance.
- `./xenoid up [--dry-run] [--skip-build]` — converge the complete Xenoid production runtime. `--skip-build` remains supported and validates existing artifact records without compiling. The final result is `dev.xenoid.convergence/v1` normally, or the canonical top-level `dev.xenoid.device-regenerate/v3` result when `up` resumes a pending regeneration.
- `./xenoid start [--dry-run] [--no-wait] [--start-colima] [--install-daemon APK] [--no-adb-root] [--skip-preflight] [--recreate]` — start the low-level Android runtime without full Xenoid state convergence.
- `./xenoid stop` — stop and retain the owned Android runtime container.
- `./xenoid status` — observe runtime state and report the recommended convergence action.
- `./xenoid logs [--out-dir DIR]` — collect Docker/ADB runtime logs.
- `./xenoid view` — open scrcpy for the Xenoid Android target.
- `./xenoid adb ...` — run adb against the Xenoid target.
- `./xenoid doctor [--full] [--require-runtime] [--out PATH]` — check installation, host dependencies, and the live runtime.

## Instances and configuration

- `./xenoid instance list` — list initialized instances.
- `./xenoid config show` — print the selected instance context and config as JSON.
- `./xenoid config set [--backend B] [--image I] [--runtime-image-tag T] [--docker-context C] [--network-dns-server ADDR] [--auto-build-runtime-image | --no-auto-build-runtime-image]` — update selected fields of the instance config.

## Runtime image and rootfs

- `./xenoid runtime-build-image [--image IMAGE] [--dry-run]` — build the custom redroid Docker image with Xenoid payloads.
- `./xenoid runtime-context [--image IMAGE]` — create the custom redroid Docker build context with Xenoid payloads.
- `./xenoid make-rootfs` — build/refresh the ext4 rootfs+data loop images for the pivot entrypoint.

## Build and release

- `./xenoid build daemon|keymint|input|hide|profile|netctl|gralloc|hwcomposer|ril|radio-config` — build one artifact target (daemon APK or native helper).
- `./xenoid build all [--force]` — build every artifact; `--force` rebuilds and verifies deterministic output.
- `./xenoid package-release [--version VERSION]` — package a transferable Xenoid release bundle.
- `./xenoid verify-release ARCHIVE` — verify a Xenoid release bundle manifest and required artifacts.

## Google services

- `./xenoid google-services releases` — list the pinned Google services release registry.
- `./xenoid google-services status [--require-runtime]` — show configured, bound, image, rootfs, and live runtime state.
- `./xenoid google-services enable [--release RELEASE]` — enable the pinned release before first Android data creation.
- `./xenoid google-services disable` — disable Google services before first Android data creation.
- `./xenoid google-services import-mindthegapps ARCHIVE CERTIFICATE` — verify and import the pinned official MindTheGapps source release.
- `./xenoid google-services import-microg GMSCORE GSFPROXY` — verify and import the pinned official microG GmsCore and GsfProxy APKs.

## Daemon

- `./xenoid daemon health` — check the daemon API health endpoint.
- `./xenoid daemon install APK` — install the daemon APK and reconcile bootstrap state.
- `./xenoid daemon start` — reconcile daemon bootstrap and the persisted proxy desired state.
- `./xenoid daemon ensure` — ensure daemon bootstrap is converged (bootstrap plus proxy desired state).

## Location and cellular identity

- `./xenoid location list` — list supported countries without contacting the runtime.
- `./xenoid location set COUNTRY` — select a country (ISO 3166-1 alpha-2) and converge SIM, carrier, LTE cell, locale, and timezone.
- `./xenoid location status [--check]` — show masked host and Android location identity state; `--check` requires matching active digests in the current runtime epoch.
- `./xenoid location apply [--default COUNTRY]` *(internal)* — converge the persisted location identity.
- `./xenoid cellular status` — low-level cellular radio smoke view: masked location state and radio properties.

## Global proxy

- `./xenoid proxy status [--check]` — show redacted proxy status; `--check` runs a fresh data-plane proof.
- `./xenoid proxy set (--stdin | --prompt | --source-file FILE) [--kind endpoint|uri_list|clash|subscription] [--name NAME] [--udp | --no-udp] [--allow-insecure-http] [--enable | --no-enable]` — set a source from stdin or a current-user-owned mode-0600 file.
- `./xenoid proxy subscribe (--stdin | --prompt | --source-file FILE) [--name NAME] [--udp | --no-udp] [--allow-insecure-http] [--enable | --no-enable]` — set an online configuration URL from stdin or a private file.
- `./xenoid proxy import [--kind KIND] [--name NAME] [--udp | --no-udp] [--allow-insecure-http] [--enable | --no-enable] FILE` — import a regular, non-symlink, current-user-owned mode-0600 file.
- `./xenoid proxy on` — enable the configured source.
- `./xenoid proxy off` — disable proxying while preserving the configured source.
- `./xenoid proxy clear [--discard-unreadable-state]` — disable and clear the configured source.
- `./xenoid proxy list` — list only nodes present in redacted agent status observations.
- `./xenoid proxy select NAME` — select an observed node.
- `./xenoid proxy export --out FILE` — atomically export source bytes to a private mode-0600 file.
- `./xenoid proxy prepare [--asset FILE]` — prepare the digest-pinned proxy engine asset on the Docker engine host.
- `./xenoid proxy reconcile` *(internal)* — converge the persisted proxy desired state.

## Device identity and KeyMint keybox

- `./xenoid device collect [--out PATH]` — collect the live device fingerprint through the daemon.
- `./xenoid device apply [--keep-unique | --instance-identity] [--generate-frida] [--frida-out PATH] PROFILE` — apply a fingerprint profile and re-converge the runtime.
- `./xenoid device set FIELD VALUE` — set a single fingerprint field.
- `./xenoid device generate-frida [--out PATH] [--keep-unique] PROFILE` — generate a Frida script for a profile without applying it.
- `./xenoid device generate-service-frida [--out PATH] [--keep-unique] PROFILE` — generate the service-side Frida script for a profile.
- `./xenoid device keybox set FILE` — import a trusted-local KeyMint keybox.
- `./xenoid device keybox status` — show KeyMint keybox state.
- `./xenoid device keybox clear` — clear the configured keybox.
- `./xenoid device regenerate [--dry-run]` — first fail-closed checks that the current checkout and live runtime already converge without mutation, then rotates every per-device uniqueness factor (IDs, SIM, boot, filesystem identity, per-app SSAID, GAID/GSF, Bluetooth address, DRM `deviceUniqueId`) in place across one soft reboot; the container is never recreated. The command no longer accepts `--skip-build` (`up --skip-build` remains available). Successful microG regeneration enters `googleIdentityMode=offline-seeded`: FCM registration and delivery are unavailable, and status reports `cloudMessaging=unsupported` with `offline-checkin-disabled`. Run `./xenoid up` first when preflight reports `device_regeneration_runtime_not_converged`.

## Camera

- `./xenoid camera status [--check]` — show camera source and activation status; `--check` runs a fresh ordinary-app capture self-test.
- `./xenoid camera set photo|video FILE` — validate, persist, and publish a camera source.
- `./xenoid camera mode naturalized|faithful` — set the camera rendering mode.
- `./xenoid camera clear photo|video|all` — clear configured camera sources.
- `./xenoid camera apply` — reconcile persisted camera state.

## Root control

- `./xenoid root status` — show token-gated root helper status.
- `./xenoid root exec COMMAND...` — run a command through the token-gated root helper.

## Frida (explicit inspection only)

- `./xenoid frida fetch [--version V] [--arch A] [--out-dir DIR]` — download a frida-server build without deploying it.
- `./xenoid frida install [--version V] [--arch A] [--out-dir DIR] [--remote-path PATH]` — download and deploy frida-server.
- `./xenoid frida deploy PATH [--remote-path PATH]` — deploy a local frida-server binary.
- `./xenoid frida deploy-scripts [--scripts-dir DIR] [--remote-dir DIR]` — push the Frida script directory to the device.
- `./xenoid frida load-script [--spawn] [--oneshot] PACKAGE SCRIPT` — load a script into a target application.
- `./xenoid frida start [--port PORT]` — start frida-server (default port 27042).
- `./xenoid frida stop` — stop frida-server.
- `./xenoid frida status` — show frida-server state.

Frida is never part of normal production startup. After any instrumentation session, stop instrumentation and restart the complete runtime before production acceptance.

## Profile helper

- `./xenoid profile deploy-helper PATH [--remote-path PATH]` — deploy the native profile helper.
- `./xenoid profile status` — show profile helper status.
- `./xenoid profile env` — show the helper-observed environment.
- `./xenoid profile dump` — dump the helper profile data.

## Applications, input, and automation

- `./xenoid app install PATH` — install an APK through the daemon.
- `./xenoid app uninstall PACKAGE` — uninstall an application.
- `./xenoid app launch COMPONENT` — launch an activity component (for example `com.example.app/.MainActivity`).
- `./xenoid input deploy PATH [--remote-path PATH]` — deploy the input injection helper.
- `./xenoid input tap X Y` — inject a tap.
- `./xenoid input swipe X1 Y1 X2 Y2 [DURATION_MS]` — inject a swipe.
- `./xenoid automation plan SCRIPT` — plan an automation script without executing it.
- `./xenoid automation run-host SCRIPT [--execute]` — plan on the host; `--execute` executes through the daemon API.
- `./xenoid automation run SCRIPT` — execute an automation script through the daemon.

## Environment hiding

- `./xenoid hide deploy PATH [--remote-path PATH]` — deploy the environment-hiding helper.
- `./xenoid hide status` — show hiding policy status.
- `./xenoid hide apply [POLICY]` — apply a hiding policy JSON (or the persisted policy).
- `./xenoid hide deploy-overlay [PATH] [--remote-path PATH]` — deploy the overlay helper.
- `./xenoid hide overlay-status` — show overlay helper status.
- `./xenoid hide cleanup-overlay` — remove overlay state.

## Shared engine-host protection (kmod/eBPF)

- `./xenoid ebpf build` — build and validate shared protection replacements without loading.
- `./xenoid ebpf load` — converge shared engine-host protection.
- `./xenoid ebpf status` — show safe shared protection status.
- `./xenoid ebpf smoke` — run fresh target-engine host and Android UID protection proofs.
- `./xenoid ebpf unload [--maintenance]` — maintenance-only eBPF unload with no active Xenoid runtimes.

## Network identity helper

- `./xenoid netctl deploy [PATH] [--remote-path PATH]` — deploy the rtnetlink network identity helper.
- `./xenoid netctl status [--ifname IFNAME]` — show interface identity state (default `rmnet_data0`).
- `./xenoid netctl set-mac MAC [--ifname IFNAME]` — set the interface MAC address.

## OTA

- `./xenoid ota make [--version VERSION]` — build an OTA bundle.
- `./xenoid ota install-bundle BUNDLE` — install a local OTA bundle.
- `./xenoid ota check` — check for OTA updates through the daemon.
- `./xenoid ota apply [--channel CHANNEL]` — apply an OTA update from a channel (default `stable`).

## MCP and remote service

- `./xenoid mcp-config` — print the MCP server config.
- `./xenoid-mcp` — run the MCP server entrypoint; tools are documented in [mcp-tools](mcp-tools.md).
- `./xenoid-service` — run the remote service entrypoint; see [remote-service](remote-service.md).
