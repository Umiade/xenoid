# Xenoid MCP tool contract

The `xenoid-mcp` stdio server exposes the catalog below to a trusted local agent for one fixed `XENOID_INSTANCE`. The catalog is generated from code; this document intentionally does not hard-code a count. Every call accepts exactly the documented camelCase properties and returns one JSON object with `ok`.

Runtime-dependent tools share the listener-first authenticated bootstrap path. The daemon credential is app-private and may be held only in a container-ID-bound host memory buffer; neither MCP adapter persists or returns it. Component tools require their own component readiness, while aggregate daemon health is final acceptance rather than a bootstrap prerequisite.

`xenoid-service` derives a smaller, scope-filtered network catalog from this local catalog. It adds required `instance` to every instance tool, supports `xenoid_instances_list`, keeps reads observational, and excludes unrestricted host paths/code, builds, packaging, deployment, binderfs, and host protection changes. See [`remote-service.md`](remote-service.md).

Both adapters redact credentials, proxy sources/keys, Keybox/SIM bytes, private paths/endpoints, raw commands/responses, and child streams. `xenoid_up` calls the shared executor directly and returns safe phase summaries in one final result; it never spawns/parses another CLI.


## Runtime lifecycle

### `xenoid_doctor`
Observe host dependencies, selected digest-bound GateRunner records, and an already-running runtime.
  - `full` (boolean): select the broader doctor-safe static record set
  - `requireRuntime` (boolean): fail when fresh `LiveAcceptance` cannot observe a ready runtime

Doctor is non-converging even with `full`: it never calls `up`, ensures daemon/rootd, builds/packages, runs mutating gates, or recursively invokes a suite. Runtime absence can be `ok=true, complete=false` unless `requireRuntime` is true.

### `xenoid_install_runtime_plan`
Dry-run macOS runtime dependency install plan
_No parameters._

### `xenoid_up_plan`
Return the exact read-only initial or resumable convergence plan.
_No parameters._

### `xenoid_up`
Run the canonical full Xenoid production convergence path.
  - `skipBuild` (boolean): validate required artifact records/objects and fail on stale or missing inputs instead of compiling

Reuse is automatic; no runtime-reuse field exists. The executor chooses no-op, resume, start, create, or recreate and independently refines component actions. Results use `schema=dev.xenoid.convergence/v1` and include `plan`, `resumed`, safe `phases`, immutable `before`/`after`, and `nextActions`. CLI callers additionally receive pre-hash `dev.xenoid.progress/v1` JSONL and five-second heartbeats on stderr; MCP receives only the final bounded result.

`xenoid_up` also resumes a validated `dev.xenoid.device-regenerate/v2` transaction using its recorded fixed targets. A v1-only regeneration remains blocked; the evidence-preserving `device regenerate --restart-legacy-transaction` escape is trusted-local CLI only and is not an MCP tool.

### `xenoid_start`
Start the low-level Android runtime without full state convergence or acceptance.
  - `dryRun` (boolean)
  - `startColima` (boolean)
  - `installDaemonApk` (string)
  - `adbRoot` (boolean)
  - `recreate` (boolean)

`recreate` selects an already verified runtime image; it never builds artifacts/images. Normal operators should use `xenoid_up`.

### `xenoid_stop`
Quarantine, sync, and stop the owned Android runtime while retaining its immutable container ID and data volume.
_No parameters._

### `xenoid_status`
Observe runtime/cache/image/protection state. Important fields include `recommendedAction`, `driftReasons`, `pendingJournalPhase`, and content digests. A valid stopped container is not an error; status never mutates.
_No parameters._

### `xenoid_logs`
Collect Docker/ADB runtime logs
  - `outDir` (string)

### `xenoid_view`
Open scrcpy for Xenoid Android target
_No parameters._

### `xenoid_runtime_context`
Create a canonical custom redroid context from validated artifact/object records.
  - `image` (string)

### `xenoid_runtime_build_image`
Ensure or inspect the configured content-addressed runtime image.
  - `image` (string)
  - `dryRun` (boolean)

The configured runtime tag is only a repository namespace; no per-call tag field exists. The effective tag is derived from the full input SHA-256 and publication verifies full/boot/base identity labels.

### `xenoid_linux_binderfs`
Run/dry-run Linux binderfs setup
  - `dryRun` (boolean)

### `xenoid_config_show`
Show Xenoid config
_No parameters._

## Optional Google services

MCP exposes status and the fresh-instance provider transition, but intentionally does not accept host paths or proprietary import bytes. Import the pinned official release with the CLI before enabling it.

### `xenoid_google_services_status`
Show provider/release configuration, immutable binding, image/rootfs identity, live package readiness, and capability state.
  - `requireRuntime` (boolean): fail unless the configured runtime is running and ready

### `xenoid_google_services_enable`
Enable the known pinned release on the fixed fresh instance.
  - `release` (string): optional; only `MindTheGapps-13.0.0-arm64-20231025_200931` is accepted

### `xenoid_google_services_disable`
Disable Google services on the fixed fresh instance.
_No parameters._

## Daemon & root

### `xenoid_daemon_health`
Observe aggregate Android daemon health. It does not start or repair bootstrap.
_No parameters._

### `xenoid_daemon_ensure`
Join the shared listener-first transport/root/component reconciliation path.
_No parameters._

This tool never uses aggregate health as an early bootstrap prerequisite and never creates a host credential cache.

### `xenoid_daemon_install`
Install and start daemon APK
  - `apk` (string) **(required)**

## Global proxy

MCP intentionally exposes redacted lifecycle operations only. Configure or import credential-bearing sources through the Android Xenoid settings screen or the CLI's private stdin/file inputs.

### `xenoid_proxy_status`
Show redacted desired state, generation, selected node, capabilities, and packet counters for the fixed instance.
_No parameters._

### `xenoid_proxy_check`
Request and wait for a fresh check bound to the fixed instance, current generation, and runtime epoch.
_No parameters._

### `xenoid_proxy_on`
Enable and converge the configured source.
_No parameters._

### `xenoid_proxy_off`
Disable proxying while preserving the configured source.
_No parameters._

### `xenoid_proxy_clear`
Disable proxying and erase the configured source.
  - `discardUnreadableState` (boolean): explicit evidence-preserving quarantine and cryptographic clear when daemon state is unreadable

Ordinary clear (`false` or omitted) never silently discards unreadable bytes or releases quarantine. Authenticated import through trusted-local CLI is the other recovery path; source-bearing import remains absent from MCP.

### `xenoid_proxy_select`
Select one node already present in the redacted agent observation.
  - `name` (string) **(required)**


## Location identity

Location tools manage the explicit, proxy-independent device identity (country, locale, timezone, USIM, carrier, LTE cell). Results never include raw IMSI/ICCID/MSISDN — only masked values.

### `xenoid_location_list`
List supported location countries without contacting the runtime.
_No parameters._

### `xenoid_location_status`
Show masked host and Android location identity state.
  - `check` (boolean): require active host/Android digests to match in the current runtime epoch

### `xenoid_location_set`
Select the device location country and converge SIM, carrier, LTE cell, locale, and timezone. A country change recreates the owned container exactly once; selecting the current country is a no-op.
  - `countryCode` (string) **(required)**: ISO 3166-1 alpha-2 code from `xenoid_location_list`


### `xenoid_root_status`
Check the authenticated loopback root helper status.
_No parameters._

### `xenoid_root_exec`
Run a bounded command through the daemon/rootd boundary.
  - `command` (string) **(required)**

The helper exposes no application-visible `su`, host token file/cache, or credential-bearing argv/result.


## Device fingerprint & profile

### `xenoid_device_collect`
Collect Android device fingerprint through daemon
_No parameters._

### `xenoid_device_apply`
Apply device fingerprint profile through daemon
  - `profilePath` (string) **(required)**
  - `regenerateUnique` (boolean)

### `xenoid_device_set`
Set one fingerprint field through daemon
  - `field` (string) **(required)**
  - `value` (any) **(required)**

### `xenoid_device_generate_frida`
Generate Frida profile spoof script from fingerprint profile
  - `profilePath` (string) **(required)**
  - `out` (string)
  - `keepUnique` (boolean)

### `xenoid_device_generate_service_frida`
Generate service/system Frida spoof script from fingerprint profile
  - `profilePath` (string) **(required)**
  - `out` (string)
  - `keepUnique` (boolean)

### `xenoid_profile_deploy_helper`
Deploy native xenoid-profile helper
  - `path` (string) **(required)**
  - `remotePath` (string)

### `xenoid_profile_helper_status`
Query native profile helper status through daemon
_No parameters._

### `xenoid_profile_helper_env`
Query native profile helper env summary through daemon
_No parameters._

### `xenoid_profile_helper_dump`
Dump staged effective profile through daemon
_No parameters._


## Frida

### `xenoid_frida_install`
Download and deploy frida-server
  - `version` (string)
  - `arch` (string)
  - `outDir` (string)
  - `remotePath` (string)

### `xenoid_frida_fetch`
Download frida-server release asset
  - `version` (string)
  - `arch` (string)
  - `outDir` (string)

### `xenoid_frida_deploy`
Deploy frida-server to Android
  - `path` (string) **(required)**
  - `remotePath` (string)

### `xenoid_frida_deploy_scripts`
Deploy Xenoid Frida JS scripts to Android
  - `scriptsDir` (string)
  - `remoteDir` (string)

### `xenoid_frida_load_script`
Load a Frida JS script into a package/process
  - `package` (string) **(required)**
  - `script` (string) **(required)**
  - `spawn` (boolean)

### `xenoid_frida_start`
Start frida-server through daemon
  - `port` (integer)

### `xenoid_frida_stop`
Stop frida-server through daemon
_No parameters._

### `xenoid_frida_status`
Check frida-server status through daemon
_No parameters._


## Input & automation

### `xenoid_input_deploy`
Deploy native /dev/uinput helper
  - `path` (string) **(required)**
  - `remotePath` (string)

### `xenoid_input_tap`
Tap using daemon low-level input API
  - `x` (integer) **(required)**
  - `y` (integer) **(required)**

### `xenoid_input_swipe`
Swipe using daemon low-level input API
  - `x1` (integer) **(required)**
  - `y1` (integer) **(required)**
  - `x2` (integer) **(required)**
  - `y2` (integer) **(required)**
  - `durationMs` (integer)

### `xenoid_automation_plan`
Parse Xenoid JS automation task into ordered calls
  - `scriptPath` (string) **(required)**

### `xenoid_automation_run_host`
Run/plan Xenoid JS automation task with host JS runner
  - `scriptPath` (string) **(required)**
  - `execute` (boolean)

### `xenoid_automation_run`
Run Xenoid JS automation task
  - `scriptPath` (string) **(required)**


## Hide / overlay / network identity

### `xenoid_hide_deploy`
Deploy native xenoid-hide helper
  - `path` (string) **(required)**
  - `remotePath` (string)

### `xenoid_hide_status`
Inspect environment hiding policy through daemon
_No parameters._

### `xenoid_hide_apply`
Apply environment hiding policy through daemon
  - `policyPath` (string)

### `xenoid_hide_overlay_status`
Inspect Xenoid overlay helper status-json
_No parameters._

### `xenoid_hide_cleanup_overlay`
Cleanup Xenoid overlay bind mounts
_No parameters._

### `xenoid_netctl_deploy`
Deploy low-level rtnetlink network identity helper
  - `path` (string) **(required)**
  - `remotePath` (string)

### `xenoid_netctl_status`
Inspect ioctl/rtnetlink MAC identity through xenoid-netctl
  - `ifname` (string)

### `xenoid_netctl_set_mac`
Set interface MAC through xenoid-netctl RTM_SETLINK path
  - `mac` (string) **(required)**
  - `ifname` (string)


## Shared engine-host protection

The tools below address one digest-bound kmod/eBPF deployment shared by every Xenoid runtime on the selected Docker engine host. They are local stdio tools and are excluded from the remote network catalog.

### `xenoid_ebpf_build`
Build and validate shared protection replacement artifacts without replacing the active deployment.
_No parameters._

### `xenoid_ebpf_load`
Converge shared engine-host kmod/eBPF protection, reusing a matching deployment.
_No parameters._

### `xenoid_ebpf_status`
Return safe shared-protection scope, hashed engine identity, expected/current digests, inventory, and replacement/maintenance state.
_No parameters._

### `xenoid_ebpf_unload`
Maintenance-only eBPF unload; zero active owned runtimes is required.
  - `maintenance` (boolean) **(required)**: must be `true`

Normal `stop` never unloads protection. If a sibling runtime is active, replacement/unload fails closed and retains the verified deployment.


## Apps & OTA & release

### `xenoid_app_install`
Install APK by Android-side path through daemon
  - `path` (string) **(required)**

### `xenoid_app_uninstall`
Uninstall package through daemon
  - `package` (string) **(required)**

### `xenoid_app_launch`
Launch component through daemon
  - `component` (string) **(required)**

### `xenoid_ota_make`
Create local Xenoid OTA bundle
  - `version` (string)

### `xenoid_ota_install_bundle`
Install local Xenoid OTA bundle
  - `bundle` (string) **(required)**

### `xenoid_ota_check`
Check daemon OTA status
_No parameters._

### `xenoid_ota_apply`
Apply daemon OTA channel
  - `channel` (string)

### `xenoid_package_release`
Package transferable Xenoid release bundle
  - `version` (string)

### `xenoid_verify_release`
Verify a Xenoid release bundle
  - `archive` (string) **(required)**

Release packaging consumes fresh non-recursive gate evidence and validated artifact snapshots, emits canonical archives, and mandates verification before publication. Its packaged doctor evidence is explicitly offline (`complete=false`). Release results and archives exclude credentials, private paths/endpoints, proxy/Keybox material, imported proprietary payloads, runtime captures, and assessment details.
