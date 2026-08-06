# Xenoid MCP tool contract

The `xenoid-mcp` stdio server exposes these tools for agent/host use (67 total).
Every tool returns a JSON object; `ok` indicates success. The daemon-backed tools
require the runtime up and the daemon reachable (daemon control channel is
authenticated with the per-instance `X-Xenoid-Token`).


## Runtime lifecycle

### `xenoid_doctor`
Check installation, host dependencies, and the live runtime.
  - `full` (boolean): include builds and exhaustive runtime smoke checks
  - `requireRuntime` (boolean): fail when Android is not running and ready

### `xenoid_install_runtime_plan`
Dry-run macOS runtime dependency install plan
_No parameters._

### `xenoid_up_plan`
Dry-run full Xenoid startup plan
_No parameters._

### `xenoid_start`
Start Xenoid Android runtime
  - `dryRun` (boolean)
  - `startColima` (boolean)
  - `installDaemonApk` (string)
  - `adbRoot` (boolean)
  - `recreate` (boolean)

### `xenoid_stop`
Stop Xenoid Android runtime
_No parameters._

### `xenoid_status`
Get runtime status
_No parameters._

### `xenoid_logs`
Collect Docker/ADB runtime logs
  - `outDir` (string)

### `xenoid_view`
Open scrcpy for Xenoid Android target
_No parameters._

### `xenoid_runtime_context`
Create custom redroid Docker build context with Xenoid payloads
  - `image` (string)

### `xenoid_runtime_build_image`
Build or dry-run custom redroid Docker image
  - `image` (string)
  - `tag` (string)
  - `dryRun` (boolean)

### `xenoid_linux_binderfs`
Run/dry-run Linux binderfs setup
  - `dryRun` (boolean)

### `xenoid_config_show`
Show Xenoid config
_No parameters._

## Daemon & root

### `xenoid_daemon_health`
Check Android daemon health
_No parameters._

### `xenoid_daemon_ensure`
Ensure Android daemon API is reachable
_No parameters._

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
_No parameters._

### `xenoid_proxy_select`
Select one node already present in the redacted agent observation.
  - `name` (string) **(required)**


### `xenoid_root_status`
Check daemon root/su helper status
_No parameters._

### `xenoid_root_exec`
Run command through daemon root helper
  - `command` (string) **(required)**


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
  - `endpoint` (string)

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


## System-layer eBPF (host)

Host-side path-hide hooks (`native/xenoid-ebpf`). Distinct from Frida (app-layer) and from Magisk/Zygisk.

### `xenoid_ebpf_build`
Build eBPF program + libbpf loader on Colima/Linux engine host
_No parameters._

### `xenoid_ebpf_load`
Load/attach host-side eBPF path-hide
_No parameters._

### `xenoid_ebpf_status`
JSON status for pinned eBPF path-hide
_No parameters._

### `xenoid_ebpf_unload`
Unload/unpin host-side eBPF path-hide
_No parameters._


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
