#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# Full startup requires the image-bound zygote preload layer.
export XENOID_ZYGOTE_PRELOAD=1
DRY=0
SKIP_BUILD=0
INSTANCE="${XENOID_INSTANCE:-default}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --instance)
      [[ $# -ge 2 ]] || { echo "--instance requires a name" >&2; exit 2; }
      INSTANCE="$2"
      shift 2
      ;;
    --instance=*) INSTANCE="${1#--instance=}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
export XENOID_PROJECT="$ROOT"
export XENOID_INSTANCE="$INSTANCE"
xenoid_cli() {
  ./xenoid --instance "$INSTANCE" "$@"
}
# Only pass --start-colima for local Colima backends (never linux-docker / remote context).
start_colima_flag() {
  python3 - <<PY
import sys
from pathlib import Path
sys.path.insert(0, str(Path("$ROOT") / "src"))
from xenoid.config import resolve_instance
from xenoid.backend import RuntimeManager
context, config, lease = resolve_instance("$INSTANCE", project_root=Path("$ROOT"))
sys.exit(0 if RuntimeManager(context, config, lease).should_use_colima() else 1)
PY
}
START_COLIMA=()
if start_colima_flag; then START_COLIMA=(--start-colima); fi

cmds=()
if [[ "$SKIP_BUILD" == 1 ]]; then
  cmds+=("validate prebuilt runtime artifacts")
else
  cmds+=("./xenoid --instance $INSTANCE build all" "./scripts/build-native-shim.sh arm64 prop")
fi
cmds+=(
  "./xenoid --instance $INSTANCE start ${START_COLIMA[*]} --recreate --no-adb-root --install-daemon $ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
  "./xenoid --instance $INSTANCE input deploy <runtime-abi input helper>"
  "./xenoid --instance $INSTANCE hide deploy <runtime-abi hide helper>"
  "./xenoid --instance $INSTANCE hide deploy-overlay <runtime-abi overlay helper>"
  "./xenoid --instance $INSTANCE adb push <runtime-abi prop-area helper> /data/local/tmp/xenoid-prop-area"
  "./xenoid --instance $INSTANCE adb push <runtime-abi SSAID helper> /data/local/tmp/xenoid-ssaid"
  "./xenoid --instance $INSTANCE profile deploy-helper <runtime-abi profile helper>"
  "./xenoid --instance $INSTANCE device apply $ROOT/examples/fingerprints/sample-profile.json --keep-unique"
  "./xenoid --instance $INSTANCE root exec <remove stale Frida state>"
  "./xenoid --instance $INSTANCE hide apply $ROOT/examples/hide/default-policy.json"
  "./xenoid --instance $INSTANCE root exec <restart health HAL and reset battery state>"
  "./xenoid --instance $INSTANCE ebpf build"
  "./xenoid --instance $INSTANCE ebpf unload"
  "./xenoid --instance $INSTANCE ebpf load"
  "./scripts/smoke-ebpf.sh --verify-loaded"
  "./xenoid --instance $INSTANCE daemon health"
  "./xenoid --instance $INSTANCE adb shell pm grant --user 0 dev.xenoid.daemon android.permission.CAMERA"
  "./xenoid --instance $INSTANCE camera apply"
  "./xenoid --instance $INSTANCE camera status --check"
  "./xenoid --instance $INSTANCE doctor --require-runtime"
)
if [[ "$DRY" == 1 ]]; then
  printf '{"ok":true,"dryRun":true,"skipBuild":%s,"commands":[' "$([[ $SKIP_BUILD == 1 ]] && echo true || echo false)"
  first=1
  for c in "${cmds[@]}"; do [[ $first -eq 0 ]] && printf ','; first=0; python3 -c 'import json,sys; print(json.dumps(sys.argv[1]), end="")' "$c"; done
  printf ']}\n'
  exit 0
fi

diagnose_failure() {
  local rc=$?
  trap - ERR
  echo "[up] startup failed; collecting unified diagnostics" >&2
  xenoid_cli doctor >&2 || true
  exit "$rc"
}
trap diagnose_failure ERR
if [[ "$SKIP_BUILD" == 1 ]]; then
  echo "[up] --skip-build: validating prebuilt artifacts"
  APK="$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
  MISSING=()
  [[ -f "$APK" ]] || MISSING+=("daemon APK: $APK")
  # Full ARM (aarch64, no-suffix/-arm64 convention) deliverable set: start's
  # runtime-context needs netctl/prop-area/zygote/sensorshal; up's deploy steps
  # need input/hide/overlay/ssaid/profile/rootd.
  ARM_ARTS=(
    native/xenoid-input/xenoid-input
    native/xenoid-hide/xenoid-hide
    native/xenoid-hide/xenoid-overlay
    native/xenoid-hide/xenoid-prop-area
    native/xenoid-hide/xenoid-ssaid
    native/xenoid-profile/xenoid-profile
    native/xenoid-netctl/xenoid-netctl
    native/xenoid-rootd/xenoid-rootd-arm64
    native/xenoid-zygote/libxenoid_zygote.so
    native/xenoid-shim/libxenoid_shim-arm64.so
    native/xenoid-pivot/xenoid-pivot
    native/xenoid-sensorshal/xenoid-sensorshal
    native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml
    native/xenoid-gralloc/gralloc.redroid.so
    native/xenoid-camerahal/android.hardware.camera.provider-service-aidl
    native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml
    native/xenoid-camerahal/media_profiles_V1_0.xml
    native/xenoid-proxy-sandbox/xenoid-proxy-sandbox
  )
  for f in "${ARM_ARTS[@]}"; do
    if [[ ! -f "$ROOT/$f" ]]; then MISSING+=("$f"); continue; fi
    if command -v file >/dev/null 2>&1; then
      FB="$(file -b "$ROOT/$f")"
      case "$FB" in
        ELF*) echo "$FB" | grep -q 'aarch64' || MISSING+=("$f (not aarch64: $(echo "$FB" | cut -d, -f1-2))") ;;
      esac
    fi
  done
  SANDBOX="$ROOT/native/xenoid-proxy-sandbox/xenoid-proxy-sandbox"
  if [[ -f "$SANDBOX" ]] && ! python3 - "$SANDBOX" <<'PY'
import pathlib, struct, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
valid = len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01"
if valid:
    valid = int.from_bytes(data[18:20], "little") == 183
if valid:
    offset = struct.unpack_from("<Q", data, 32)[0]
    size = struct.unpack_from("<H", data, 54)[0]
    count = struct.unpack_from("<H", data, 56)[0]
    valid = all(
        struct.unpack_from("<I", data, offset + index * size)[0] != 3
        for index in range(count)
    )
valid = valid and b"/system/bin/linker64" not in data
raise SystemExit(0 if valid else 1)
PY
  then
    MISSING+=("native/xenoid-proxy-sandbox/xenoid-proxy-sandbox (not Linux ARM64)")
  fi
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    printf '[up] --skip-build: missing/invalid artifact: %s\n' "${MISSING[@]}" >&2
    echo "[up] run without --skip-build (needs Android NDK + SDK/JDK) or use a release bundle" >&2
    false
  fi
  echo "[up] --skip-build: ${#ARM_ARTS[@]} arm64 artifacts + APK verified"
else
  xenoid_cli build all
  ./scripts/build-native-shim.sh arm64 prop >/dev/null
fi
xenoid_cli start "${START_COLIMA[@]}" --recreate --no-adb-root --install-daemon "$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
# Full startup uses rootd and avoids restarting adbd as root. Another adbd
# restart could expose port 5555 again after the internal port was hidden.
# Pick helper binaries for the runtime ABI: arm64-v8a uses unsuffixed arm64
# artifacts, while x86_64 uses the -x86_64 suffix.
ABI="$(xenoid_cli adb shell getprop ro.product.cpu.abi 2>/dev/null | grep -oE 'arm64-v8a|x86_64' | head -1 || true)"
ARCH_TOK="x86_64"; SUF="-x86_64"
[[ "$ABI" == "arm64-v8a" ]] && { ARCH_TOK="arm64"; SUF=""; }
pick() { # pick <dir> <base> — echo existing binary path for current ABI, prefer exact, fall back to the other arch
  local d="$ROOT/native/$1" b="$2"
  if [[ -f "$d/$b$SUF" ]]; then echo "$d/$b$SUF"; elif [[ -f "$d/$b" ]]; then echo "$d/$b"; elif [[ -f "$d/$b-x86_64" ]]; then echo "$d/$b-x86_64"; fi
}
# rootd is now started as uid=0 by `xenoid start` (ensure_rootd_root via docker exec) so the
# daemon gets a real root channel. Do NOT relaunch it here via `adb shell` — that runs as
# uid=2000 and would replace the root instance with a shell one that EPERMs on mounts.

INPUT_BIN="$(pick xenoid-input xenoid-input)"
if [[ -z "$INPUT_BIN" ]]; then echo "missing input helper for $ABI" >&2; false; fi
HIDE_BIN="$(pick xenoid-hide xenoid-hide)"
if [[ -z "$HIDE_BIN" ]]; then echo "missing hide helper for $ABI" >&2; false; fi
OVERLAY_BIN="$(pick xenoid-hide xenoid-overlay)"
if [[ -z "$OVERLAY_BIN" ]]; then echo "missing overlay helper for $ABI" >&2; false; fi
PROP_AREA_BIN="$(pick xenoid-hide xenoid-prop-area)"
if [[ -z "$PROP_AREA_BIN" ]]; then echo "missing prop-area helper for $ABI" >&2; false; fi
SSAID_BIN="$(pick xenoid-hide xenoid-ssaid)"
if [[ -z "$SSAID_BIN" ]]; then echo "missing SSAID helper for $ABI" >&2; false; fi
PROFILE_BIN="$(pick xenoid-profile xenoid-profile)"
if [[ -z "$PROFILE_BIN" ]]; then echo "missing profile helper for $ABI" >&2; false; fi

xenoid_cli input deploy "$INPUT_BIN"
xenoid_cli hide deploy "$HIDE_BIN"
xenoid_cli hide deploy-overlay "$OVERLAY_BIN"
xenoid_cli adb push "$PROP_AREA_BIN" /data/local/tmp/xenoid-prop-area
xenoid_cli adb shell chmod 755 /data/local/tmp/xenoid-prop-area
# Deploy the libc interposition library used by direct native smoke checks.
SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-${ABI/aarch64/arm64}.so"
[[ "$ABI" == "arm64-v8a" || "$ABI" == "arm64" || "$ABI" == "aarch64" ]] && SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-arm64.so"
[[ "$ABI" == "x86_64" ]] && SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-x86_64.so"
if [[ ! -f "$SHIM_SO" ]]; then echo "missing native shim for $ABI" >&2; false; fi
xenoid_cli adb shell 'mkdir -p /data/local/tmp/.ld'
xenoid_cli adb push "$SHIM_SO" /data/local/tmp/.ld/core.so
xenoid_cli adb shell chmod 755 /data/local/tmp/.ld/core.so
xenoid_cli adb push "$SSAID_BIN" /data/local/tmp/xenoid-ssaid
xenoid_cli adb shell chmod 755 /data/local/tmp/xenoid-ssaid
xenoid_cli profile deploy-helper "$PROFILE_BIN"
# Re-stage the effective fingerprint on every cold start without rotating stable
# identifiers. Rotation is an explicit `xenoid device apply` operation; doing it
# implicitly on every `up` makes boot/property/profile views race and diverge.
xenoid_cli device apply "$ROOT/examples/fingerprints/sample-profile.json" --keep-unique
# Production startup contains no Frida process or payload. Dynamic instrumentation
# remains an explicit analysis command and never mutates the zygote by default.
xenoid_cli frida stop >/dev/null 2>&1 || true
xenoid_cli root exec 'pkill -x svc.bin 2>/dev/null || true; pkill -x .fs64 2>/dev/null || true; pkill -x frida-server 2>/dev/null || true; rm -rf /data/system/.core /data/local/tmp/.fs64 /data/local/tmp/frida-server /data/local/tmp/xenoid-frida /data/local/tmp/.xenoid-hidden/frida-server.bak; rm -f /data/local/tmp/libxenoid_*.so'
# Host control uses the configured TCP ADB endpoint; no local Unix socket is required.
xenoid_cli root exec 'rm -f /dev/socket/adbd'
xenoid_cli hide apply "$ROOT/examples/hide/default-policy.json"
# Health example HAL only rediscovers the kmod power_supply after a service
# restart. Then unfreeze BatteryService so voltage/technology come from HAL
# instead of a prior `cmd battery set` freeze (which cannot set voltage).
xenoid_cli root exec 'stop vendor.health-default >/dev/null 2>&1 || true; start vendor.health-default >/dev/null 2>&1 || true; sleep 1; dumpsys battery reset >/dev/null 2>&1 || true'
# System-layer eBPF path-hide (host/Colima kernel). Complements kmod; not Frida.
xenoid_cli ebpf build
xenoid_cli ebpf load
./scripts/smoke-ebpf.sh --verify-loaded
xenoid_cli daemon health
xenoid_cli adb shell pm grant --user 0 dev.xenoid.daemon android.permission.CAMERA
xenoid_cli camera apply
xenoid_cli camera status --check
xenoid_cli doctor --require-runtime
