#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# Full startup requires the image-bound zygote preload layer.
export XENOID_ZYGOTE_PRELOAD=1
DRY=0
SKIP_BUILD=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
  esac
done
# Only pass --start-colima for local Colima backends (never linux-docker / remote context).
start_colima_flag() {
  python3 - <<PY
import sys
from pathlib import Path
sys.path.insert(0, str(Path("$ROOT") / "src"))
from xenoid.config import load_config
from xenoid.backend import RuntimeManager
sys.exit(0 if RuntimeManager(load_config()).should_use_colima() else 1)
PY
}
START_COLIMA=()
if start_colima_flag; then START_COLIMA=(--start-colima); fi

cmds=()
if [[ "$SKIP_BUILD" == 1 ]]; then
  cmds+=("validate prebuilt runtime artifacts")
else
  cmds+=("./xenoid build all" "./scripts/build-native-shim.sh arm64 prop")
fi
cmds+=(
  "./xenoid start ${START_COLIMA[*]} --recreate --no-adb-root --install-daemon $ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
  "./xenoid input deploy <runtime-abi input helper>"
  "./xenoid hide deploy <runtime-abi hide helper>"
  "./xenoid hide deploy-overlay <runtime-abi overlay helper>"
  "./xenoid adb push <runtime-abi prop-area helper> /data/local/tmp/xenoid-prop-area"
  "./xenoid adb push <runtime-abi SSAID helper> /data/local/tmp/xenoid-ssaid"
  "./xenoid profile deploy-helper <runtime-abi profile helper>"
  "./xenoid device apply $ROOT/examples/fingerprints/sample-profile.json --keep-unique"
  "./xenoid root exec <remove stale Frida state>"
  "./xenoid hide apply $ROOT/examples/hide/default-policy.json"
  "./xenoid root exec <restart health HAL and reset battery state>"
  "./xenoid ebpf build"
  "./xenoid ebpf unload"
  "./xenoid ebpf load"
  "./scripts/smoke-ebpf.sh --verify-loaded"
  "./xenoid daemon health"
  "./xenoid doctor --require-runtime"
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
  ./xenoid doctor >&2 || true
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
    native/xenoid-camerahal/xenoid-camerahal
    native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml
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
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    printf '[up] --skip-build: missing/invalid artifact: %s\n' "${MISSING[@]}" >&2
    echo "[up] run without --skip-build (needs Android NDK + SDK/JDK) or use a release bundle" >&2
    false
  fi
  echo "[up] --skip-build: ${#ARM_ARTS[@]} arm64 artifacts + APK verified"
else
  ./xenoid build all
  ./scripts/build-native-shim.sh arm64 prop >/dev/null
fi
./xenoid start "${START_COLIMA[@]}" --recreate --no-adb-root --install-daemon "$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
# Full startup uses rootd and avoids restarting adbd as root. Another adbd
# restart could expose port 5555 again after the internal port was hidden.
# Pick helper binaries for the runtime ABI: arm64-v8a uses unsuffixed arm64
# artifacts, while x86_64 uses the -x86_64 suffix.
ABI="$(./xenoid adb shell getprop ro.product.cpu.abi 2>/dev/null | grep -oE 'arm64-v8a|x86_64' | head -1 || true)"
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

./xenoid input deploy "$INPUT_BIN"
./xenoid hide deploy "$HIDE_BIN"
./xenoid hide deploy-overlay "$OVERLAY_BIN"
./xenoid adb push "$PROP_AREA_BIN" /data/local/tmp/xenoid-prop-area
./xenoid adb shell chmod 755 /data/local/tmp/xenoid-prop-area
# Deploy the libc interposition library used by direct native smoke checks.
SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-${ABI/aarch64/arm64}.so"
[[ "$ABI" == "arm64-v8a" || "$ABI" == "arm64" || "$ABI" == "aarch64" ]] && SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-arm64.so"
[[ "$ABI" == "x86_64" ]] && SHIM_SO="$ROOT/native/xenoid-shim/libxenoid_shim-x86_64.so"
if [[ ! -f "$SHIM_SO" ]]; then echo "missing native shim for $ABI" >&2; false; fi
./xenoid adb shell 'mkdir -p /data/local/tmp/.ld'
./xenoid adb push "$SHIM_SO" /data/local/tmp/.ld/core.so
./xenoid adb shell chmod 755 /data/local/tmp/.ld/core.so
./xenoid adb push "$SSAID_BIN" /data/local/tmp/xenoid-ssaid
./xenoid adb shell chmod 755 /data/local/tmp/xenoid-ssaid
./xenoid profile deploy-helper "$PROFILE_BIN"
# Re-stage the effective fingerprint on every cold start without rotating stable
# identifiers. Rotation is an explicit `xenoid device apply` operation; doing it
# implicitly on every `up` makes boot/property/profile views race and diverge.
./xenoid device apply "$ROOT/examples/fingerprints/sample-profile.json" --keep-unique
# Production startup contains no Frida process or payload. Dynamic instrumentation
# remains an explicit analysis command and never mutates the zygote by default.
./xenoid frida stop >/dev/null 2>&1 || true
./xenoid root exec 'pkill -x svc.bin 2>/dev/null || true; pkill -x .fs64 2>/dev/null || true; pkill -x frida-server 2>/dev/null || true; rm -rf /data/system/.core /data/local/tmp/.fs64 /data/local/tmp/frida-server /data/local/tmp/xenoid-frida /data/local/tmp/.xenoid-hidden/frida-server.bak; rm -f /data/local/tmp/libxenoid_*.so'
# Host control uses the configured TCP ADB endpoint; no local Unix socket is required.
./xenoid root exec 'rm -f /dev/socket/adbd'
./xenoid hide apply "$ROOT/examples/hide/default-policy.json"
# Health example HAL only rediscovers the kmod power_supply after a service
# restart. Then unfreeze BatteryService so voltage/technology come from HAL
# instead of a prior `cmd battery set` freeze (which cannot set voltage).
./xenoid root exec 'stop vendor.health-default >/dev/null 2>&1 || true; start vendor.health-default >/dev/null 2>&1 || true; sleep 1; dumpsys battery reset >/dev/null 2>&1 || true'
# System-layer eBPF path-hide (host/Colima kernel). Complements kmod; not Frida.
./xenoid ebpf build
./xenoid ebpf unload
./xenoid ebpf load
./scripts/smoke-ebpf.sh --verify-loaded
./xenoid daemon health
./xenoid doctor --require-runtime
