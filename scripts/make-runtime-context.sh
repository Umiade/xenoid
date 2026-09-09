#!/usr/bin/env bash
set -euo pipefail

canonicalize_context() {
  python3 - "$1" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

SCHEMA = "dev.xenoid.runtime-context/v1"
EXECUTABLES = {
    "payload/android.hardware.camera.provider-service-aidl",
    "payload/android.hardware.radio.config-service.xenoid",
    "payload/android.hardware.security.keymint-service",
    "payload/app_process64",
    "payload/xenoid-app-process",
    "payload/xenoid-hide-helper",
    "payload/xenoid-init",
    "payload/xenoid-input",
    "payload/xenoid-netctl",
    "payload/xenoid-overlay-helper",
    "payload/xenoid-profile-helper",
    "payload/xenoid-prop-area",
    "payload/xenoid-sensorshal",
}
GOOGLE_PREFIX = "payload/google-services/"


class ContextError(Exception):
    pass


def digest_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def canonicalize(root: Path) -> None:
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ContextError("runtime_context_invalid")

    files: list[tuple[bytes, str, Path, int]] = []
    directories: list[tuple[bytes, str, Path]] = []
    seen: set[str] = set()
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for name in dirnames:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ContextError("runtime_context_unsafe_entry")
            relative = path.relative_to(root).as_posix()
            if relative in seen:
                raise ContextError("runtime_context_duplicate_entry")
            seen.add(relative)
            directories.append((relative.encode("utf-8"), relative, path))
        for name in filenames:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ContextError("runtime_context_unsafe_entry")
            relative = path.relative_to(root).as_posix()
            if relative == "context-manifest.json":
                continue
            if relative.startswith(".context-manifest."):
                raise ContextError("runtime_context_temporary_entry")
            if relative in seen:
                raise ContextError("runtime_context_duplicate_entry")
            seen.add(relative)
            source_mode = stat.S_IMODE(info.st_mode)
            files.append((relative.encode("utf-8"), relative, path, source_mode))


    entries: list[dict[str, object]] = []
    for _, relative, path, source_mode in files:
        executable = relative in EXECUTABLES or (
            relative.startswith(GOOGLE_PREFIX) and bool(source_mode & 0o111)
        )
        mode = 0o755 if executable else 0o644
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ContextError("runtime_context_unsafe_entry")
            os.fchmod(descriptor, mode)
            os.utime(descriptor, ns=(0, 0))
            digest = digest_descriptor(descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        entries.append(
            {
                "path": relative,
                "type": "file",
                "mode": f"0{mode:03o}",
                "size": info.st_size,
                "sha256": digest,
            }
        )
    for _, relative, path in directories:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise ContextError("runtime_context_unsafe_entry")
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        entries.append(
            {
                "path": relative,
                "type": "directory",
                "mode": "0755",
                "size": 0,
                "sha256": None,
            }
        )
    entries.sort(key=lambda entry: str(entry["path"]).encode("utf-8"))
    manifest = {
        "schema": SCHEMA,
        "entries": entries,
    }
    payload = (
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")

    descriptor, temporary = tempfile.mkstemp(prefix=".context-manifest.", dir=root)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.utime(stream.fileno(), ns=(0, 0))
            os.fsync(stream.fileno())
        descriptor = -1
        os.replace(temporary, root / "context-manifest.json")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

    for _, _, path in sorted(
        directories,
        key=lambda item: (item[1].count("/"), item[0]),
        reverse=True,
    ):
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.utime(descriptor, ns=(0, 0))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    root_descriptor = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fchmod(root_descriptor, 0o755)
        os.utime(root_descriptor, ns=(0, 0))
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)


try:
    canonicalize(Path(sys.argv[1]))
except ContextError as exc:
    raise SystemExit(str(exc)) from None
except (OSError, UnicodeError, ValueError):
    raise SystemExit("runtime_context_invalid") from None
PY
}

if [[ "${1:-}" == "--canonicalize-only" ]]; then
  if [[ "$#" != 2 ]]; then
    echo "usage: make-runtime-context.sh --canonicalize-only <context-directory>" >&2
    exit 2
  fi
  canonicalize_context "$2"
  exit 0
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-redroid/redroid:13.0.0_64only-latest}"
_DOCKER_LINES="$(
  python3 - <<'PY'
import json
import os

try:
    value = json.loads(os.environ["XENOID_DOCKER_ARGV_JSON"])
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str)
            or not item
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in value
        )
    ):
        raise ValueError
except (KeyError, TypeError, ValueError):
    raise SystemExit(1) from None
print("\n".join(value))
PY
)" || {
  echo "runtime_context_docker_argv_invalid" >&2
  exit 1
}
DOCKER=()
while IFS= read -r argument; do
  DOCKER+=("$argument")
done <<< "$_DOCKER_LINES"
unset _DOCKER_LINES
REQUESTED_OUT="${2:-$ROOT/dist/runtime-context}"
GOOGLE_PAYLOAD="${XENOID_GOOGLE_PAYLOAD:-}"
GOOGLE_PROVIDER="${XENOID_GOOGLE_PROVIDER:-}"
GOOGLE_RELEASE="${XENOID_GOOGLE_RELEASE:-}"
GOOGLE_SPEC_SHA256="${XENOID_GOOGLE_SPEC_SHA256:-}"
GOOGLE_DATA_COMPAT_SHA256="${XENOID_GOOGLE_DATA_COMPAT_SHA256:-}"
ARTIFACT_ROOT="${XENOID_ARTIFACT_STAGE:-}"
if [[ -z "$ARTIFACT_ROOT" || ! -d "$ARTIFACT_ROOT" || -L "$ARTIFACT_ROOT" ]]; then
  echo "artifact_snapshot_invalid: XENOID_ARTIFACT_STAGE is required" >&2
  exit 1
fi
if [[ -z "$REQUESTED_OUT" || "$REQUESTED_OUT" == "/" ]]; then
  echo "unsafe runtime context output path" >&2
  exit 2
fi
OUT_PARENT_REQUESTED="$(dirname "$REQUESTED_OUT")"
OUT_BASENAME="$(basename "$REQUESTED_OUT")"
if [[ "$OUT_BASENAME" == "." || "$OUT_BASENAME" == ".." || "$OUT_BASENAME" == "/" ]]; then
  echo "unsafe runtime context output path" >&2
  exit 2
fi
mkdir -p "$OUT_PARENT_REQUESTED"
OUT_PARENT="$(cd "$OUT_PARENT_REQUESTED" && pwd -P)"
PUBLISH_OUT="$OUT_PARENT/$OUT_BASENAME"
if [[ -L "$PUBLISH_OUT" || ( -e "$PUBLISH_OUT" && ! -d "$PUBLISH_OUT" ) ]]; then
  echo "unsafe runtime context output path" >&2
  exit 2
fi
OUT=""
_cid=""
cleanup() {
  local status=$?
  if [[ -n "$_cid" ]]; then
    "${DOCKER[@]}" rm "$_cid" >/dev/null 2>&1 || true
    _cid=""
  fi
  if [[ -n "$OUT" && "$OUT" != "$PUBLISH_OUT" ]]; then
    rm -rf -- "$OUT"
  fi
  return "$status"
}
trap cleanup EXIT
DAEMON="$ARTIFACT_ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
INPUT="$ARTIFACT_ROOT/native/xenoid-input/xenoid-input"
HIDE="$ARTIFACT_ROOT/native/xenoid-hide/xenoid-hide"
OVERLAY="$ARTIFACT_ROOT/native/xenoid-hide/xenoid-overlay"
PROFILE="$ARTIFACT_ROOT/native/xenoid-profile/xenoid-profile"
NETCTL="$ARTIFACT_ROOT/native/xenoid-netctl/xenoid-netctl"
PROP_AREA="$ARTIFACT_ROOT/native/xenoid-hide/xenoid-prop-area"
ZYGOTE="$ARTIFACT_ROOT/native/xenoid-zygote/libxenoid_zygote.so"
PIVOT="$ARTIFACT_ROOT/native/xenoid-pivot/xenoid-pivot"
SENSORSHAL="$ARTIFACT_ROOT/native/xenoid-sensorshal/xenoid-sensorshal"
CAMERA_PROVIDER="$ARTIFACT_ROOT/native/xenoid-camerahal/android.hardware.camera.provider-service-aidl"
GRALLOC="$ARTIFACT_ROOT/native/xenoid-gralloc/gralloc.redroid.so"
HWCOMPOSER="$ARTIFACT_ROOT/native/xenoid-hwcomposer/hwcomposer.raven.so"
MEDIA_PROFILES="$ARTIFACT_ROOT/native/xenoid-camerahal/media_profiles_V1_0.xml"
RIL="$ARTIFACT_ROOT/native/xenoid-ril/libxenoid-ril.so"
RADIO_CONFIG="$ARTIFACT_ROOT/native/xenoid-radio-config/android.hardware.radio.config-service.xenoid"
HARDWARE_FEATURES="$ROOT/runtime/redroid/xenoid-hardware-features.xml"
TEESIM_KEYMINT="$ARTIFACT_ROOT/native/xenoid-keymint/xenoid-keymint"
KEYMINT_VINTF="$ARTIFACT_ROOT/native/xenoid-keymint/android.hardware.security.keymint.IKeyMintDevice.xml"
SENSORS_VINTF="$ARTIFACT_ROOT/native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml"
CAMERA_VINTF="$ARTIFACT_ROOT/native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml"
RIL_VINTF="$ARTIFACT_ROOT/native/xenoid-ril/android.hardware.radio.IRadio.xml"
RADIO_CONFIG_VINTF="$ARTIFACT_ROOT/native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml"
[[ -f "$HARDWARE_FEATURES" && ! -L "$HARDWARE_FEATURES" ]] || {
  echo "missing runtime/redroid/xenoid-hardware-features.xml" >&2
  exit 1
}
python3 "$ROOT/scripts/smoke-hardware-features.py" --contract "$HARDWARE_FEATURES" >/dev/null
for artifact in \
  "$DAEMON" "$INPUT" "$HIDE" "$OVERLAY" "$PROFILE" "$NETCTL" \
  "$PROP_AREA" "$PIVOT" "$ZYGOTE" "$SENSORSHAL" "$GRALLOC" \
  "$HWCOMPOSER" "$CAMERA_PROVIDER" "$MEDIA_PROFILES" "$RIL" \
  "$RADIO_CONFIG" "$TEESIM_KEYMINT" "$KEYMINT_VINTF" \
  "$SENSORS_VINTF" "$CAMERA_VINTF" "$RIL_VINTF" \
  "$RADIO_CONFIG_VINTF"; do
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    echo "artifact_snapshot_invalid: missing staged artifact" >&2
    exit 1
  fi
done
OUT="$(mktemp -d "$OUT_PARENT/.${OUT_BASENAME}.tmp.XXXXXXXX")"
chmod 0755 "$OUT"
mkdir -p "$OUT/payload"
if [[ -n "$GOOGLE_PAYLOAD" ]]; then
  [[ -d "$GOOGLE_PAYLOAD" && ! -L "$GOOGLE_PAYLOAD" ]] || {
    echo "invalid staged Google services payload" >&2
    exit 1
  }
  mkdir -p "$OUT/payload/google-services"
  cp -pR "$GOOGLE_PAYLOAD"/. "$OUT/payload/google-services/"
fi
cp "$DAEMON" "$OUT/payload/xenoid-daemon.apk"
mkdir -p "$OUT/payload/XenoidDaemon"
cp "$DAEMON" "$OUT/payload/XenoidDaemon/XenoidDaemon.apk"
chmod 0755 "$OUT/payload/XenoidDaemon"
chmod 0644 "$OUT/payload/XenoidDaemon/XenoidDaemon.apk"
cp "$TEESIM_KEYMINT" "$OUT/payload/android.hardware.security.keymint-service"
cp "$KEYMINT_VINTF" "$OUT/payload/android.hardware.security.keymint.IKeyMintDevice.xml"
cp "$INPUT" "$OUT/payload/xenoid-input"
cp "$HIDE" "$OUT/payload/xenoid-hide-helper"
cp "$OVERLAY" "$OUT/payload/xenoid-overlay-helper"
cp "$PROFILE" "$OUT/payload/xenoid-profile-helper"
cp "$NETCTL" "$OUT/payload/xenoid-netctl"
cp "$PROP_AREA" "$OUT/payload/xenoid-prop-area"
cp "$PIVOT" "$OUT/payload/xenoid-init"
cp "$SENSORSHAL" "$OUT/payload/xenoid-sensorshal"
cp "$SENSORS_VINTF" "$OUT/payload/android.hardware.sensors.ISensors.xml"
cp "$CAMERA_PROVIDER" "$OUT/payload/android.hardware.camera.provider-service-aidl"
cp "$GRALLOC" "$OUT/payload/gralloc.redroid.so"
cp "$HWCOMPOSER" "$OUT/payload/hwcomposer.raven.so"
cp "$CAMERA_VINTF" "$OUT/payload/android.hardware.camera.provider.ICameraProvider.xml"
cp "$MEDIA_PROFILES" "$OUT/payload/media_profiles_V1_0.xml"
cp "$RIL" "$OUT/payload/libxenoid-ril.so"
cp "$RIL_VINTF" "$OUT/payload/android.hardware.radio.IRadio.xml"
cp "$RADIO_CONFIG" "$OUT/payload/android.hardware.radio.config-service.xenoid"
cp "$RADIO_CONFIG_VINTF" "$OUT/payload/android.hardware.radio.config.IRadioConfig.xml"
cp "$ROOT/runtime/redroid/xenoid-cellular-overlay/system/etc/apns-conf.xml" "$OUT/payload/apns-conf.xml"
cp "$ROOT/runtime/redroid/xenoid-cellular-overlay/system/etc/permissions/xenoid-cellular-features.xml" "$OUT/payload/xenoid-cellular-features.xml"
cp "$HARDWARE_FEATURES" "$OUT/payload/xenoid-hardware-features.xml" || {
  echo "failed to stage xenoid-hardware-features.xml" >&2
  exit 1
}
cmp -s "$HARDWARE_FEATURES" "$OUT/payload/xenoid-hardware-features.xml" || {
  echo "staged xenoid-hardware-features.xml differs from source" >&2
  exit 1
}
cp "$ROOT/runtime/redroid/xenoid-cellular-overlay/system/etc/permissions/privapp-permissions-xenoid.xml" "$OUT/payload/privapp-permissions-xenoid.xml"
cp "$ZYGOTE" "$OUT/payload/libpiex_shim.so"
# app_process64 loads the compatibility layer as an ordinary leading
# dependency. Unlike LD_PRELOAD this does not populate bionic's preload vector.
if command -v "${DOCKER[0]}" >/dev/null 2>&1; then
  _cid=$("${DOCKER[@]}" create "$IMAGE" 2>/dev/null || true)
  if [[ -n "$_cid" ]]; then "${DOCKER[@]}" cp "$_cid:/system/etc/init/hw/init.zygote64.rc" "$OUT/payload/init.zygote64.rc" >/dev/null 2>&1 || true
    # Extract the stock build.prop files so identity can be baked in at image
    # build time (init derives ro.build.fingerprint/ro.product.* at boot, before
    # prop-area can run; zygote preloads Build with those derived values).
    _stock="$OUT/.stock-props"
    mkdir -p "$_stock/system/product/etc" "$_stock/system/system_ext/etc" "$_stock/system/system_dlkm/etc" "$_stock/vendor/odm/etc" "$_stock/vendor/odm_dlkm/etc" "$_stock/vendor/vendor_dlkm/etc"
    for _f in system/build.prop system/product/etc/build.prop system/system_ext/etc/build.prop system/system_dlkm/etc/build.prop vendor/build.prop vendor/odm/etc/build.prop vendor/odm_dlkm/etc/build.prop vendor/vendor_dlkm/etc/build.prop; do
      "${DOCKER[@]}" cp "$_cid:/$_f" "$_stock/$_f" >/dev/null 2>&1 || true
    done
    # Patch libandroid_runtime: Zygote.cpp gates per-child seccomp on
    # security_getenforce() (SELinux), which is 0 in this container, leaving every
    # app with Seccomp_filters=0 (real devices have the AOSP app filter). Force
    # the stored flag to 1: CSET W9,NE -> MOVZ W9,#1 @ VA 0x1c9cfc.
    "${DOCKER[@]}" cp "$_cid:/system/lib64/libandroid_runtime.so" "$OUT/payload/libandroid_runtime.so" >/dev/null 2>&1 || true
    # ro.hardware=raven makes libhardware request raven-named graphics HALs.
    # Preserve the base image's redroid implementations under those names so
    # the canonical hardware identity is correct before graphics initialization.
    _required_extract_ok=1
    "${DOCKER[@]}" cp "$_cid:/system/bin/app_process64" "$OUT/payload/app_process64" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/bin/app_process64" "$OUT/payload/xenoid-app-process" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/lib64/libui.so" "$OUT/payload/libui.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/lib64/libselinux.so" "$OUT/payload/libselinux.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/hw/gralloc.redroid.so" "$OUT/payload/gralloc.base.redroid.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/hw/hwcomposer.redroid.so" "$OUT/payload/hwcomposer.redroid.so" >/dev/null || _required_extract_ok=0
    # This library is patched below only to report a locked, verified
    # SoftKeymaster RootOfTrust; it does not provide hardware-backed KeyMint.
    "${DOCKER[@]}" cp "$_cid:/system/framework/services.jar" "$OUT/payload/services.jar" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/framework/telephony-common.jar" "$OUT/payload/telephony-common.base.jar" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/libpuresoftkeymasterdevice.so" "$OUT/payload/libpuresoftkeymasterdevice.so" >/dev/null || _required_extract_ok=0
    if [[ "$GOOGLE_PROVIDER" == "microg" ]]; then
      # The microG product policy is pinned against this exact base image's
      # framework resources and requires the AOSP location provider library.
      "${DOCKER[@]}" cp "$_cid:/system/framework/framework-res.apk" "$OUT/.policy-framework-res.apk" >/dev/null || _required_extract_ok=0
      "${DOCKER[@]}" cp "$_cid:/system/framework/com.android.location.provider.jar" "$OUT/.policy-location-provider.probe" >/dev/null || _required_extract_ok=0
      rm -f "$OUT/.policy-location-provider.probe"
    fi
    if "${DOCKER[@]}" rm "$_cid" >/dev/null 2>&1; then
      _cid=""
    fi
    if [[ "$_required_extract_ok" != "1" ]]; then
      echo "failed to extract required Android 13 runtime payload from $IMAGE" >&2
      exit 1
    fi
    _props_args=("$ROOT/scripts/patch-runtime-props.py" "$_stock" "$OUT/payload/props")
    if [[ -n "${XENOID_EXPECT_BUILD_PRODUCT:-}" ]]; then
      _props_args+=(--expect-build-product "$XENOID_EXPECT_BUILD_PRODUCT")
    fi
    if [[ "$GOOGLE_PROVIDER" == "mindthegapps" ]]; then
      _props_args+=(--setupwizard-mode DISABLED)
    fi
    python3 "${_props_args[@]}"
    python3 "$ROOT/scripts/patch-app-process-needed.py" "$OUT/payload/app_process64"
    python3 "$ROOT/scripts/patch-runtime-libselinux.py" "$OUT/payload/libselinux.so"
    python3 "$ROOT/scripts/patch-telephony-legacy-lte-band.py"       "$OUT/payload/telephony-common.base.jar" "$OUT/payload/telephony-common.jar"
    rm -f "$OUT/payload/telephony-common.base.jar"
    _services_provider="none"
    if [[ "$GOOGLE_PROVIDER" == "microg" ]]; then
      _services_provider="microg"
    elif [[ -n "$GOOGLE_PROVIDER" && "$GOOGLE_PROVIDER" != "none" ]]; then
      echo "unsupported Google services provider for services.jar policy: $GOOGLE_PROVIDER" >&2
      exit 1
    fi
    python3 "$ROOT/scripts/patch-services-runtime.py" \
      "$OUT/payload/services.jar" "$OUT/payload/services.runtime.jar" \
      --google-provider "$_services_provider"
    mv "$OUT/payload/services.runtime.jar" "$OUT/payload/services.jar"
    if [[ "$GOOGLE_PROVIDER" == "microg" ]]; then
      # Stage the pinned canonical microG product policy into the Google
      # services payload, after the third-party APKs and before Xenoid files.
      _aapt2="${ANDROID_SDK_ROOT:-}/build-tools/35.0.0/aapt2"
      if [[ ! -x "$_aapt2" ]]; then
        _aapt2="$(command -v aapt2 || true)"
      fi
      [[ -n "$_aapt2" && -x "$_aapt2" ]] || {
        echo "aapt2 35.0.0 is required for the microG product policy" >&2
        exit 1
      }
      python3 "$ROOT/scripts/generate-microg-product-policy.py" \
        --project-root "$ROOT" \
        --framework-res "$OUT/.policy-framework-res.apk" \
        --aapt2 "$_aapt2" \
        --output-dir "$OUT/payload/google-services" \
        --manifest "$OUT/.policy-manifest.json" || {
        echo "microG product policy generation failed" >&2
        exit 1
      }
      python3 - "$OUT/.policy-manifest.json" <<'PY3'
import json
import sys

with open(sys.argv[1], "rb") as stream:
    manifest = json.load(stream)
if set(manifest) != {"schema", "inputs", "outputs"} or manifest["schema"] != "dev.xenoid.microg-product-policy/v1":
    raise SystemExit("microG product policy manifest is not canonical")
if len(manifest["outputs"]) != 4:
    raise SystemExit("microG product policy outputs are incomplete")
PY3
      rm -f "$OUT/.policy-framework-res.apk" "$OUT/.policy-manifest.json"
    fi
    python3 - \
      "$OUT/payload/gralloc.base.redroid.so" \
      "$OUT/payload/hwcomposer.redroid.so" \
      "$OUT/payload/libpuresoftkeymasterdevice.so" <<'PY3'
from pathlib import Path
import hashlib
import sys

paths = [Path(arg) for arg in sys.argv[1:]]
expected_hashes = (
    "0ae2ffa900c5d3d4381f1eaad1c61da1e9a2b0a9cead697db44f20a4e02a9f50",
    "697be23ea4d82c4b60084b50a7eacce6b71ee03c67fb5104a69bbe6f84ac675d",
    "0508e4b8921656285e3315d3aecf1ce0ae0127c3072d857310ec9abf6e61933d",
)
for path, expected in zip(paths, expected_hashes):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"SHA256 mismatch for {path}: expected {expected}, got {actual}")

keymaster = paths[2]
data = bytearray(keymaster.read_bytes())
patches = (
    # SoftAttestationContext::GetVerifiedBootParams @ 0xb5c0
    (0xb5ec, bytes.fromhex("4c008052"), bytes.fromhex("2c008052")),
    (0xb60c, bytes.fromhex("0c2000b9"), bytes.fromhex("1f2000b9")),
    (0xb610, bytes.fromhex("1f900039"), bytes.fromhex("0c900039")),
    (0xb654, bytes.fromhex("e2031f2a"), bytes.fromhex("020b8052")),
    # PureSoftKeymasterContext::GetVerifiedBootParams @ 0xe7e0 (the HAL path
    # actually used by android.hardware.keymaster@4.1-service).
    (0xe80c, bytes.fromhex("4c008052"), bytes.fromhex("2c008052")),
    (0xe82c, bytes.fromhex("0c2000b9"), bytes.fromhex("1f2000b9")),
    (0xe830, bytes.fromhex("1f900039"), bytes.fromhex("0c900039")),
    (0xe874, bytes.fromhex("e2031f2a"), bytes.fromhex("020b8052")),
)
for offset, original, replacement in patches:
    actual = bytes(data[offset:offset + len(original)])
    assert actual == original, (
        f"unexpected bytes at {offset:#x}: expected {original.hex()}, got {actual.hex()}"
    )
    data[offset:offset + len(original)] = replacement
keymaster.write_bytes(data)
print("verified graphics ABI and retained SoftKeymaster software security level")
PY3
    rm -f "$OUT/payload/gralloc.base.redroid.so"
    python3 - "$OUT/payload/libandroid_runtime.so" <<'PY2'
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = bytearray(p.read_bytes())
OFF = 0x1c9cfc
CSET_NE = bytes.fromhex('e9079f1a')  # csinc w9, wzr, wzr, eq  (CSET W9, NE)
MOVZ_1  = bytes.fromhex('29008052')  # movz  w9, #1
assert data[OFF:OFF+4] == CSET_NE, f'unexpected bytes at 0x1c9cfc: {data[OFF:OFF+4].hex()}'
data[OFF:OFF+4] = MOVZ_1
p.write_bytes(data)
print('patched libandroid_runtime: security_getenforce gate -> always-true')
PY2
    python3 - "$OUT/payload/libui.so" <<'PY4'
from pathlib import Path
import hashlib
import sys

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
expected_hash = "709b80ed6f09f91bdb29f48138dc5e8a7dcbbdc72cdf73e16697576370a30c1e"
actual_hash = hashlib.sha256(data).hexdigest()
if actual_hash != expected_hash:
    raise SystemExit(
        f"SHA256 mismatch for {path}: expected {expected_hash}, got {actual_hash}"
    )

# Gralloc2Mapper owns every nonnegative acquire fence. Descriptor 0 is reserved
# for stdin in zygote children and is also used as a legacy no-fence sentinel.
# Close only positive fence descriptors in both RGB and YCbCr lock overloads.
patches = (
    (
        0x2E2D0,
        bytes.fromhex("7400f837e003142a"),
        bytes.fromhex("800200714d000054"),
    ),
    (
        0x2E4A8,
        bytes.fromhex("9300f837e003132a"),
        bytes.fromhex("600200716d000054"),
    ),
)
for offset, original, replacement in patches:
    actual = bytes(data[offset:offset + len(original)])
    if actual != original:
        raise SystemExit(
            f"unexpected bytes at {offset:#x}: "
            f"expected {original.hex()}, got {actual.hex()}"
        )
    data[offset:offset + len(original)] = replacement
path.write_bytes(data)
print("patched libui: Gralloc2Mapper preserves reserved descriptor 0")
PY4
    rm -rf "$_stock"
  else
    echo "failed to create extraction container from $IMAGE" >&2
    exit 1
  fi
else
  echo "docker is required to extract runtime payloads from $IMAGE" >&2
  exit 1
fi
cat > "$OUT/payload/xenoid.rc" <<'RC'
on early-init
    mkdir /dev/input 0755 root root
    start xenoid-input
    start xenoid-cellular-watch

service xenoid-input /system/bin/xenoid-input serve
    class core
    user root
    group root input

# Preserve Docker's lease-owned dual-stack link before netd starts, then restore
# addresses, gateways, and control-plane rules after Android boot completes.
service xenoid-cellular-watch /system/bin/xenoid-netctl cellular-watch
    class core
    user root
    group root inet net_admin net_raw
    capabilities NET_ADMIN NET_RAW
    oneshot
    disabled

on init
    start xenoid-sensorshal
    start vendor.radio-config-xenoid

# Bind identity proc/sysfs files in init's mount namespace before zygote and
# system_server fork. Post-boot docker/rootd mounts live in a different mount
# namespace and cannot make raw-syscall readers agree with libc readers.
on post-fs-data
    exec_start xenoid-overlay

service xenoid-overlay /system/bin/xenoid-overlay-helper apply
    class core
    user root
    group root
    oneshot
    disabled

# Property-area identity runs after /dev/__properties__ is mounted and writable.
on property:sys.boot_completed=1
    start xenoid-cellular-ready
    start xenoid-props

# Every adbd start/stop/restart bumps the init.svc.adbd area serial. App
# processes inherit the zygote's expected generation (2), and out-of-band
# writes cannot update that watcher, so any drift makes every app spin in
# futex(EAGAIN). Re-run the area patcher on each adbd state change to
# re-normalize the serial instead of waiting for the next convergence.
on property:init.svc.adbd=*
    start xenoid-props

service xenoid-props /system/bin/xenoid-prop-area --identity
    class main
    user root
    group root
    oneshot
    disabled

# Virtual AIDL sensor HAL. Must register with servicemanager before system_server's
# SensorService initializes the ISensors HAL connection, so start it at init.
service xenoid-sensorshal /system/bin/xenoid-sensorshal
    class main
    user root
    group root

service vendor.radio-config-xenoid /vendor/bin/hw/android.hardware.radio.config-service.xenoid
    class hal
    user radio
    group radio system
    interface aidl android.hardware.radio.config.IRadioConfig/default

RC
cat > "$OUT/payload/android.hardware.camera.provider-service-aidl.rc" <<'RC'
on init
    start vendor.camera-provider-aidl

service vendor.camera-provider-aidl /system/bin/hw/android.hardware.camera.provider-service-aidl
    class main
    user root
    group root
RC

# The filename sorts before keystore2.rc, so within class early_hal the KeyMint
# HAL registers in servicemanager before keystore2 starts and resolves devices.
# It runs as the keystore user: the daemon's control client authenticates the
# @teesim peer by that uid.
cat > "$OUT/payload/android.hardware.security.keymint-service.rc" <<'RC'
service vendor.keymint-aidl /system/bin/hw/android.hardware.security.keymint-service
    class early_hal
    user keystore
    group keystore
    interface aidl android.hardware.security.keymint.IKeyMintDevice/default
RC

assert_no_artifact_markers() {
  local artifact="$1"
  shift
  local marker
  for marker in "$@"; do
    if LC_ALL=C strings "$artifact" | grep -Fi "$marker" >/dev/null; then
      echo "camera runtime artifact contains prohibited marker '$marker': $artifact" >&2
      exit 1
    fi
  done
}
# ICameraInjectionSession is a required member of the stable Android camera
# interface even when unsupported, so its standard descriptor is not a
# product-specific marker.
assert_no_artifact_markers "$OUT/payload/android.hardware.camera.provider-service-aidl" \
  xenoid mock replay /Users/ /home/
assert_no_artifact_markers "$OUT/payload/android.hardware.security.keymint-service" \
  xenoid mock replay /Users/ /home/
assert_no_artifact_markers "$OUT/payload/gralloc.redroid.so" \
  mock replay inject /Users/ /home/
# Gralloc consumes the one owned device-profile directory. Permit only that
# intentional product token; any extra branded string remains a build failure.
python3 - "$OUT/payload/gralloc.redroid.so" <<'PY'
import subprocess
import sys

artifact = sys.argv[1]
lines = subprocess.run(
    ["strings", artifact],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
markers = [line for line in lines if "xenoid" in line.casefold()]
expected = "/data/local/tmp/xenoid-profile"
if not markers or set(markers) != {expected}:
    raise SystemExit(
        f"gralloc runtime artifact has unexpected product markers: {markers}"
    )
PY
for artifact in \
  "$OUT/payload/android.hardware.camera.provider.ICameraProvider.xml" \
  "$OUT/payload/android.hardware.camera.provider-service-aidl.rc" \
  "$OUT/payload/android.hardware.security.keymint.IKeyMintDevice.xml" \
  "$OUT/payload/android.hardware.security.keymint-service.rc"; do
  assert_no_artifact_markers "$artifact" \
    xenoid mock replay inject /Users/ /home/
done
chmod 755 "$OUT/payload/xenoid-input" "$OUT/payload/xenoid-hide-helper" "$OUT/payload/xenoid-overlay-helper" "$OUT/payload/xenoid-profile-helper" "$OUT/payload/xenoid-netctl"
chmod 0755 "$OUT/payload/android.hardware.security.keymint-service"
# VINTF fragments must be world-readable: libvintf in unprivileged readers
# (keystore2 runs as the keystore user) fails the whole device-manifest parse on
# an unreadable fragment, and keystore2 then crashes dereferencing the result.
chmod 0644 "$OUT/payload/android.hardware.security.keymint-service.rc" \
  "$OUT/payload/android.hardware.security.keymint.IKeyMintDevice.xml" \
  "$OUT/payload/android.hardware.radio.IRadio.xml" \
  "$OUT/payload/android.hardware.radio.config.IRadioConfig.xml" \
  "$OUT/payload/android.hardware.sensors.ISensors.xml" \
  "$OUT/payload/android.hardware.camera.provider.ICameraProvider.xml"
cat > "$OUT/Dockerfile" <<DOCKER
FROM $IMAGE
__GOOGLE_LABELS__
__GOOGLE_COPY__
COPY payload/xenoid-init /xenoid-init
COPY payload/xenoid-input /data/local/tmp/xenoid-input
COPY payload/xenoid-input /system/bin/xenoid-input
COPY payload/xenoid-hide-helper /data/local/tmp/xenoid-hide-helper
COPY payload/xenoid-profile-helper /data/local/tmp/xenoid-profile-helper
COPY payload/xenoid-netctl /data/local/tmp/xenoid-netctl
# xenoid-prop-area runs at early boot from the rc, so it MUST live in the image
# (/system), NOT in /data (a named volume whose stale contents shadow the image
# across rebuilds). The post-boot adb-deployed helpers stay in /data/local/tmp.
COPY payload/xenoid-prop-area /system/bin/xenoid-prop-area
COPY payload/xenoid-overlay-helper /system/bin/xenoid-overlay-helper
COPY --chmod=755 payload/xenoid-netctl /system/bin/xenoid-netctl
COPY payload/xenoid-sensorshal /system/bin/xenoid-sensorshal
COPY --chmod=644 payload/libxenoid-ril.so /vendor/lib64/libxenoid-ril.so
COPY --chmod=755 payload/android.hardware.radio.config-service.xenoid /vendor/bin/hw/android.hardware.radio.config-service.xenoid
COPY payload/android.hardware.radio.IRadio.xml /vendor/etc/vintf/manifest/android.hardware.radio.IRadio.xml
COPY payload/android.hardware.radio.config.IRadioConfig.xml /vendor/etc/vintf/manifest/android.hardware.radio.config.IRadioConfig.xml
COPY --chmod=644 payload/apns-conf.xml /system/etc/apns-conf.xml
COPY --chmod=644 payload/xenoid-cellular-features.xml /system/etc/permissions/xenoid-cellular-features.xml
COPY --chmod=644 payload/xenoid-hardware-features.xml /system/etc/permissions/xenoid-hardware-features.xml
COPY --chmod=644 payload/privapp-permissions-xenoid.xml /system/etc/permissions/privapp-permissions-xenoid.xml
COPY payload/android.hardware.sensors.ISensors.xml /vendor/etc/vintf/manifest/android.hardware.sensors.ISensors.xml
COPY payload/android.hardware.camera.provider-service-aidl /system/bin/hw/android.hardware.camera.provider-service-aidl
COPY payload/android.hardware.camera.provider.ICameraProvider.xml /vendor/etc/vintf/manifest/android.hardware.camera.provider.ICameraProvider.xml
COPY payload/xenoid.rc /system/etc/init/xenoid.rc
COPY payload/android.hardware.camera.provider-service-aidl.rc /system/etc/init/android.hardware.camera.provider-service-aidl.rc
COPY payload/init.zygote64.rc /system/etc/init/hw/init.zygote64.rc
# Deterministic Android 13 KeyMint HAL service. keystore2 resolves the declared
# AIDL HAL over its in-process km_compat fallback; the stock HIDL Keymaster 4.1
# service remains the owning backend for the explicit SOFTWARE security level.
COPY --chmod=755 payload/android.hardware.security.keymint-service /system/bin/hw/android.hardware.security.keymint-service
COPY --chmod=644 payload/android.hardware.security.keymint-service.rc /system/etc/init/android.hardware.security.keymint-service.rc
COPY payload/android.hardware.security.keymint.IKeyMintDevice.xml /vendor/etc/vintf/manifest/android.hardware.security.keymint.IKeyMintDevice.xml
COPY payload/libandroid_runtime.so /system/lib64/libandroid_runtime.so
# Preserve descriptor 0 when legacy AHardwareBuffer clients use it as no-fence.
COPY --chmod=644 payload/libui.so /system/lib64/libui.so
# Restore standard SELinux context APIs removed by redroid's HACKED stubs.
COPY --chmod=644 payload/libselinux.so /system/lib64/libselinux.so
# ro.hardware=raven resolves these aliases during early graphics HAL loading.
# Replace the owning redroid allocator and provide the matching Raven alias.
COPY --chmod=644 payload/gralloc.redroid.so /vendor/lib64/hw/gralloc.redroid.so
COPY --chmod=644 payload/gralloc.redroid.so /vendor/lib64/hw/gralloc.raven.so
COPY --chmod=644 payload/hwcomposer.raven.so /vendor/lib64/hw/hwcomposer.raven.so
COPY --chmod=644 payload/media_profiles_V1_0.xml /vendor/etc/media_profiles_V1_0.xml
# RootOfTrust-only SoftKeymaster patch; this is not hardware-backed KeyMint.
COPY --chmod=644 payload/libpuresoftkeymasterdevice.so /vendor/lib64/libpuresoftkeymasterdevice.so
# Preserve the owning package for isolated UIDs in PackageManager queries.
COPY --chmod=644 payload/services.jar /system/framework/services.jar
# Legacy HIDL LTE identities derive bands from EARFCN and use profile bandwidth.
COPY --chmod=644 payload/telephony-common.jar /system/framework/telephony-common.jar
COPY --chmod=755 payload/app_process64 /system/bin/app_process64
COPY --chmod=755 payload/xenoid-app-process /system/bin/xenoid-app-process
COPY --chmod=644 payload/libpiex_shim.so /system/lib64/libpiex_shim.so
COPY payload/props/system_build.prop /system/build.prop
COPY payload/props/vendor_build.prop /vendor/build.prop
COPY payload/props/product_build.prop /system/product/etc/build.prop
COPY payload/props/system_ext_build.prop /system/system_ext/etc/build.prop
COPY payload/props/system_dlkm_build.prop /system/system_dlkm/etc/build.prop
COPY payload/props/odm_build.prop /vendor/odm/etc/build.prop
COPY payload/props/vendor_dlkm_build.prop /vendor/vendor_dlkm/etc/build.prop
COPY payload/props/odm_dlkm_build.prop /vendor/odm_dlkm/etc/build.prop
COPY payload/XenoidDaemon /system/priv-app/XenoidDaemon
COPY payload/xenoid-daemon.apk /data/local/tmp/xenoid-daemon.apk
DOCKER
python3 - "$OUT/Dockerfile" "$GOOGLE_PROVIDER" "$GOOGLE_RELEASE" "$GOOGLE_SPEC_SHA256" "$GOOGLE_DATA_COMPAT_SHA256" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
provider, release, spec_sha256, data_compat_sha256 = sys.argv[2:6]
values = (provider, release, spec_sha256, data_compat_sha256)
google_enabled = any(values)
valid_pair = (
    provider == "microg" and release.startswith("microg-0.3.15.250932-")
) or (
    provider == "mindthegapps" and release.startswith("MindTheGapps-13.0.0-arm64-")
)
if google_enabled and (
    not valid_pair
    or any(len(value) == 0 for value in values)
    or len(spec_sha256) != 64
    or len(data_compat_sha256) != 64
):
    raise SystemExit("invalid Google services runtime context identity")
google_labels = ""
google_copy = ""
if google_enabled:
    google_labels = "\n".join(
        (
            f'LABEL dev.xenoid.google_provider="{provider}"',
            f'LABEL dev.xenoid.google_release="{release}"',
            f'LABEL dev.xenoid.google_spec_sha256="{spec_sha256}"',
            f'LABEL dev.xenoid.google_data_compat_sha256="{data_compat_sha256}"',
        )
    )
    google_copy = "COPY --chown=0:0 payload/google-services/ /"
text = path.read_text()
text = text.replace("__GOOGLE_LABELS__", google_labels)
text = text.replace("__GOOGLE_COPY__", google_copy)
path.write_text(text)
PY
cat >> "$OUT/Dockerfile" <<'DOCKER'
# Xenoid payloads are activated by the host CLI after Android boot:
#   adb install -r /data/local/tmp/xenoid-daemon.apk
#   adb shell am start --user 0 -n dev.xenoid.daemon/.MainActivity --ez bootstrap true
#   daemon applies device and runtime policies through the token-gated root channel.
# Pivot into real ext4 rootfs+data loop images before Android init so the mount
# table looks like a physical device (no container overlayfs/binds anywhere).
ENTRYPOINT ["/xenoid-init","/data/xenoid-rootfs.img","/data/xenoid-data.img","/init","qemu=1","androidboot.hardware=raven","androidboot.hardware.sku=G8V0U","androidboot.mode=normal","androidboot.bootreason=reboot,normal","androidboot.verifiedbootstate=green","androidboot.flash.locked=1","androidboot.vbmeta.device_state=locked","androidboot.veritymode=enforcing","androidboot.use_redroid_c2=1"]
DOCKER
canonicalize_context "$OUT"
python3 - "$OUT" "$PUBLISH_OUT" <<'PY'
from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])


def exchange(left: Path, right: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    left_bytes = os.fsencode(left)
    right_bytes = os.fsencode(right)
    if sys.platform == "darwin":
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(left_bytes, right_bytes, 0x00000002)
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise OSError(errno.ENOTSUP, "atomic directory exchange unavailable") from exc
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(-100, left_bytes, -100, right_bytes, 0x00000002)
    else:
        raise OSError(errno.ENOTSUP, "atomic directory exchange unavailable")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


try:
    source_info = source.lstat()
    parent_info = destination.parent.lstat()
    if (
        stat.S_ISLNK(source_info.st_mode)
        or not stat.S_ISDIR(source_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
    ):
        raise OSError(errno.EINVAL, "unsafe runtime context publication")
    try:
        destination_info = destination.lstat()
    except FileNotFoundError:
        os.rename(source, destination)
    else:
        if stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(destination_info.st_mode):
            raise OSError(errno.EINVAL, "unsafe runtime context destination")
        exchange(source, destination)
        shutil.rmtree(source)
    parent_descriptor = os.open(
        destination.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
except OSError:
    raise SystemExit("runtime_context_publish_failed") from None
PY
OUT="$PUBLISH_OUT"
printf '%s\n' "$OUT"
