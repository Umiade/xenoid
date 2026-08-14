#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-redroid/redroid:13.0.0_64only-latest}"
DOCKER=(docker)
if [[ -n "${XENOID_DOCKER_CONTEXT:-}" ]]; then
  DOCKER+=(--context "$XENOID_DOCKER_CONTEXT")
fi
OUT="${2:-$ROOT/dist/runtime-context}"
GOOGLE_PAYLOAD="${XENOID_GOOGLE_PAYLOAD:-}"
GOOGLE_PROVIDER="${XENOID_GOOGLE_PROVIDER:-}"
GOOGLE_RELEASE="${XENOID_GOOGLE_RELEASE:-}"
GOOGLE_SPEC_SHA256="${XENOID_GOOGLE_SPEC_SHA256:-}"
GOOGLE_DATA_COMPAT_SHA256="${XENOID_GOOGLE_DATA_COMPAT_SHA256:-}"
if [[ -z "$OUT" || "$OUT" == "/" ]]; then
  echo "unsafe runtime context output path" >&2
  exit 2
fi
DAEMON="$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
INPUT="$ROOT/native/xenoid-input/xenoid-input"
HIDE="$ROOT/native/xenoid-hide/xenoid-hide"
OVERLAY="$ROOT/native/xenoid-hide/xenoid-overlay"
PROFILE="$ROOT/native/xenoid-profile/xenoid-profile"
NETCTL="$ROOT/native/xenoid-netctl/xenoid-netctl"
PROP_AREA="$ROOT/native/xenoid-hide/xenoid-prop-area"
ZYGOTE="$ROOT/native/xenoid-zygote/libxenoid_zygote.so"
PIVOT="$ROOT/native/xenoid-pivot/xenoid-pivot"
SENSORSHAL="$ROOT/native/xenoid-sensorshal/xenoid-sensorshal"
CAMERA_PROVIDER="$ROOT/native/xenoid-camerahal/android.hardware.camera.provider-service-aidl"
GRALLOC="$ROOT/native/xenoid-gralloc/gralloc.redroid.so"
HWCOMPOSER="$ROOT/native/xenoid-hwcomposer/hwcomposer.raven.so"
MEDIA_PROFILES="$ROOT/native/xenoid-camerahal/media_profiles_V1_0.xml"
RIL="$ROOT/native/xenoid-ril/libxenoid-ril.so"
RADIO_CONFIG="$ROOT/native/xenoid-radio-config/android.hardware.radio.config-service.xenoid"
HARDWARE_FEATURES="$ROOT/runtime/redroid/xenoid-hardware-features.xml"
[[ -f "$HARDWARE_FEATURES" && ! -L "$HARDWARE_FEATURES" ]] || {
  echo "missing runtime/redroid/xenoid-hardware-features.xml" >&2
  exit 1
}
python3 "$ROOT/scripts/smoke-hardware-features.py" --contract "$HARDWARE_FEATURES" >/dev/null
[[ -f "$DAEMON" ]] || "$ROOT/scripts/build-daemon.sh" >/dev/null
[[ -f "$INPUT" ]] || "$ROOT/scripts/build-native-input.sh" >/dev/null
[[ -f "$HIDE" ]] || "$ROOT/scripts/build-native-hide.sh" >/dev/null
[[ -f "$OVERLAY" ]] || "$ROOT/scripts/build-native-overlay.sh" >/dev/null
[[ -f "$PROFILE" ]] || "$ROOT/scripts/build-native-profile.sh" >/dev/null
[[ -f "$NETCTL" ]] || "$ROOT/scripts/build-native-netctl.sh" >/dev/null
[[ -f "$PROP_AREA" ]] || "$ROOT/scripts/build-native-for-arch.sh" xenoid-prop-area "$ROOT/native/xenoid-hide/xenoid_prop_area.c" "$PROP_AREA" arm64 >/dev/null
[[ -f "$PIVOT" ]] || "$ROOT/scripts/build-native-for-arch.sh" xenoid-pivot "$ROOT/native/xenoid-pivot/xenoid_pivot.c" "$PIVOT" arm64 static >/dev/null
[[ -f "$ZYGOTE" ]] || "$ROOT/scripts/build-native-zygote.sh" arm64 >/dev/null
[[ -f "$SENSORSHAL" ]] || "$ROOT/scripts/build-sensors-hal.sh" arm64 >/dev/null
[[ -f "$GRALLOC" ]] || "$ROOT/scripts/build-gralloc.sh" arm64 >/dev/null
[[ -f "$HWCOMPOSER" ]] || "$ROOT/scripts/build-hwcomposer.sh" arm64 >/dev/null
[[ -f "$CAMERA_PROVIDER" ]] || "$ROOT/scripts/build-camera-hal.sh" arm64 >/dev/null
[[ -f "$RIL" ]] || "$ROOT/scripts/build-ril.sh" arm64 >/dev/null
[[ -f "$RADIO_CONFIG" ]] || "$ROOT/scripts/build-radio-config.sh" arm64 >/dev/null
rm -rf "$OUT"
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
cp "$INPUT" "$OUT/payload/xenoid-input"
cp "$HIDE" "$OUT/payload/xenoid-hide-helper"
cp "$OVERLAY" "$OUT/payload/xenoid-overlay-helper"
cp "$PROFILE" "$OUT/payload/xenoid-profile-helper"
cp "$NETCTL" "$OUT/payload/xenoid-netctl"
cp "$PROP_AREA" "$OUT/payload/xenoid-prop-area"
cp "$PIVOT" "$OUT/payload/xenoid-init"
cp "$SENSORSHAL" "$OUT/payload/xenoid-sensorshal"
cp "$ROOT/native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml" "$OUT/payload/android.hardware.sensors.ISensors.xml" || { echo "missing native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml (required by Dockerfile VINTF COPY)" >&2; exit 1; }
cp "$CAMERA_PROVIDER" "$OUT/payload/android.hardware.camera.provider-service-aidl"
cp "$GRALLOC" "$OUT/payload/gralloc.redroid.so"
cp "$HWCOMPOSER" "$OUT/payload/hwcomposer.raven.so"
cp "$ROOT/native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml" "$OUT/payload/android.hardware.camera.provider.ICameraProvider.xml" || { echo "missing native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml (required by Dockerfile VINTF COPY)" >&2; exit 1; }
cp "$MEDIA_PROFILES" "$OUT/payload/media_profiles_V1_0.xml" || { echo "missing native/xenoid-camerahal/media_profiles_V1_0.xml (required by Dockerfile camera profile COPY)" >&2; exit 1; }
cp "$RIL" "$OUT/payload/libxenoid-ril.so"
cp "$ROOT/native/xenoid-ril/android.hardware.radio.IRadio.xml" "$OUT/payload/android.hardware.radio.IRadio.xml"
cp "$RADIO_CONFIG" "$OUT/payload/android.hardware.radio.config-service.xenoid"
cp "$ROOT/native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml" "$OUT/payload/android.hardware.radio.config.IRadioConfig.xml"
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
if command -v docker >/dev/null 2>&1; then
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
    "${DOCKER[@]}" cp "$_cid:/system/lib64/libui.so" "$OUT/payload/libui.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/lib64/libselinux.so" "$OUT/payload/libselinux.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/hw/gralloc.redroid.so" "$OUT/payload/gralloc.base.redroid.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/hw/hwcomposer.redroid.so" "$OUT/payload/hwcomposer.redroid.so" >/dev/null || _required_extract_ok=0
    # This library is patched below only to report a locked, verified
    # SoftKeymaster RootOfTrust; it does not provide hardware-backed KeyMint.
    "${DOCKER[@]}" cp "$_cid:/system/framework/services.jar" "$OUT/payload/services.jar" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/system/framework/telephony-common.jar" "$OUT/payload/telephony-common.base.jar" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" cp "$_cid:/vendor/lib64/libpuresoftkeymasterdevice.so" "$OUT/payload/libpuresoftkeymasterdevice.so" >/dev/null || _required_extract_ok=0
    "${DOCKER[@]}" rm "$_cid" >/dev/null 2>&1 || true
    if [[ "$_required_extract_ok" != "1" ]]; then
      echo "failed to extract required runtime library, framework jar, graphics HAL, or SoftKeymaster payload from $IMAGE" >&2
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
    python3 "$ROOT/scripts/patch-services-runtime.py" \
      "$OUT/payload/services.jar" "$OUT/payload/services.runtime.jar"
    mv "$OUT/payload/services.runtime.jar" "$OUT/payload/services.jar"
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
  unset _cid
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
  "$OUT/payload/android.hardware.camera.provider-service-aidl.rc"; do
  assert_no_artifact_markers "$artifact" \
    xenoid mock replay inject /Users/ /home/
done
chmod 755 "$OUT/payload/xenoid-input" "$OUT/payload/xenoid-hide-helper" "$OUT/payload/xenoid-overlay-helper" "$OUT/payload/xenoid-profile-helper" "$OUT/payload/xenoid-netctl"
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
if google_enabled and (
    provider != "mindthegapps"
    or not release.startswith("MindTheGapps-13.0.0-arm64-")
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
cat > "$OUT/build.sh" <<'BUILD'
#!/usr/bin/env bash
set -euo pipefail
TAG="${1:-xenoid/redroid:local}"
docker build -t "$TAG" .
echo "$TAG"
BUILD
chmod +x "$OUT/build.sh"
printf '%s\n' "$OUT"
