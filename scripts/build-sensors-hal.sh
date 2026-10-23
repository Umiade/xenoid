#!/usr/bin/env bash
# Build the virtual AIDL sensor HAL (xenoid-sensorshal) for arm64.
# Generates the NDK AIDL stubs from the vendored .aidl tree, compiles them with
# the service, and links libbinder_ndk. Output: native/xenoid-sensorshal/xenoid-sensorshal
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAL="$ROOT/native/xenoid-sensorshal"
ARCH="${1:-arm64}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
AIDL_BIN="$SDK/build-tools/35.0.0/aidl"
[[ -x "$AIDL_BIN" ]] || AIDL_BIN="$(ls -d "$SDK"/build-tools/*/aidl 2>/dev/null | sort -V | tail -1)"
if [[ "$ARCH" == x86_64 ]]; then
  TOOL=x86_64-linux-android29-clang++
  TRIPLE=x86_64-linux-android
else
  TOOL=aarch64-linux-android29-clang++
  TRIPLE=aarch64-linux-android
fi
# android/binder_enums.h is absent from NDK 28 and newer. The pinned NDK
# still ships it; an explicit ANDROID_NDK_HOME override must do the same.
NDK="$(xenoid_ndk_require "$SDK")" || exit 1
PRE="$(xenoid_ndk_prebuilt "$NDK")" \
  || { printf 'no compatible Android NDK prebuilt under %s\n' "$NDK" >&2; exit 1; }
if [[ ! -f "$PRE/sysroot/usr/include/android/binder_enums.h" ]]; then
  printf 'Android NDK %s does not provide android/binder_enums.h required by the sensors HAL AIDL build; use NDK %s\n' \
    "$NDK" "$(xenoid_ndk_version)" >&2
  exit 1
fi
[[ -x "$PRE/bin/$TOOL" ]] || { printf '%s not found in %s\n' "$TOOL" "$NDK" >&2; exit 1; }
CXX="$PRE/bin/$TOOL"
SYSROOT="$PRE/sysroot"

GEN="$HAL/gen"
rm -rf "$GEN"
mkdir -p "$GEN"
# Regenerate all stable AIDL stubs on every build. Keeping generated sources
# across AIDL schema changes silently changes the Binder wire format.
for f in "$HAL"/aidl/android/hardware/sensors/*.aidl \
         "$HAL"/aidl/android/hardware/common/NativeHandle.aidl \
         "$HAL"/aidl/android/hardware/common/fmq/*.aidl; do
  [[ -f "$f" ]] || continue
  "$AIDL_BIN" --lang=ndk --structured --stability=vintf \
    -o"$GEN" -h"$GEN" -I"$HAL/aidl" "$f"
done
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"


INC=( -I"$GEN" -I"$GEN/aidl" -I"$SYSROOT/usr/include" )
# Service-side binder API (AServiceManager_addService, ABinderProcess_*) is not in the
# NDK's libbinder_ndk stub; link the on-device libbinder_ndk.so (versioned symbols).
if [[ ! -f "$HAL/libbinder_ndk.so" ]]; then
  _container_name="$(PYTHONPATH="$ROOT/src" python3 -c 'import os; from pathlib import Path; from xenoid.config import resolve_instance; c,g,l=resolve_instance(project_root=Path.cwd(), env={}); print(l.container_name)' 2>/dev/null || echo xenoid-android)"
  docker cp "${_container_name}:/system/lib64/libbinder_ndk.so" "$HAL/libbinder_ndk.so" >/dev/null 2>&1 \
    || docker cp "${_container_name}:/apex/com.android.runtime/lib64/bionic/libbinder_ndk.so" "$HAL/libbinder_ndk.so" >/dev/null 2>&1 \
    || {
      _image="${XENOID_BASE_IMAGE:-redroid/redroid:13.0.0_64only-latest}"
      _cid="$(docker create "$_image")"
      trap 'docker rm -f "$_cid" >/dev/null 2>&1 || true' EXIT
      docker cp "$_cid:/system/lib64/libbinder_ndk.so" "$HAL/libbinder_ndk.so" >/dev/null 2>&1 \
        || docker cp "$_cid:/apex/com.android.runtime/lib64/bionic/libbinder_ndk.so" "$HAL/libbinder_ndk.so"
      docker rm "$_cid" >/dev/null
      trap - EXIT
    }
fi
SRCS=( "$HAL/xenoid_sensors_hal.cpp" "$HAL/sensor_catalog.cpp" )
while IFS= read -r c; do SRCS+=( "$c" ); done < <(find "$GEN" -name '*.cpp')

"$CXX" -std=c++17 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  "-ffile-prefix-map=$HAL=android/hardware/sensors/default" \
  "-fmacro-prefix-map=$HAL=android/hardware/sensors/default" \
  "-ffile-prefix-map=$SDK=android-sdk" \
  "-fmacro-prefix-map=$SDK=android-sdk" \
  --sysroot="$SYSROOT" "${INC[@]}" \
  -o "$HAL/xenoid-sensorshal" "${SRCS[@]}" \
  -L"$SYSROOT/usr/lib/$TRIPLE/29" "$HAL/libbinder_ndk.so" -llog -landroid -static-libstdc++ -Wl,-s
echo "$HAL/xenoid-sensorshal"
