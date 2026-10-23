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
source "$ROOT/scripts/hal-build-lib.sh"
# Unversioned AIDL packages: no extra per-package arguments.
sensors_aidl_package() { :; }
# Regenerate all stable AIDL stubs on every build. Keeping generated sources
# across AIDL schema changes silently changes the Binder wire format.
{
  find "$HAL/aidl/android/hardware/sensors" -maxdepth 1 -name '*.aidl' -print0 | LC_ALL=C sort -z
  printf '%s\0' "$HAL/aidl/android/hardware/common/NativeHandle.aidl"
  find "$HAL/aidl/android/hardware/common/fmq" -maxdepth 1 -name '*.aidl' -print0 | LC_ALL=C sort -z
} | xenoid_aidl_generate "$AIDL_BIN" "$GEN" sensors_aidl_package \
      --lang=ndk --structured --stability=vintf -I"$HAL/aidl"
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"

# Service-side binder API (AServiceManager_addService, ABinderProcess_*) is not in the
# NDK's libbinder_ndk stub; link the pinned on-device libbinder_ndk.so (cached
# outside the source tree).
LIBBINDER="$("$ROOT/scripts/platform-libs.sh" libbinder_ndk.so)"
[[ -f "$LIBBINDER" ]] || { echo "failed to resolve libbinder_ndk.so" >&2; exit 1; }

SRCS=( "$HAL/xenoid_sensors_hal.cpp" "$HAL/sensor_catalog.cpp" )
while IFS= read -r c; do SRCS+=( "$c" ); done < <(find "$GEN" -name '*.cpp' | LC_ALL=C sort)
CXXFLAGS=(
  -std=c++17 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
  "-ffile-prefix-map=$HAL=android/hardware/sensors/default"
  "-fmacro-prefix-map=$HAL=android/hardware/sensors/default"
  "-ffile-prefix-map=$SDK=android-sdk"
  "-fmacro-prefix-map=$SDK=android-sdk"
  --sysroot="$SYSROOT" -I"$GEN" -I"$GEN/aidl" -I"$SYSROOT/usr/include"
)
LDFLAGS=( -L"$SYSROOT/usr/lib/$TRIPLE/29" "$LIBBINDER" -llog -landroid -static-libstdc++ -Wl,-s )
xenoid_compile_link "$CXX" "$HAL/xenoid-sensorshal" "${XENOID_BUILD_JOBS:-1}"
echo "$HAL/xenoid-sensorshal"
