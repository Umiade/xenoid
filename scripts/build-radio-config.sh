#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAL="$ROOT/native/xenoid-radio-config"
SERVICE="android.hardware.radio.config-service.xenoid"
ARCH="${1:-arm64}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
AIDL_BIN="$SDK/build-tools/35.0.0/aidl"
[[ -x "$AIDL_BIN" ]] || { echo "Android build-tools 35 aidl not found" >&2; exit 127; }
if [[ "$ARCH" == "x86_64" ]]; then
  TOOL=x86_64-linux-android30-clang++
  TRIPLE=x86_64-linux-android
else
  TOOL=aarch64-linux-android30-clang++
  TRIPLE=aarch64-linux-android
fi
NDK="$(xenoid_ndk_require "$SDK")" || exit 127
PRE="$(xenoid_ndk_prebuilt "$NDK")" \
  || { printf 'no compatible Android NDK prebuilt under %s\n' "$NDK" >&2; exit 127; }
if [[ ! -f "$PRE/sysroot/usr/include/android/binder_enums.h" ]]; then
  printf 'Android NDK %s does not provide android/binder_enums.h required by the RadioConfig AIDL build; use NDK %s\n' \
    "$NDK" "$(xenoid_ndk_version)" >&2
  exit 127
fi
[[ -x "$PRE/bin/$TOOL" ]] || { printf '%s not found in %s\n' "$TOOL" "$NDK" >&2; exit 127; }
CXX="$PRE/bin/$TOOL"
SYSROOT="$PRE/sysroot"
GEN="$HAL/gen"
rm -rf "$GEN"
mkdir -p "$GEN"
source "$ROOT/scripts/hal-build-lib.sh"
radio_aidl_package() {
  case "$1" in
    */android/hardware/radio/config/*) echo "--hash dd9c3f8e21930f9b4c46a4125bd5f5cec90318ec" ;;
    */android/hardware/radio/*) echo "--hash 31b668688e937e8e1eff48fea7b4bb37681114a0" ;;
    *) echo "unknown RadioConfig AIDL package: $1" >&2; return 1 ;;
  esac
}
find "$HAL/aidl" -name '*.aidl' -print0 | LC_ALL=C sort -z \
  | xenoid_aidl_generate "$AIDL_BIN" "$GEN" radio_aidl_package \
      --lang=ndk --structured --stability=vintf --min_sdk_version=30 --version 1 \
      -p"$HAL/framework-min.aidl" -I"$HAL/aidl"
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"
LIBBINDER="$("$ROOT/scripts/platform-libs.sh" libbinder_ndk.so)"
[[ -f "$LIBBINDER" ]] || { echo "failed to resolve libbinder_ndk.so" >&2; exit 1; }
SRCS=("$HAL/radio_config.cpp")
while IFS= read -r source; do SRCS+=("$source"); done < <(find "$GEN" -name '*.cpp' | LC_ALL=C sort)
OUT="$HAL/$SERVICE"
CXXFLAGS=(
  -std=c++17 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
  -fvisibility=hidden -fvisibility-inlines-hidden -fno-rtti
  "-ffile-prefix-map=$HAL=android/hardware/radio/config/default"
  "-fmacro-prefix-map=$HAL=android/hardware/radio/config/default"
  "-ffile-prefix-map=$SDK=android-sdk"
  "-fmacro-prefix-map=$SDK=android-sdk"
  -ffunction-sections -fdata-sections --sysroot="$SYSROOT" -I"$GEN" -I"$SYSROOT/usr/include"
)
LDFLAGS=(
  -L"$SYSROOT/usr/lib/$TRIPLE/30" "$LIBBINDER" -llog -static-libstdc++
  -Wl,-z,defs,--gc-sections,--exclude-libs,ALL,-s,-z,relro,-z,now
)
xenoid_compile_link "$CXX" "$OUT" "${XENOID_BUILD_JOBS:-1}"
printf '%s\n' "$OUT"
