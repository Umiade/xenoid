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
PRE=""
for candidate in "$SDK"/ndk/* "${ANDROID_NDK_HOME:-}"; do
  [[ -d "$candidate" ]] || continue
  for prebuilt in "$candidate"/toolchains/llvm/prebuilt/*; do
    if [[ -f "$prebuilt/sysroot/usr/include/android/binder_enums.h" && -x "$prebuilt/bin/$TOOL" ]]; then PRE="$prebuilt"; fi
  done
done
[[ -n "$PRE" ]] || { echo "compatible Android NDK not found" >&2; exit 127; }
CXX="$PRE/bin/$TOOL"
SYSROOT="$PRE/sysroot"
GEN="$HAL/gen"
rm -rf "$GEN"
mkdir -p "$GEN"
while IFS= read -r aidl; do
  case "$aidl" in
    */android/hardware/radio/config/*) hash=dd9c3f8e21930f9b4c46a4125bd5f5cec90318ec ;;
    */android/hardware/radio/*) hash=31b668688e937e8e1eff48fea7b4bb37681114a0 ;;
    *) echo "unknown RadioConfig AIDL package: $aidl" >&2; exit 1 ;;
  esac
  "$AIDL_BIN" --lang=ndk --structured --stability=vintf --min_sdk_version=30 \
    --version 1 --hash "$hash" -o"$GEN" -h"$GEN" \
    -p"$HAL/framework-min.aidl" -I"$HAL/aidl" "$aidl"
done < <(find "$HAL/aidl" -name '*.aidl' | sort)
python3 "$ROOT/scripts/sanitize-aidl-output.py" "$GEN"
if [[ ! -f "$HAL/libbinder_ndk.so" ]]; then
  cid="$(docker create "${XENOID_BASE_IMAGE:-redroid/redroid:13.0.0_64only-latest}")"
  docker cp "$cid:/system/lib64/libbinder_ndk.so" "$HAL/libbinder_ndk.so"
  docker rm "$cid" >/dev/null
fi
SRCS=("$HAL/radio_config.cpp")
while IFS= read -r source; do SRCS+=("$source"); done < <(find "$GEN" -name '*.cpp' | sort)
OUT="$HAL/$SERVICE"
"$CXX" -std=c++17 -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -fvisibility=hidden -fvisibility-inlines-hidden -fno-rtti \
  "-ffile-prefix-map=$HAL=android/hardware/radio/config/default" \
  "-fmacro-prefix-map=$HAL=android/hardware/radio/config/default" \
  "-ffile-prefix-map=$SDK=android-sdk" \
  "-fmacro-prefix-map=$SDK=android-sdk" \
  -ffunction-sections -fdata-sections --sysroot="$SYSROOT" -I"$GEN" -I"$SYSROOT/usr/include" \
  -o "$OUT" "${SRCS[@]}" -L"$SYSROOT/usr/lib/$TRIPLE/30" \
  "$HAL/libbinder_ndk.so" -llog -static-libstdc++ \
  -Wl,-z,defs,--gc-sections,--exclude-libs,ALL,-s,-z,relro,-z,now
printf '%s\n' "$OUT"
