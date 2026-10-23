#!/usr/bin/env bash
# Build the Android 13 HWC1 Raven dynamic-mode wrapper without an AOSP checkout.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAL="$ROOT/native/xenoid-hwcomposer"
ARCH="${1:-arm64}"
API=29

case "$ARCH" in
  arm64)
    TOOL="aarch64-linux-android${API}-clang"
    TRIPLE="aarch64-linux-android"
    ;;
  x86_64)
    TOOL="x86_64-linux-android${API}-clang"
    TRIPLE="x86_64-linux-android"
    ;;
  *)
    printf 'unsupported architecture %q (expected arm64 or x86_64)\n' "$ARCH" >&2
    exit 2
    ;;
esac

source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
NDK="$(xenoid_ndk_require "$SDK")" || exit 1
PREBUILT="$(xenoid_ndk_prebuilt "$NDK")" \
  || { printf 'no compatible Android NDK prebuilt under %s\n' "$NDK" >&2; exit 1; }
if [[ ! -x "$PREBUILT/bin/$TOOL" || ! -x "$PREBUILT/bin/llvm-strip" ]]; then
  printf 'Android NDK %s does not provide %s and llvm-strip\n' "$NDK" "$TOOL" >&2
  exit 1
fi

CC="$PREBUILT/bin/$TOOL"
STRIP="$PREBUILT/bin/llvm-strip"
SYSROOT="$PREBUILT/sysroot"
LIBDIR="$SYSROOT/usr/lib/$TRIPLE/$API"
[[ -d "$LIBDIR" ]] || {
  printf 'Android NDK sysroot library directory is missing: %s\n' "$LIBDIR" >&2
  exit 1
}

OUTPUT="$HAL/hwcomposer.raven.so"
TEMP="$OUTPUT.tmp.$$"
trap 'rm -f "$TEMP"' EXIT

"$CC" \
  -std=gnu11 \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  -fPIC \
  -fvisibility=hidden \
  -ffunction-sections \
  -fdata-sections \
  -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 \
  --sysroot="$SYSROOT" \
  -I"$ROOT/native/xenoid-gralloc" \
  -shared \
  -Wl,-soname,hwcomposer.raven.so \
  -Wl,--gc-sections \
  -Wl,--exclude-libs,ALL \
  -Wl,-z,defs \
  -Wl,-z,relro \
  -Wl,-z,now \
  -L"$LIBDIR" \
  "$HAL/hwcomposer_wrapper.c" \
  -ldl \
  -o "$TEMP"

"$STRIP" --strip-unneeded "$TEMP"
mv -f "$TEMP" "$OUTPUT"
trap - EXIT
printf '%s\n' "$OUTPUT"
