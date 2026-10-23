#!/usr/bin/env bash
#
# Copyright 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build the Android 13 legacy gralloc HAL without a full AOSP checkout.
# Output: native/xenoid-gralloc/gralloc.redroid.so

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAL="$ROOT/native/xenoid-gralloc"
ARCH="${1:-arm64}"
API=29

case "$ARCH" in
  arm64)
    TOOL="aarch64-linux-android${API}-clang++"
    TRIPLE="aarch64-linux-android"
    ;;
  x86_64)
    TOOL="x86_64-linux-android${API}-clang++"
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
if [[ ! -x "$PREBUILT/bin/$TOOL" || ! -x "$PREBUILT/bin/llvm-strip" \
      || ! -f "$PREBUILT/sysroot/usr/include/android/sharedmem.h" \
      || ! -f "$PREBUILT/sysroot/usr/include/android/log.h" ]]; then
  printf 'Android NDK %s does not provide %s plus android/sharedmem.h and android/log.h\n' \
    "$NDK" "$TOOL" >&2
  exit 1
fi

CXX="$PREBUILT/bin/$TOOL"
STRIP="$PREBUILT/bin/llvm-strip"
SYSROOT="$PREBUILT/sysroot"
LIBDIR="$SYSROOT/usr/lib/$TRIPLE/$API"
if [[ ! -d "$LIBDIR" ]]; then
  printf 'Android NDK sysroot library directory is missing: %s\n' "$LIBDIR" >&2
  exit 1
fi

# libcutils is not part of the NDK; link the pinned on-device library (cached
# outside the source tree, verified by SHA-256).
LIBCUTILS="$("$ROOT/scripts/platform-libs.sh" libcutils.so)"
[[ -f "$LIBCUTILS" ]] || { printf 'missing Android libcutils link library\n' >&2; exit 1; }


OUTPUT="$HAL/gralloc.redroid.so"
TEMP="$OUTPUT.tmp.$$"
trap 'rm -f "$TEMP"' EXIT

"$CXX" \
  -std=gnu++17 \
  -O2 \
  -fPIC \
  -fvisibility=hidden \
  -ffunction-sections \
  -fdata-sections \
  -fno-exceptions \
  -fno-rtti \
  -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 \
  --sysroot="$SYSROOT" \
  -I"$HAL" \
  -shared \
  -Wl,-soname,gralloc.redroid.so \
  -Wl,--gc-sections \
  -Wl,--exclude-libs,ALL \
  -Wl,-z,defs \
  -Wl,-z,relro \
  -Wl,-z,now \
  -L"$LIBDIR" \
  "$HAL/gralloc.cpp" \
  "$HAL/mapper.cpp" \
  "$HAL/framebuffer.cpp" \
  -llog \
  "$LIBCUTILS" \
  -static-libstdc++ \
  -o "$TEMP"

"$STRIP" --strip-unneeded "$TEMP"
mv -f "$TEMP" "$OUTPUT"
trap - EXIT
printf '%s\n' "$OUTPUT"
