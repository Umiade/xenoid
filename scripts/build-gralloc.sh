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
PREBUILT=""

select_prebuilt() {
  local ndk="$1"
  local candidate
  [[ -d "$ndk" ]] || return 1
  for candidate in "$ndk"/toolchains/llvm/prebuilt/*; do
    [[ -x "$candidate/bin/$TOOL" ]] || continue
    [[ -x "$candidate/bin/llvm-strip" ]] || continue
    [[ -f "$candidate/sysroot/usr/include/android/sharedmem.h" ]] || continue
    [[ -f "$candidate/sysroot/usr/include/android/log.h" ]] || continue
    PREBUILT="$candidate"
    return 0
  done
  return 1
}

if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
  select_prebuilt "$ANDROID_NDK_HOME" || true
fi
if [[ -z "$PREBUILT" && -d "$SDK/ndk" ]]; then
  for ndk in "$SDK"/ndk/*; do
    select_prebuilt "$ndk" || true
  done
fi

if [[ -z "$PREBUILT" ]]; then
  printf 'no compatible Android NDK found: need %s plus android/sharedmem.h under ANDROID_NDK_HOME or %s/ndk\n' \
    "$TOOL" "$SDK" >&2
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

LIBCUTILS="$HAL/libcutils.so"
if [[ ! -f "$LIBCUTILS" ]]; then
  SELECTED_DOCKER_CONTEXT="${XENOID_DOCKER_CONTEXT:-${DOCKER_CONTEXT:-}}"
  if [[ -z "$SELECTED_DOCKER_CONTEXT" && -f "$ROOT/.xenoid/config.json" ]]; then
    SELECTED_DOCKER_CONTEXT="$(PYTHONPATH="$ROOT/src" python3 -c 'from xenoid.backend import RuntimeManager; from xenoid.config import load_config; print(RuntimeManager(load_config()).effective_docker_context())')"
  fi
  DOCKER=(docker)
  if [[ -n "$SELECTED_DOCKER_CONTEXT" ]]; then
    DOCKER+=(--context "$SELECTED_DOCKER_CONTEXT")
  fi
  if ! "${DOCKER[@]}" cp "xenoid-android:/system/lib64/libcutils.so" "$LIBCUTILS" >/dev/null 2>&1; then
    IMAGE="${XENOID_BASE_IMAGE:-redroid/redroid:13.0.0_64only-latest}"
    CID="$("${DOCKER[@]}" create "$IMAGE")"
    if ! "${DOCKER[@]}" cp "$CID:/system/lib64/libcutils.so" "$LIBCUTILS"; then
      "${DOCKER[@]}" rm "$CID" >/dev/null 2>&1 || true
      printf 'failed to extract /system/lib64/libcutils.so from %s\n' "$IMAGE" >&2
      exit 1
    fi
    "${DOCKER[@]}" rm "$CID" >/dev/null
  fi
fi

[[ -f "$LIBCUTILS" ]] || { printf 'missing Android libcutils link library: %s\n' "$LIBCUTILS" >&2; exit 1; }


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
