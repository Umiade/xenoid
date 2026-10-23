#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-all}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
NDK="$(xenoid_ndk_require "$SDK")" || exit 1
build_one() {
  local arch="$1" TOOL BIN
  if [[ "$arch" == x86_64 ]]; then TOOL=x86_64-linux-android21-clang; else TOOL=aarch64-linux-android21-clang; fi
  BIN="$(xenoid_ndk_tool "$NDK" "$TOOL")" || { echo "$TOOL not found in $NDK" >&2; exit 1; }
  local OUT="$ROOT/native/xenoid-rootd/xenoid-rootd-$arch"
  "$BIN" -O2 -Wall -Wextra -pthread -fPIE -pie -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
    -o "$OUT" "$ROOT/native/xenoid-rootd/xenoid_rootd.c"
  echo "$OUT"
}
if [[ "$ARCH" == all ]]; then
  build_one x86_64
  build_one arm64
else
  build_one "$ARCH"
fi
