#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-all}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
build_one() {
  local arch="$1" TOOL BIN=""
  if [[ "$arch" == x86_64 ]]; then TOOL=x86_64-linux-android21-clang; else TOOL=aarch64-linux-android21-clang; fi
  for ndk in "$SDK"/ndk/*; do for pre in darwin-arm64 darwin-x86_64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
  [[ -n "$BIN" ]] || { echo "$TOOL not found" >&2; exit 1; }
  local OUT="$ROOT/native/xenoid-rootd/xenoid-rootd-$arch"
  "$BIN" -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o "$OUT" "$ROOT/native/xenoid-rootd/xenoid_rootd.c"
  echo "$OUT"
}
if [[ "$ARCH" == all ]]; then
  build_one x86_64
  build_one arm64
else
  build_one "$ARCH"
fi
