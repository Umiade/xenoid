#!/usr/bin/env bash
# Build the ordinary app_process64 dependency used by every zygote descendant.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-arm64}"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
BIN=""
if [[ "$ARCH" == x86_64 ]]; then TOOL=x86_64-linux-android24-clang; else TOOL=aarch64-linux-android24-clang; fi
for ndk in "$SDK"/ndk/*; do for pre in darwin-arm64 darwin-x86_64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
if [[ -z "$BIN" ]]; then # fall back to API21 toolchain if 24 isn't present
  if [[ "$ARCH" == x86_64 ]]; then TOOL=x86_64-linux-android21-clang; else TOOL=aarch64-linux-android21-clang; fi
  for ndk in "$SDK"/ndk/*; do for pre in darwin-arm64 darwin-x86_64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
fi
[[ -n "$BIN" ]] || { echo "$TOOL not found" >&2; exit 1; }
SUF=""; [[ "$ARCH" == x86_64 ]] && SUF="-x86_64"
OUT="$ROOT/native/xenoid-zygote/libxenoid_zygote$SUF.so"
"$BIN" -O2 -fPIC -shared -Wall -Wextra -fstack-protector-strong \
  -Wl,-z,global -D_FORTIFY_SOURCE=2 -DXENOID_COMBINED_SHIM \
  -o "$OUT" \
  "$ROOT/native/xenoid-zygote/xenoid_zygote.c" \
  "$ROOT/native/xenoid-shim/xenoid_shim.c" \
  -ldl
echo "$OUT"
