#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="${1:-x86_64}"
MODE="${2:-stable}"
OUT="$ROOT/native/xenoid-shim/libxenoid_shim-$ARCH.so"
case "$ARCH" in x86_64) TOOL=x86_64-linux-android21-clang;; arm64|aarch64) TOOL=aarch64-linux-android21-clang;; *) echo bad arch >&2; exit 2;; esac
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
BIN=""
for ndk in "$SDK"/ndk/*; do for pre in darwin-x86_64 darwin-arm64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
[[ -n "$BIN" ]] || { echo "$TOOL not found" >&2; exit 127; }
CFLAGS="-shared -fPIC -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2"
case "$MODE" in stable) ;; prop) CFLAGS="$CFLAGS -DXENOID_ENABLE_PROPERTY_GET";; *) echo bad mode >&2; exit 2;; esac
"$BIN" $CFLAGS -o "$OUT" "$ROOT/native/xenoid-shim/xenoid_shim.c" -ldl
echo "$OUT"
