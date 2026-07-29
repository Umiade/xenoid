#!/usr/bin/env bash
set -euo pipefail
NAME="$1"; SRC="$2"; OUT="$3"; ARCH="${4:-x86_64}"; LINK="${5:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
case "$ARCH" in x86_64) TOOL=x86_64-linux-android21-clang;; arm64|aarch64) TOOL=aarch64-linux-android21-clang;; *) echo "bad arch $ARCH" >&2; exit 2;; esac
BIN=""
for ndk in "$SDK"/ndk/*; do for pre in darwin-x86_64 darwin-arm64 linux-x86_64; do [[ -x "$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL" ]] && BIN="$ndk/toolchains/llvm/prebuilt/$pre/bin/$TOOL"; done; done
[[ -n "$BIN" ]] || { echo "$TOOL not found" >&2; exit 127; }
EXTRA=()
[[ "$LINK" == "static" ]] && EXTRA+=(-static)
"$BIN" -O2 -s -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 "${EXTRA[@]}" -o "$OUT" "$SRC"
echo "$OUT"
