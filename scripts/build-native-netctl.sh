#!/usr/bin/env bash
set -euo pipefail
ARCH="${1:-arm64}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/native/xenoid-netctl/xenoid-netctl"
[[ "$ARCH" == "x86_64" ]] && OUT="$ROOT/native/xenoid-netctl/xenoid-netctl-x86_64"
XENOID_ANDROID_API=24 exec "$ROOT/scripts/build-native-for-arch.sh" xenoid-netctl "$ROOT/native/xenoid-netctl/xenoid_netctl.c" "$OUT" "$ARCH"
