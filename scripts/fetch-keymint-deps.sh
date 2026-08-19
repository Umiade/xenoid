#!/usr/bin/env bash
# Fetch the pinned AOSP/BoringSSL dependencies of the in-tree KeyMint HAL
# service into native/xenoid-keymint/.deps (gitignored). Checkouts are pinned
# to exact commits and kept small with partial clone + sparse checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS="$ROOT/native/xenoid-keymint/.deps"

fail() {
  printf 'keymint_deps_%s\n' "$1" >&2
  exit 1
}

command -v git >/dev/null 2>&1 || fail "git_missing"

mkdir -p "$DEPS"

# fetch <name> <url> <commit> <sparse paths...>
fetch() {
  local name="$1" url="$2" sha="$3"
  shift 3
  local dir="$DEPS/$name"
  if [[ -d "$dir/.git" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$sha" ]]; then
    printf '%s %s\n' "$name" "pinned"
    return 0
  fi
  rm -rf "$dir"
  git init -q "$dir" || fail "init_failed:$name"
  git -C "$dir" remote add origin "$url"
  if ! git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$sha"; then
    fail "fetch_failed:$name"
  fi
  git -C "$dir" sparse-checkout init --cone || fail "sparse_failed:$name"
  git -C "$dir" sparse-checkout set "$@" || fail "sparse_failed:$name"
  if ! git -C "$dir" checkout -q FETCH_HEAD; then
    fail "checkout_failed:$name"
  fi
  [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$sha" ]] || fail "pin_failed:$name"
  printf '%s %s\n' "$name" "fetched"
}

fetch keymint https://android.googlesource.com/platform/system/keymint \
  cfeefc94bf8c4f19d19dca193d376a1fc05e8e3e \
  boringssl common derive ta tests wire

fetch interfaces https://android.googlesource.com/platform/hardware/interfaces \
  0162af698935100a590b7359581ac8b1b80693e5 \
  security/keymint/aidl security/secureclock/aidl security/sharedsecret/aidl

fetch frameworks-native https://android.googlesource.com/platform/frameworks/native \
  ae266dcb706d083868578cfedce381ef44488a07 \
  libs/binder/ndk/include_cpp libs/binder/ndk/include_ndk libs/binder/ndk/include_platform

fetch boringssl https://boringssl.googlesource.com/boringssl \
  423b1aa3b1dc62f01e46bbd51affee5f5e021db0 \
  include

[[ -f "$DEPS/keymint/ta/src/lib.rs" ]] || fail "keymint_incomplete"
[[ -f "$DEPS/interfaces/security/keymint/aidl/android/hardware/security/keymint/IKeyMintDevice.aidl" ]] \
  || fail "interfaces_incomplete"
[[ -f "$DEPS/frameworks-native/libs/binder/ndk/include_ndk/android/binder_ibinder.h" ]] \
  || fail "frameworks_native_incomplete"
[[ -f "$DEPS/boringssl/include/openssl/base.h" ]] || fail "boringssl_incomplete"
printf '%s\n' "native/xenoid-keymint/.deps ready"
