#!/usr/bin/env bash
# Validate or build the Android 13 ARM64 KeyMint HAL service.
#
# Default mode validates the checked-out prebuilt native/xenoid-keymint/xenoid-keymint
# (used by image staging, `xenoid up`, and release verification). `--build`
# compiles it from the in-tree sources: src/ (TEESimulator-derived C++),
# rust/teesim-km (GPL-3.0-or-later glue crate) plus the pinned AOSP/BoringSSL
# checkouts under native/xenoid-keymint/.deps (scripts/fetch-keymint-deps.sh).
#
# The service registers android.hardware.security.keymint.IKeyMintDevice/default
# so keystore2 resolves it through ordinary binder (a declared AIDL HAL always
# wins over keystore2's in-process km_compat fallback). The daemon pushes the
# resolved keybox profile over the @teesim control socket at runtime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT/native/xenoid-keymint"
SERVICE_OUT="$ARTIFACT_DIR/xenoid-keymint"
BUILD_MODE=0
if [[ "${1:-}" == "--build" ]]; then
  BUILD_MODE=1
elif [[ -n "${1:-}" ]]; then
  printf 'usage: %s [--build]\n' "$0" >&2
  exit 64
fi

fail() {
  printf 'keymint_%s\n' "$1" >&2
  exit 1
}

validate_artifacts() {
  python3 - "$1" <<'PY'
from pathlib import Path
import stat
import struct
import sys


def fail(code: str) -> None:
    raise SystemExit(f"keymint_{code}")


path = Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    fail("artifact_missing")
try:
    mode = stat.S_IMODE(path.stat().st_mode)
    data = path.read_bytes()
except OSError:
    fail("artifact_unreadable")
if mode != 0o755:
    fail("artifact_mode_invalid")
if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
    fail("artifact_not_elf64")
if struct.unpack_from("<H", data, 16)[0] != 3:
    fail("artifact_not_pie")
if struct.unpack_from("<H", data, 18)[0] != 183:
    fail("artifact_not_arm64")
phoff = struct.unpack_from("<Q", data, 32)[0]
shoff = struct.unpack_from("<Q", data, 40)[0]
phentsize = struct.unpack_from("<H", data, 54)[0]
phnum = struct.unpack_from("<H", data, 56)[0]
shentsize = struct.unpack_from("<H", data, 58)[0]
shnum = struct.unpack_from("<H", data, 60)[0]
if phentsize < 56 or phnum == 0 or phoff + phentsize * phnum > len(data):
    fail("artifact_segments_invalid")
if shentsize < 64 or shnum == 0 or shoff + shentsize * shnum > len(data):
    fail("artifact_sections_invalid")
has_interp = False
for index in range(phnum):
    p_type = struct.unpack_from("<I", data, phoff + index * phentsize)[0]
    if p_type == 3:
        has_interp = True
if not has_interp:
    fail("artifact_not_executable")
sections = []
for index in range(shnum):
    offset = shoff + index * shentsize
    sections.append({
        "type": struct.unpack_from("<I", data, offset + 4)[0],
        "offset": struct.unpack_from("<Q", data, offset + 24)[0],
        "size": struct.unpack_from("<Q", data, offset + 32)[0],
        "link": struct.unpack_from("<I", data, offset + 40)[0],
        "entsize": struct.unpack_from("<Q", data, offset + 56)[0],
    })
for section in sections:
    if section["type"] != 8 and section["offset"] + section["size"] > len(data):
        fail("artifact_sections_invalid")


def strings(section_index: int) -> bytes:
    if section_index >= len(sections):
        fail("artifact_sections_invalid")
    section = sections[section_index]
    return data[section["offset"]:section["offset"] + section["size"]]


needed: set[str] = set()
for section in sections:
    if section["type"] != 6:
        continue
    dynstr = strings(section["link"])
    entsize = section["entsize"] or 16
    if entsize < 16 or section["size"] % entsize:
        fail("artifact_dynamic_invalid")
    for offset in range(section["offset"], section["offset"] + section["size"], entsize):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag != 1:
            continue
        if value >= len(dynstr):
            fail("artifact_dynamic_invalid")
        end = dynstr.find(b"\0", value)
        if end < 0:
            fail("artifact_dynamic_invalid")
        needed.add(dynstr[value:end].decode("ascii", "strict"))
if b"/Users/" in data or b"/home/" in data or b"xenoid" in data or b"Xenoid" in data:
    fail("artifact_contains_host_path")
allowed_dependencies = {
    "libbinder_ndk.so",
    "libcrypto.so",
    "liblog.so",
    "libc.so",
    "libdl.so",
    "libm.so",
}
if not needed or not needed.issubset(allowed_dependencies):
    fail("artifact_dependency_invalid")
if "libbinder_ndk.so" not in needed or "libcrypto.so" not in needed:
    fail("artifact_dependency_invalid")
PY
}

mkdir -p "$ARTIFACT_DIR"

if [[ "$BUILD_MODE" != "1" ]]; then
  validate_artifacts "$SERVICE_OUT"
  printf '%s\n' 'native/xenoid-keymint/xenoid-keymint'
  exit 0
fi

# --build: compile from the in-tree sources.
[[ -f "$ARTIFACT_DIR/CMakeLists.txt" && -f "$ARTIFACT_DIR/src/keymint_service.cpp" ]] \
  || fail "source_invalid"
if [[ ! -d "$ARTIFACT_DIR/.deps/keymint" ]]; then
  bash "$ROOT/scripts/fetch-keymint-deps.sh" >/dev/null || fail "deps_missing"
fi

PATH="$HOME/.cargo/bin:$PATH"
export PATH RUSTUP_TOOLCHAIN=stable
command -v cargo >/dev/null 2>&1 || fail "cargo_missing"
command -v rustup >/dev/null 2>&1 || fail "rustup_missing"
rustup run stable rustc --version >/dev/null 2>&1 || fail "rust_toolchain_missing"
cargo ndk --version >/dev/null 2>&1 || fail "cargo_ndk_missing"
RUST_TARGETS="$(rustup target list --toolchain stable --installed 2>/dev/null)" \
  || fail "rust_target_missing"
case "$RUST_TARGETS" in
  *aarch64-linux-android*) ;;
  *) fail "rust_target_missing" ;;
esac
# Do not rely on rustup's ~/.cargo/bin proxies being present: resolve the stable
# toolchain's own cargo/rustc so a shadow toolchain earlier on PATH (e.g. a
# Homebrew rustc without the Android target std) cannot hijack the build.
RUST_SYSROOT="$(rustup run stable rustc --print sysroot 2>/dev/null)" \
  || fail "rust_toolchain_missing"
[[ -x "$RUST_SYSROOT/bin/rustc" && -x "$RUST_SYSROOT/bin/cargo" ]] \
  || fail "rust_toolchain_missing"
PATH="$RUST_SYSROOT/bin:$PATH"
export PATH RUSTC="$RUST_SYSROOT/bin/rustc"
# Remap rules are last-match-wins in both clang and rustc: the home prefix goes
# first so the more specific artifact/build dirs below can still win.
RUSTFLAGS="--remap-path-prefix=$HOME=.home --remap-path-prefix=$ARTIFACT_DIR=keymint"
export RUSTFLAGS
export CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0 ZERO_AR_DATE=1

source "$ROOT/scripts/android-sdk-root.sh"
SDK="$(xenoid_android_sdk_root)"
NDK=""
HOST_TAG=""
CC=""
STRIP=""
shopt -s nullglob
for candidate in "$SDK"/ndk/*; do
  for tag in darwin-arm64 darwin-x86_64 linux-x86_64; do
    compiler="$candidate/toolchains/llvm/prebuilt/$tag/bin/aarch64-linux-android33-clang"
    if [[ -x "$compiler" ]]; then
      NDK="$candidate"
      HOST_TAG="$tag"
      CC="$compiler"
      STRIP="$candidate/toolchains/llvm/prebuilt/$tag/bin/llvm-strip"
    fi
  done
done
shopt -u nullglob
[[ -n "$NDK" && -n "$HOST_TAG" && -x "$CC" && -x "$STRIP" ]] || fail "ndk_missing"

CMAKE=""
NINJA=""
shopt -s nullglob
for candidate in "$SDK"/cmake/*/bin/cmake; do
  [[ -x "$candidate" ]] && CMAKE="$candidate"
done
for candidate in "$SDK"/cmake/*/bin/ninja; do
  [[ -x "$candidate" ]] && NINJA="$candidate"
done
shopt -u nullglob
if [[ -z "$CMAKE" ]]; then CMAKE="$(command -v cmake || true)"; fi
if [[ -z "$NINJA" ]]; then NINJA="$(command -v ninja || true)"; fi
[[ -n "$CMAKE" && -x "$CMAKE" ]] || fail "cmake_missing"
[[ -n "$NINJA" && -x "$NINJA" ]] || fail "ninja_missing"

mkdir -p "$ROOT/.tmp"
WORK="$(mktemp -d "$ROOT/.tmp/keymint-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
BUILD="$WORK/keymint"
LOG="$WORK/build.log"

if ! ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK" ANDROID_NDK="$NDK" \
  "$CMAKE" -S "$ARTIFACT_DIR" -B "$BUILD" -G Ninja \
    -DCMAKE_MAKE_PROGRAM="$NINJA" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    "-DCMAKE_C_FLAGS=-ffile-prefix-map=$HOME=.home -ffile-prefix-map=$WORK=work -ffile-prefix-map=$ARTIFACT_DIR=keymint" \
    "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$HOME=.home -ffile-prefix-map=$WORK=work -ffile-prefix-map=$ARTIFACT_DIR=keymint" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-33 \
    -DANDROID_NDK="$NDK" >"$LOG" 2>&1; then
  fail "source_configure_failed"
fi
if ! ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK" ANDROID_NDK="$NDK" \
  "$CMAKE" --build "$BUILD" --target xenoid_keymint_service >"$LOG" 2>&1; then
  fail "source_build_failed"
fi

STAGED_SERVICE="$WORK/xenoid-keymint"
if ! python3 - "$BUILD" "$STAGED_SERVICE" <<'PY'
from pathlib import Path
import shutil
import sys

build = Path(sys.argv[1])
out = Path(sys.argv[2])
candidates = [
    path for path in build.rglob("xenoid_keymint_service")
    if path.is_file() and not path.is_symlink()
]
if len(candidates) != 1:
    raise SystemExit("keymint_source_artifact_invalid")
shutil.copyfile(candidates[0], out)
PY
then
  fail "source_artifact_invalid"
fi

if ! "$STRIP" --strip-unneeded "$STAGED_SERVICE" >"$LOG" 2>&1; then
  fail "artifact_strip_failed"
fi
if ! chmod 0755 "$STAGED_SERVICE" 2>/dev/null; then
  fail "artifact_mode_invalid"
fi

validate_artifacts "$STAGED_SERVICE"
if ! install -m 0755 "$STAGED_SERVICE" "$SERVICE_OUT" 2>/dev/null; then
  fail "artifact_install_failed"
fi
printf '%s\n' 'native/xenoid-keymint/xenoid-keymint'
