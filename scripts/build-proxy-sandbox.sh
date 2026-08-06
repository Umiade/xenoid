#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/xenoid-proxy-sandbox/xenoid_proxy_sandbox.c"
OUT="$ROOT/native/xenoid-proxy-sandbox/xenoid-proxy-sandbox"
TMP="$OUT.tmp-$$"
DOCKER_BUILD_DIR="$ROOT/.tmp/proxy-sandbox-build-$$"
DOCKER_STAGED="$DOCKER_BUILD_DIR/xenoid-proxy-sandbox"
cleanup() {
  rm -f "$TMP" "$DOCKER_STAGED"
  rmdir "$DOCKER_BUILD_DIR" 2>/dev/null || true
}
trap cleanup EXIT

FLAGS=(
  -O2 -std=c11 -Wall -Wextra -Werror -fPIE
  -fstack-protector-strong -D_FORTIFY_SOURCE=3
  -static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
)

build_with() {
  local -a compiler=("$@")
  "${compiler[@]}" "${FLAGS[@]}" "$SRC" -o "$TMP"
}

if [[ -n "${XENOID_PROXY_CC:-}" ]]; then
  # Explicit trusted cross compiler; whitespace-delimited wrappers are not accepted.
  [[ "$XENOID_PROXY_CC" != *[[:space:]]* ]] || {
    echo "XENOID_PROXY_CC must name one executable" >&2
    exit 2
  }
  build_with "$XENOID_PROXY_CC"
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  build_with aarch64-linux-gnu-gcc
elif [[ "$(uname -s)" == Linux && "$(uname -m)" =~ ^(aarch64|arm64)$ ]]; then
  build_with "${CC:-cc}"
elif command -v zig >/dev/null 2>&1; then
  build_with zig cc -target aarch64-linux-gnu
elif command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1; then
  # Colima exposes the repository at the same absolute path and is native ARM64.
  colima ssh -- cc "${FLAGS[@]}" "$SRC" -o "$TMP"
elif command -v docker >/dev/null 2>&1; then
  rm -f "$TMP"
  mkdir -p "$ROOT/.tmp"
  mkdir -m 0700 "$DOCKER_BUILD_DIR"
  docker run --rm --platform linux/arm64 \
    -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
    -v "$SRC:/src/xenoid_proxy_sandbox.c:ro" \
    -v "$DOCKER_BUILD_DIR:/out" \
    debian:bookworm-slim sh -ceu '
      apt-get update >/dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev binutils >/dev/null
      cc -O2 -std=c11 -Wall -Wextra -Werror -fPIE -fstack-protector-strong \
        -D_FORTIFY_SOURCE=3 -static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
        /src/xenoid_proxy_sandbox.c -o /out/xenoid-proxy-sandbox
      chown "$HOST_UID:$HOST_GID" /out/xenoid-proxy-sandbox
    '
  mv "$DOCKER_STAGED" "$TMP"
  rmdir "$DOCKER_BUILD_DIR"
else
  echo "Linux ARM64 compiler unavailable (install aarch64-linux-gnu-gcc, zig, or Docker)" >&2
  exit 127
fi

python3 - "$TMP" <<'PY'
import pathlib, struct, sys
path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    raise SystemExit("sandbox build is not a 64-bit little-endian ELF")
if struct.unpack_from("<H", data, 18)[0] != 183:
    raise SystemExit("sandbox build is not Linux ARM64")
program_offset = struct.unpack_from("<Q", data, 32)[0]
program_size = struct.unpack_from("<H", data, 54)[0]
program_count = struct.unpack_from("<H", data, 56)[0]
if any(
    struct.unpack_from("<I", data, program_offset + index * program_size)[0] == 3
    for index in range(program_count)
):
    raise SystemExit("sandbox build is dynamically linked")
if b"/system/bin/linker64" in data:
    raise SystemExit("sandbox build uses the Android/Bionic linker")
PY
chmod 0555 "$TMP"
mv -f "$TMP" "$OUT"
trap - EXIT
printf '%s\n' "$OUT"
