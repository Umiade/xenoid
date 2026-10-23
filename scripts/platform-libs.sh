#!/usr/bin/env bash
# Resolve Android platform link libraries from the pinned redroid base image.
#
# Usage: scripts/platform-libs.sh <lib.so>...
# Prints one absolute path per requested library, in argument order.
#
# HAL services link a few on-device libraries whose service-side symbols are
# absent from the NDK stubs. The bytes are pinned by SHA-256 below and cached
# under .xenoid/cache/platform-libs/<sha256>/<name>, outside every declared
# artifact source tree, so extracting them never mutates build inputs. Docker is
# only consulted when the cache is cold; a verified cache entry is reused as is.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.xenoid/cache/platform-libs"

fail() {
  printf 'platform_libs_%s\n' "$1" >&2
  [[ -z "${2:-}" ]] || printf '%s\n' "$2" >&2
  exit 1
}

# /system/lib64 of redroid/redroid:13.0.0_64only-latest
# (sha256:5a42a569ee1d7c71796c0385e906cbaa4c3e0a162a56d9f26b29bdb1befac13b).
pinned_sha256() {
  case "$1" in
    libbinder_ndk.so) printf '%s\n' 662b165fbca2d32a60e75622d33886351a10cb989c16adcdc20d318541b35ca1 ;;
    libcamera_metadata.so) printf '%s\n' 254eefcecd8df257e54046d3cfdd10a673209b0f90258215f99266a73c6e97d0 ;;
    libcutils.so) printf '%s\n' 7bab7accfb8bf5ff81b245c00b8e4a5efae3127d1ba1edbdfb8eb38a189b884d ;;
    *) return 1 ;;
  esac
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

[[ $# -gt 0 ]] || fail "usage" "usage: $0 <lib.so>..."
for name in "$@"; do
  pinned_sha256 "$name" >/dev/null || fail "unknown:$name"
done

missing=()
for name in "$@"; do
  sha="$(pinned_sha256 "$name")"
  path="$CACHE/$sha/$name"
  if [[ -f "$path" && ! -L "$path" && "$(sha256_of "$path")" == "$sha" ]]; then
    continue
  fi
  missing+=("$name")
done

if [[ ${#missing[@]} -gt 0 ]]; then
  command -v docker >/dev/null 2>&1 \
    || fail "docker_missing" "docker is required once to extract Android platform libraries; run ./xenoid install-runtime"
  IMAGE_ID="$(PYTHONPATH="$ROOT/src" python3 -c 'from xenoid.config import DEFAULT_IMAGE_ID; print(DEFAULT_IMAGE_ID)')" \
    || fail "image_unresolved"

  # Candidate engines, most explicit first. The first one that already holds the
  # pinned base image wins; contexts are only probed, never switched.
  contexts=()
  [[ -z "${XENOID_DOCKER_CONTEXT:-}" ]] || contexts+=("$XENOID_DOCKER_CONTEXT")
  [[ -z "${DOCKER_CONTEXT:-}" ]] || contexts+=("$DOCKER_CONTEXT")
  instance_context="$(PYTHONPATH="$ROOT/src" python3 -c '
from pathlib import Path
import sys
from xenoid.backend import RuntimeManager
from xenoid.config import resolve_instance
c, g, l = resolve_instance(project_root=Path(sys.argv[1]))
print(RuntimeManager(c, g, l).effective_docker_context())
' "$ROOT" 2>/dev/null || true)"
  [[ -z "$instance_context" ]] || contexts+=("$instance_context")
  [[ "$(uname -s)" != Darwin ]] || contexts+=(colima)
  contexts+=(default)

  DOCKER=()
  for context in "${contexts[@]}"; do
    if docker --context "$context" image inspect --format '{{.Id}}' "$IMAGE_ID" >/dev/null 2>&1; then
      DOCKER=(docker --context "$context")
      break
    fi
  done
  [[ ${#DOCKER[@]} -gt 0 ]] \
    || fail "base_image_missing" "pinned base image $IMAGE_ID is not present in any Docker engine; run ./xenoid install-runtime"

  mkdir -p "$CACHE"
  chmod 0700 "$CACHE"
  STAGE="$(mktemp -d "$CACHE/.stage.XXXXXX")"
  CID=""
  cleanup() {
    [[ -z "$CID" ]] || "${DOCKER[@]}" rm -f "$CID" >/dev/null 2>&1 || true
    rm -rf "$STAGE"
  }
  trap cleanup EXIT
  CID="$("${DOCKER[@]}" create "$IMAGE_ID")" || fail "container_create_failed"
  for name in "${missing[@]}"; do
    sha="$(pinned_sha256 "$name")"
    "${DOCKER[@]}" cp -L "$CID:/system/lib64/$name" "$STAGE/$name" >/dev/null \
      || fail "extract_failed:$name"
    actual="$(sha256_of "$STAGE/$name")"
    [[ "$actual" == "$sha" ]] || fail "digest_mismatch:$name" "expected $sha, got $actual"
    chmod 0644 "$STAGE/$name"
    mkdir -p "$CACHE/$sha"
    # rename(2) is atomic: concurrent HAL builds publish identical verified bytes.
    mv -f "$STAGE/$name" "$CACHE/$sha/$name"
  done
fi

for name in "$@"; do
  printf '%s\n' "$CACHE/$(pinned_sha256 "$name")/$name"
done
