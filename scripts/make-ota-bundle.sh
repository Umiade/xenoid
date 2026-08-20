#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-0.1.0}"
if [[ ${#VERSION} -gt 64 || ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "release_version_invalid" >&2
  exit 64
fi
ARTIFACT_ROOT="${XENOID_ARTIFACT_ROOT:-}"
if [[ -z "$ARTIFACT_ROOT" || ! -d "$ARTIFACT_ROOT" || -L "$ARTIFACT_ROOT" ]]; then
  echo "artifact_snapshot_invalid" >&2
  exit 1
fi
OTA_ROOT="${XENOID_OTA_OUTPUT_ROOT:-$ROOT/dist/ota}"
mkdir -p "$OTA_ROOT"
STAGE="$(mktemp -d "$OTA_ROOT/.ota-stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
DIST="$STAGE/xenoid-$VERSION"
BUNDLE="$OTA_ROOT/xenoid-$VERSION.tar.gz"
mkdir -p "$DIST/payload"
DAEMON_APK="$ARTIFACT_ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
INPUT_HELPER="$ARTIFACT_ROOT/native/xenoid-input/xenoid-input"
HIDE_HELPER="$ARTIFACT_ROOT/native/xenoid-hide/xenoid-hide"
PROFILE_HELPER="$ARTIFACT_ROOT/native/xenoid-profile/xenoid-profile"
NETCTL_HELPER="$ARTIFACT_ROOT/native/xenoid-netctl/xenoid-netctl"
for artifact in \
  "$DAEMON_APK" "$INPUT_HELPER" "$HIDE_HELPER" "$PROFILE_HELPER" \
  "$NETCTL_HELPER"; do
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    echo "artifact_snapshot_invalid" >&2
    exit 1
  fi
done
install -m 0644 "$DAEMON_APK" "$DIST/payload/xenoid-daemon.apk"
install -m 0755 "$INPUT_HELPER" "$DIST/payload/xenoid-input"
install -m 0755 "$HIDE_HELPER" "$DIST/payload/xenoid-hide-helper"
install -m 0755 "$PROFILE_HELPER" "$DIST/payload/xenoid-profile-helper"
install -m 0755 "$NETCTL_HELPER" "$DIST/payload/xenoid-netctl"
DIST="$DIST" VERSION="$VERSION" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" python3 - <<'PY'
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

root = Path(os.environ["DIST"])
epoch = int(os.environ["SOURCE_DATE_EPOCH"], 10)
if epoch < 0:
    raise SystemExit("source_date_epoch_invalid")
items = {
    "daemonApk": ("payload/xenoid-daemon.apk", None),
    "inputHelper": ("payload/xenoid-input", "/data/local/tmp/xenoid-input"),
    "hideHelper": ("payload/xenoid-hide-helper", "/data/local/tmp/xenoid-hide-helper"),
    "profileHelper": ("payload/xenoid-profile-helper", "/data/local/tmp/xenoid-profile-helper"),
    "netctlHelper": ("payload/xenoid-netctl", "/data/local/tmp/xenoid-netctl"),
}
payloads = {}
for name, (relative, remote) in items.items():
    entry = {
        "path": relative,
        "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
    }
    if remote is not None:
        entry["remotePath"] = remote
    payloads[name] = entry
manifest = {
    "schema": "dev.xenoid.ota/v1",
    "version": os.environ["VERSION"],
    "createdAt": datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "payloads": payloads,
    "apply": list(items),
}
(root / "manifest.json").write_text(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" \
  python3 "$ROOT/scripts/canonical-tar.py" "$DIST" "$BUNDLE"
printf '%s\n' "$BUNDLE"
