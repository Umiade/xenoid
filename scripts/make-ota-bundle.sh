#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-0.1.0}"
DIST="$ROOT/dist/ota/xenoid-$VERSION"
BUNDLE="$ROOT/dist/ota/xenoid-$VERSION.tar.gz"
DAEMON_APK="$ROOT/daemon/app/build/outputs/apk/debug/app-debug.apk"
INPUT_HELPER="$ROOT/native/xenoid-input/xenoid-input"
HIDE_HELPER="$ROOT/native/xenoid-hide/xenoid-hide"
PROFILE_HELPER="$ROOT/native/xenoid-profile/xenoid-profile"
NETCTL_HELPER="$ROOT/native/xenoid-netctl/xenoid-netctl"

[[ -f "$DAEMON_APK" ]] || "$ROOT/scripts/build-daemon.sh" >/dev/null
[[ -f "$INPUT_HELPER" ]] || "$ROOT/scripts/build-native-input.sh" >/dev/null
[[ -f "$HIDE_HELPER" ]] || "$ROOT/scripts/build-native-hide.sh" >/dev/null
[[ -f "$PROFILE_HELPER" ]] || "$ROOT/scripts/build-native-profile.sh" >/dev/null
[[ -f "$NETCTL_HELPER" ]] || "$ROOT/scripts/build-native-netctl.sh" >/dev/null
rm -rf "$DIST"
mkdir -p "$DIST/payload"
cp "$DAEMON_APK" "$DIST/payload/xenoid-daemon.apk"
cp "$INPUT_HELPER" "$DIST/payload/xenoid-input"
cp "$HIDE_HELPER" "$DIST/payload/xenoid-hide-helper"
cp "$PROFILE_HELPER" "$DIST/payload/xenoid-profile-helper"
cp "$NETCTL_HELPER" "$DIST/payload/xenoid-netctl"
chmod 755 "$DIST/payload/xenoid-input" "$DIST/payload/xenoid-hide-helper" "$DIST/payload/xenoid-profile-helper" "$DIST/payload/xenoid-netctl"
SHA_DAEMON=$(shasum -a 256 "$DIST/payload/xenoid-daemon.apk" | awk '{print $1}')
SHA_INPUT=$(shasum -a 256 "$DIST/payload/xenoid-input" | awk '{print $1}')
SHA_HIDE=$(shasum -a 256 "$DIST/payload/xenoid-hide-helper" | awk '{print $1}')
SHA_PROFILE=$(shasum -a 256 "$DIST/payload/xenoid-profile-helper" | awk '{print $1}')
SHA_NETCTL=$(shasum -a 256 "$DIST/payload/xenoid-netctl" | awk '{print $1}')
cat > "$DIST/manifest.json" <<JSON
{
  "schema": "dev.xenoid.ota/v1",
  "version": "$VERSION",
  "createdAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "payloads": {
    "daemonApk": {
      "path": "payload/xenoid-daemon.apk",
      "sha256": "$SHA_DAEMON"
    },
    "inputHelper": {
      "path": "payload/xenoid-input",
      "sha256": "$SHA_INPUT",
      "remotePath": "/data/local/tmp/xenoid-input"
    },
    "hideHelper": {
      "path": "payload/xenoid-hide-helper",
      "sha256": "$SHA_HIDE",
      "remotePath": "/data/local/tmp/xenoid-hide-helper"
    },
    "profileHelper": {
      "path": "payload/xenoid-profile-helper",
      "sha256": "$SHA_PROFILE",
      "remotePath": "/data/local/tmp/xenoid-profile-helper"
    },
    "netctlHelper": {
      "path": "payload/xenoid-netctl",
      "sha256": "$SHA_NETCTL",
      "remotePath": "/data/local/tmp/xenoid-netctl"
    }
  },
  "apply": ["daemonApk", "inputHelper", "hideHelper", "profileHelper", "netctlHelper"]
}
JSON
rm -f "$BUNDLE"
COPYFILE_DISABLE=1 tar -C "$ROOT/dist/ota" -czf "$BUNDLE" "xenoid-$VERSION"
printf '%s\n' "$BUNDLE"
