#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADB_JSON() { "$ROOT/xenoid" adb "$@"; }
# Ensure overlays are applied when helper is present.
ADB_JSON shell 'test -x /system/bin/xenoid-overlay-helper && /system/bin/xenoid-overlay-helper apply >/data/local/tmp/xenoid-overlay-smoke.log 2>&1 || true' >/dev/null
OUT=$(ADB_JSON shell 'bad=0; for f in $(find /system /vendor /product /odm -name "*.prop" 2>/dev/null); do if grep -Eiq "redroid|redroid_x86_64|redroid13_x86_64|userdebug|test-keys|x86_64" "$f"; then echo BAD:$f; grep -Ein "redroid|redroid_x86_64|redroid13_x86_64|userdebug|test-keys|x86_64" "$f" | head -5; bad=1; fi; done; exit $bad' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("stdout",""), end="")')
if [[ -n "$OUT" ]]; then
  printf '%s' "$OUT"
  exit 1
fi
printf '{"ok":true,"propFiles":"sanitized"}\n'
