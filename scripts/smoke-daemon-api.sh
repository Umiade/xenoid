#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PORT="${XENOID_DAEMON_PORT:-18765}"
if [[ "${1:-}" == "--mock" && -z "${XENOID_DAEMON_PORT:-}" ]]; then PORT=18766; fi
START_MOCK="${1:-}"
PID=""
cleanup() { if [[ -n "${ORIG_CONFIG:-}" ]]; then printf "%s" "$ORIG_CONFIG" > .xenoid/config.json; fi; [[ -n "$PID" ]] && kill "$PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
ORIG_CONFIG=""
if [[ "$START_MOCK" == "--mock" ]]; then
  PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m xenoid.mock_daemon --port "$PORT" >/tmp/xenoid-mock-daemon.log 2>&1 &
  PID="$!"
  for i in {1..20}; do grep -q mockDaemon /tmp/xenoid-mock-daemon.log 2>/dev/null && break; sleep 0.1; done
  ORIG_CONFIG="$(cat .xenoid/config.json 2>/dev/null || true)"
  python3 - <<PY
import json, pathlib
p=pathlib.Path('.xenoid/config.json'); p.parent.mkdir(exist_ok=True)
d=json.loads(p.read_text()) if p.exists() else {}
d['daemon_port']=$PORT
p.write_text(json.dumps(d, indent=2)+'\n')
PY
fi
./xenoid daemon health
./xenoid root status
./xenoid frida start
./xenoid frida status
./xenoid frida stop
./xenoid profile status
./xenoid profile env
./xenoid profile dump
./xenoid device collect --out /tmp/xenoid-smoke-fingerprint.json
./xenoid device apply examples/fingerprints/sample-profile.json --generate-frida --frida-out /tmp/xenoid-smoke-profile.js
./xenoid device generate-frida examples/fingerprints/sample-profile.json --out /tmp/xenoid-smoke-profile-2.js
./xenoid device set android_id 0011223344556677
./xenoid input tap 10 20
./xenoid input swipe 10 20 30 40 50
./xenoid app launch com.android.settings/.Settings
./xenoid automation plan examples/automation/ordered-task.js
./xenoid automation run-host examples/automation/ordered-task.js
./xenoid automation run examples/automation/ordered-task.js
./xenoid hide apply examples/hide/default-policy.json
./xenoid hide status
./xenoid ota check
./xenoid ota apply --channel smoke
