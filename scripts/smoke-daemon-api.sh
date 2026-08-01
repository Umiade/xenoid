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
if [[ "$START_MOCK" == "--mock" ]]; then
  MOCK_CAMERA_PORT="$PORT" PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PY'
import hashlib
import io
import json
import os
import re
import urllib.request
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import xenoid.cli as cli
from xenoid.daemon_client import CAMERA_MUTATION_TIMEOUT_SECONDS, DaemonClient


class DeadlineProbe(DaemonClient):
    def __init__(self):
        self.calls = []

    def request(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body, timeout))
        return {"ok": True}


probe = DeadlineProbe()
probe.camera_source("photo", "/stage", 1, "0" * 64)
probe.camera_settings("faithful")
probe.camera_clear("all")
probe.camera_apply()
assert CAMERA_MUTATION_TIMEOUT_SECONDS > 3005
assert all(call[3] == CAMERA_MUTATION_TIMEOUT_SECONDS for call in probe.calls)
assert probe.calls[-1][2] == {}

base = f"http://127.0.0.1:{os.environ['MOCK_CAMERA_PORT']}"


def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


camera_keys = {
    "ok", "mode", "generation", "active",
    "photoConfigured", "photoWidth", "photoHeight",
    "videoConfigured", "videoWidth", "videoHeight", "videoDurationMs",
    "videoCodec", "videoRotation", "lastError", "mock",
}
status = api("GET", "/camera/status")
assert set(status) == camera_keys
assert status["active"] is False
assert isinstance(status["lastError"], str)
assert isinstance(status["videoCodec"], str)
assert status["videoRotation"] == 0

generation = status["generation"]
status = api("POST", "/camera/settings", {"mode": "naturalized"})
assert status["ok"] and status["generation"] == generation + 1
generation = status["generation"]
rejected = api("POST", "/camera/settings", {"mode": "naturalized", "extra": 1})
assert not rejected["ok"]
assert api("GET", "/camera/status")["generation"] == generation

source = {
    "kind": "video",
    "stagingPath": "/data/local/tmp/.camera-upload-" + "1" * 32,
    "size": 1,
    "sha256": "2" * 64,
}
status = api("POST", "/camera/source", source)
assert status["ok"] and status["generation"] == generation + 1
assert status["videoCodec"] == "video/avc" and status["videoRotation"] == 0
generation = status["generation"]
for path, body in (
    ("/camera/source", {**source, "extra": 1}),
    ("/camera/clear", {"kind": "video", "extra": 1}),
    ("/camera/apply", {"extra": 1}),
):
    assert not api("POST", path, body)["ok"]
assert api("GET", "/camera/status")["generation"] == generation
assert api("POST", "/camera/apply", {})["ok"]

run_id = "3" * 32
assert not api("POST", "/camera/self-test/start", {"runId": "A" * 32})["ok"]
assert not api("POST", "/camera/self-test/start", {"runId": run_id, "extra": 1})["ok"]
assert api("POST", "/camera/self-test/start", {"runId": run_id})["ok"]


class StagingManager:
    def __init__(self, payload, staging):
        self.payload = payload
        self.staging = staging
        self.cleaned = []

    def stage_camera_source(self, local):
        assert Path(local).read_bytes() == self.payload
        self.staging.write_bytes(self.payload)
        return {
            "ok": True,
            "stagingPath": str(self.staging),
            "size": len(self.payload),
            "sha256": hashlib.sha256(self.payload).hexdigest(),
        }

    def cleanup_camera_staging(self, path):
        assert path == str(self.staging)
        self.cleaned.append(path)
        Path(path).unlink()


class SourceClient:
    def __init__(self, outcome):
        self.outcome = outcome

    def camera_source(self, kind, path, size, digest):
        assert kind == "photo" and size > 0
        assert digest == hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


original_camera_ready = cli._camera_ready
try:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        payload = b"deterministic non-media camera staging smoke"
        local = root / "payload.bin"
        local.write_bytes(payload)
        scenarios = (
            ({"ok": True}, 0),
            ({"ok": False, "error": "rejected"}, 1),
            (TimeoutError("timed out"), 1),
            (RuntimeError("failed"), 1),
        )
        for index, (outcome, expected_code) in enumerate(scenarios):
            staging = root / f"controlled-stage-{index}"
            manager = StagingManager(payload, staging)
            client = SourceClient(outcome)
            cli._camera_ready = lambda manager=manager, client=client: (manager, client)
            with redirect_stdout(io.StringIO()):
                code = cli.cmd_camera_set(Namespace(file=local, kind="photo"))
            assert code == expected_code
            assert manager.cleaned == [str(staging)]
            assert not staging.exists()

    class AuthorizationManager:
        def __init__(self):
            self.launches = 0

        def grant_daemon_camera_permission(self):
            return {"ok": True}

        def launch_camera_self_test(self, run_id):
            self.launches += 1
            return {"ok": False}

    class RejectingAuthorizationClient:
        def __init__(self):
            self.started = False

        def camera_self_test_start(self, run_id):
            assert re.fullmatch(r"[0-9a-f]{32}", run_id)
            self.started = True
            return {"ok": False, "error": "authorization rejected"}

    manager = AuthorizationManager()
    client = RejectingAuthorizationClient()
    cli._camera_ready = lambda: (manager, client)
    with redirect_stdout(io.StringIO()):
        code = cli.cmd_camera_status(Namespace(check=True))
    assert code == 1 and client.started and manager.launches == 0
finally:
    cli._camera_ready = original_camera_ready
PY
fi
./xenoid camera status
./xenoid camera mode faithful
./xenoid camera mode naturalized
./xenoid camera clear all
./xenoid camera apply
