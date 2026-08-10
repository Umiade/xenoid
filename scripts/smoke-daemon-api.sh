#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PORT="${XENOID_DAEMON_PORT:-18765}"
START_MOCK="${1:-}"
PID=""
MOCK_ROOT=""
MOCK_INSTANCE=""
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" >/dev/null 2>&1 || true
  if [[ -n "$MOCK_INSTANCE" ]]; then
    rm -rf -- "$ROOT/.xenoid/instances/$MOCK_INSTANCE"
  fi
  [[ -z "$MOCK_ROOT" ]] || rm -rf -- "$MOCK_ROOT"
}
trap cleanup EXIT
if [[ "$START_MOCK" == "--mock" ]]; then
  MOCK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-daemon-smoke.XXXXXX")"
  MOCK_INSTANCE="daemon-smoke-$$"
  export HOME="$MOCK_ROOT/home"
  export XENOID_PROJECT="$ROOT"
  export XENOID_INSTANCE="$MOCK_INSTANCE"
  mkdir -p "$HOME"
  ./xenoid --instance "$MOCK_INSTANCE" init >/dev/null
  PORT="$(PYTHONPATH="$ROOT/src" python3 -c 'from xenoid.config import resolve_instance; print(resolve_instance()[2].host_daemon_port)')"
  PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m xenoid.mock_daemon --port "$PORT" >/tmp/xenoid-mock-daemon.log 2>&1 &
  PID="$!"
  for i in {1..20}; do
    grep -q mockDaemon /tmp/xenoid-mock-daemon.log 2>/dev/null && break
    sleep 0.1
  done
fi
SMOKE_STATE_ROOT="$(PYTHONPATH="$ROOT/src" python3 -c 'from xenoid.config import resolve_instance; print(resolve_instance()[0].state_root)')"
./xenoid daemon health
./xenoid root status
./xenoid frida start
./xenoid frida status
./xenoid frida stop
./xenoid profile status
./xenoid profile env
./xenoid profile dump
./xenoid device collect --out "$SMOKE_STATE_ROOT/smoke-fingerprint.json"
./xenoid device apply examples/fingerprints/sample-profile.json --keep-unique --generate-frida --frida-out "$SMOKE_STATE_ROOT/smoke-profile.js"
./xenoid device generate-frida examples/fingerprints/sample-profile.json --out "$SMOKE_STATE_ROOT/smoke-profile-2.js"
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


proxy_cases = 0


def expect(condition):
    global proxy_cases
    assert condition
    proxy_cases += 1


def expect_error(method, path, body, error):
    result = api(method, path, body)
    expect(result == {"ok": False, "error": error})


proxy_status_keys = {
    "ok",
    "schemaVersion",
    "instanceId",
    "generation",
    "enabled",
    "configured",
    "sourceKind",
    "selectedNode",
    "udpAllowed",
    "allowInsecureHttp",
    "checkId",
    "runtimeEpoch",
    "report",
    "probe",
}
proxy_status = api("GET", "/proxy/status")
expect(set(proxy_status) == proxy_status_keys)
expect(
    proxy_status["ok"]
    and proxy_status["schemaVersion"] == 1
    and proxy_status["instanceId"] == ""
    and proxy_status["generation"] == 0
    and proxy_status["checkId"] == 0
    and proxy_status["configured"] is False
    and proxy_status["enabled"] is False
    and proxy_status["sourceKind"] is None
    and proxy_status["selectedNode"] == ""
    and proxy_status["udpAllowed"] is False
    and proxy_status["allowInsecureHttp"] is False
)

for method, path in (
    ("POST", "/proxy/status"),
    ("PUT", "/proxy/status"),
    ("PATCH", "/proxy/source"),
    ("DELETE", "/proxy/clear"),
    ("GET", "/proxy/source"),
    ("GET", "/proxy/enabled"),
    ("GET", "/proxy/select"),
    ("GET", "/proxy/clear"),
    ("GET", "/proxy/check"),
    ("POST", "/proxy/export"),
    ("GET", "/proxy/agent-bootstrap"),
    ("GET", "/proxy/agent"),
):
    expect_error(method, path, {}, "method_not_allowed")

expect_error(
    "POST", "/proxy/agent-bootstrap", {}, "agent_channel_unavailable_in_mock"
)
expect_error("POST", "/proxy/agent", {}, "agent_channel_unavailable_in_mock")
expect_error("GET", "/proxy/status", {"extra": True}, "invalid_request_schema")
expect_error("GET", "/proxy/export", {"extra": True}, "invalid_request_schema")
expect_error("POST", "/proxy/enabled", {"enabled": True, "extra": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/enabled", {"enabled": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/enabled", {"enabled": True}, "source_invalid")
expect_error("POST", "/proxy/select", {"name": ""}, "invalid_request_schema")
expect_error("POST", "/proxy/select", {"name": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/select", {"name": "n" * 129}, "invalid_request_schema")
expect_error("POST", "/proxy/select", {"name": "node", "extra": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/select", {"name": "node"}, "source_invalid")
expect_error("POST", "/proxy/clear", {"extra": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/check", {"extra": 1}, "invalid_request_schema")
expect_error("POST", "/proxy/check", None, "invalid_request_body")
expect_error("POST", "/proxy/check", {}, "proxy_disabled")

synthetic_source = "socks5://proxy.invalid:1080"
source_request = {
    "kind": "endpoint",
    "value": synthetic_source,
    "enable": True,
    "selectedNode": "",
    "udpAllowed": False,
    "allowInsecureHttp": False,
}
source_type_negatives = (
    {**source_request, "kind": 1},
    {**source_request, "value": 1},
    {**source_request, "enable": 1},
    {**source_request, "selectedNode": None},
    {**source_request, "udpAllowed": 0},
    {**source_request, "allowInsecureHttp": 0},
)
for rejected_source in source_type_negatives:
    expect_error("POST", "/proxy/source", rejected_source, "invalid_request_schema")
expect_error(
    "POST",
    "/proxy/source",
    {key: value for key, value in source_request.items() if key != "allowInsecureHttp"},
    "invalid_request_schema",
)
expect_error(
    "POST", "/proxy/source", {**source_request, "kind": "unknown"}, "source_invalid"
)
expect_error("POST", "/proxy/source", {**source_request, "value": ""}, "source_invalid")
expect_error(
    "POST", "/proxy/source", {**source_request, "value": "bad\x00source"}, "source_invalid"
)
expect_error(
    "POST",
    "/proxy/source",
    {**source_request, "value": "x" * (1024 * 1024 + 1)},
    "invalid_request_schema",
)
expect_error(
    "POST",
    "/proxy/source",
    {**source_request, "selectedNode": "n" * 129},
    "invalid_request_schema",
)
expect_error(
    "POST",
    "/proxy/source",
    {**source_request, "extra": True},
    "invalid_request_schema",
)
expect_error("POST", "/proxy/source", [], "invalid_request_schema")
proxy_status = api("GET", "/proxy/status")
expect(proxy_status["generation"] == 0 and proxy_status["checkId"] == 0)

proxy_status = api("POST", "/proxy/source", source_request)
expect(
    proxy_status["ok"]
    and proxy_status["generation"] == 1
    and proxy_status["checkId"] == 1
)
generation = proxy_status["generation"]
repeated = api("POST", "/proxy/source", source_request)
expect(repeated["generation"] == generation and repeated["checkId"] == 1)

settings_request = {
    **source_request,
    "udpAllowed": True,
    "allowInsecureHttp": True,
}
proxy_status = api("POST", "/proxy/source", settings_request)
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["checkId"] == 2
    and proxy_status["udpAllowed"] is True
    and proxy_status["allowInsecureHttp"] is True
)
generation = proxy_status["generation"]
repeated = api("POST", "/proxy/source", settings_request)
expect(repeated["generation"] == generation and repeated["checkId"] == 2)

proxy_status = api("POST", "/proxy/select", {"name": "fixture-node"})
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["checkId"] == 3
    and proxy_status["selectedNode"] == "fixture-node"
)
generation = proxy_status["generation"]
repeated = api("POST", "/proxy/select", {"name": "fixture-node"})
expect(repeated["generation"] == generation and repeated["checkId"] == 3)

proxy_status = api("POST", "/proxy/check", {})
expect(proxy_status["generation"] == generation and proxy_status["checkId"] == 4)
proxy_status = api("POST", "/proxy/check", {})
expect(proxy_status["generation"] == generation and proxy_status["checkId"] == 5)

proxy_status = api("POST", "/proxy/enabled", {"enabled": False})
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["enabled"] is False
    and proxy_status["checkId"] == 5
)
generation = proxy_status["generation"]
repeated = api("POST", "/proxy/enabled", {"enabled": False})
expect(repeated["generation"] == generation and repeated["checkId"] == 5)

proxy_status = api("GET", "/proxy/status")
serialized_status = json.dumps(proxy_status, ensure_ascii=False)
expect(
    synthetic_source not in serialized_status
    and "socks5://" not in serialized_status
    and "proxy.invalid" not in serialized_status
)
expect(
    proxy_status["configured"] is True
    and proxy_status["sourceKind"] == "endpoint"
    and proxy_status["selectedNode"] == "fixture-node"
)

exported = api("GET", "/proxy/export")
expect(
    set(exported)
    == {
        "ok",
        "schemaVersion",
        "instanceId",
        "generation",
        "enabled",
        "checkId",
        "source",
    }
)
expect(
    exported["source"]
    == {
        "kind": "endpoint",
        "value": synthetic_source,
        "selectedNode": "fixture-node",
        "udpAllowed": True,
        "allowInsecureHttp": True,
    }
)

proxy_status = api("POST", "/proxy/enabled", {"enabled": True})
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["enabled"] is True
    and proxy_status["checkId"] == 6
)
generation = proxy_status["generation"]
proxy_status = api("POST", "/proxy/clear", {})
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["checkId"] == 6
    and proxy_status["enabled"] is False
    and proxy_status["configured"] is False
    and proxy_status["sourceKind"] is None
    and proxy_status["selectedNode"] == ""
    and proxy_status["udpAllowed"] is False
    and proxy_status["allowInsecureHttp"] is False
)
generation = proxy_status["generation"]
expect(api("GET", "/proxy/export")["source"] is None)
repeated = api("POST", "/proxy/clear", {})
expect(repeated["generation"] == generation and repeated["checkId"] == 6)
expect_error("POST", "/proxy/check", {}, "proxy_disabled")
proxy_status = api("GET", "/proxy/status")
expect(proxy_status["generation"] == generation and proxy_status["checkId"] == 6)

subscription_source = "https://feed.invalid/proxy-list"
subscription_request = {
    **source_request,
    "kind": "subscription",
    "value": subscription_source,
    "enable": False,
}
proxy_status = api("POST", "/proxy/source", subscription_request)
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["checkId"] == 6
    and proxy_status["sourceKind"] == "subscription"
    and proxy_status["configured"] is True
)
serialized_status = json.dumps(proxy_status, ensure_ascii=False)
expect(
    subscription_source not in serialized_status
    and "https://" not in serialized_status
    and "feed.invalid" not in serialized_status
)
expect(api("GET", "/proxy/export")["source"]["value"] == subscription_source)
generation = proxy_status["generation"]
proxy_status = api("POST", "/proxy/clear", {})
expect(
    proxy_status["generation"] == generation + 1
    and proxy_status["checkId"] == 6
    and proxy_status["configured"] is False
    and api("GET", "/proxy/export")["source"] is None
)


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
            cli._camera_ready = lambda _args, manager=manager, client=client: (manager, client)
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
    cli._camera_ready = lambda _args: (manager, client)
    with redirect_stdout(io.StringIO()):
        code = cli.cmd_camera_status(Namespace(check=True))
    assert code == 1 and client.started and manager.launches == 0
finally:
    cli._camera_ready = original_camera_ready
print(json.dumps({"ok": True, "cases": proxy_cases}, separators=(",", ":")))
PY
fi
./xenoid camera status
./xenoid camera mode faithful
./xenoid camera mode naturalized
./xenoid camera clear all
./xenoid camera apply
