from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

def _pending_camera(facing: str, state: str) -> dict[str, Any]:
    return {"facing": facing, "state": state, "ok": False}


def _capture_camera(facing: str, ok: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "facing": facing,
        "state": "success" if ok else "error",
        "ok": ok,
        "width": 320,
        "height": 240,
        "captureCompleted": ok,
        "yuvNonempty": ok,
        "jpegNonempty": ok,
        "timestampsMatched": ok,
    }
    if not ok:
        result["error"] = "camera returned an incomplete capture"
    return result


def _initial_camera_self_test() -> dict[str, Any]:
    return {
        "ok": False,
        "state": "error",
        "error": "camera self-test has not run",
        "cameras": {
            "back": _pending_camera("back", "notRun"),
            "front": _pending_camera("front", "notRun"),
        },
    }


def _running_camera_self_test(run_id: str) -> dict[str, Any]:
    return {
        "runId": run_id,
        "state": "running",
        "ok": False,
        "cameras": {
            "back": _pending_camera("back", "pending"),
            "front": _pending_camera("front", "pending"),
        },
    }


def _terminal_camera_self_test(run_id: str, succeeded: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "runId": run_id,
        "state": "success" if succeeded else "error",
        "ok": succeeded,
        "cameras": {
            "back": _capture_camera("back", succeeded),
            "front": _capture_camera("front", succeeded),
        },
    }
    if not succeeded:
        result["error"] = "one or more camera captures failed"
    return result


STATE = {
    "version": "0.1.0-mock",
    "root": True,
    "frida": False,
    "fingerprint": {
        "schema": "dev.xenoid.fingerprint/v1",
        "build": {"brand": "xenoid", "manufacturer": "Xenoid", "model": "MockDevice", "fingerprint": "xenoid/mock/mock:13/XENOID/1:userdebug/test-keys"},
        "ids": {"android_id": "0123456789abcdef", "boot_id": "00000000-0000-4000-8000-000000000000"},
        "battery": {"level": 88, "scale": 100, "temperature": 310},
        "sensors": [],
        "locale": "en-US",
        "timezone": "UTC",
    },
    "hide_policy": {},
    "ota": {"current": "0.1.0-mock", "channel": "mock", "updateAvailable": False},
    "camera": {
        "mode": "naturalized",
        "generation": 0,
        "active": False,
        "photoConfigured": False,
        "photoWidth": 0,
        "photoHeight": 0,
        "videoConfigured": False,
        "videoWidth": 0,
        "videoHeight": 0,
        "videoDurationMs": 0,
        "videoCodec": "",
        "videoRotation": 0,
        "lastError": "",
    },
    "cameraSelfTest": _initial_camera_self_test(),
    "cameraSelfTestSucceeds": True,
    "cameraSelfTestAuthorization": None,
}


def camera_status(ok: bool = True) -> dict[str, Any]:
    result = {"ok": ok, **STATE["camera"], "mock": True}
    if not ok:
        result["error"] = STATE["camera"]["lastError"]
    return result


def camera_failure(error: str) -> dict[str, Any]:
    STATE["camera"]["lastError"] = error
    return camera_status(False)


def response(path: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    if path == "/health":
        return {"ok": True, "service": "xenoid-mock-daemon", "version": STATE["version"]}
    if path == "/camera/status" and method == "GET":
        return camera_status()
    if path == "/camera/source" and method == "POST":
        if not isinstance(body, dict) or set(body) != {"kind", "stagingPath", "size", "sha256"}:
            return {"ok": False, "error": "invalid request schema"}
        kind = body["kind"]
        staging_path = body["stagingPath"]
        size = body["size"]
        digest = body["sha256"]
        valid = (
            kind in {"photo", "video"}
            and isinstance(staging_path, str)
            and re.fullmatch(r"/data/local/tmp/\.camera-upload-[0-9a-f]{32}", staging_path) is not None
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size > 0
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        )
        if not valid:
            return camera_failure("invalid camera source request")
        camera = STATE["camera"]
        camera["generation"] += 1
        camera["active"] = True
        camera["lastError"] = ""
        if kind == "photo":
            camera["photoConfigured"] = True
            camera["photoWidth"] = 944
            camera["photoHeight"] = 980
        else:
            camera["videoConfigured"] = True
            camera["videoWidth"] = 960
            camera["videoHeight"] = 540
            camera["videoDurationMs"] = 59840
            camera["videoCodec"] = "video/avc"
            camera["videoRotation"] = 0
        return camera_status()
    if path == "/camera/settings" and method == "POST":
        if not isinstance(body, dict) or set(body) != {"mode"}:
            return {"ok": False, "error": "invalid request schema"}
        mode = body["mode"]
        if mode not in {"naturalized", "faithful"}:
            return camera_failure("invalid camera mode")
        camera = STATE["camera"]
        camera["mode"] = mode
        camera["generation"] += 1
        camera["active"] = True
        camera["lastError"] = ""
        return camera_status()
    if path == "/camera/clear" and method == "POST":
        if not isinstance(body, dict) or set(body) != {"kind"}:
            return {"ok": False, "error": "invalid request schema"}
        kind = body["kind"]
        if kind not in {"photo", "video", "all"}:
            return camera_failure("invalid clear kind")
        camera = STATE["camera"]
        if kind in {"photo", "all"}:
            camera["photoConfigured"] = False
            camera["photoWidth"] = 0
            camera["photoHeight"] = 0
        if kind in {"video", "all"}:
            camera["videoConfigured"] = False
            camera["videoWidth"] = 0
            camera["videoHeight"] = 0
            camera["videoDurationMs"] = 0
            camera["videoCodec"] = ""
            camera["videoRotation"] = 0
        camera["generation"] += 1
        camera["active"] = True
        camera["lastError"] = ""
        return camera_status()
    if path == "/camera/apply" and method == "POST":
        if not isinstance(body, dict) or body:
            return {"ok": False, "error": "invalid request schema"}
        STATE["camera"]["active"] = True
        STATE["camera"]["lastError"] = ""
        return camera_status()
    if path == "/camera/self-test/start" and method == "POST":
        if not isinstance(body, dict) or set(body) != {"runId"}:
            return {"ok": False, "error": "invalid request schema"}
        run_id = body["runId"]
        if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
            return {"ok": False, "error": "invalid camera self-test run id"}
        STATE["cameraSelfTestAuthorization"] = run_id
        STATE["cameraSelfTest"] = _running_camera_self_test(run_id)
        return {"ok": True, "runId": run_id, "mock": True}
    if path == "/camera/self-test/status" and method == "GET":
        status = STATE["cameraSelfTest"]
        if status.get("state") == "running":
            run_id = status["runId"]
            STATE["cameraSelfTest"] = _terminal_camera_self_test(
                run_id, bool(STATE["cameraSelfTestSucceeds"])
            )
        return status
    if path == "/root/status":
        return {"ok": True, "root": STATE["root"], "stdout": "uid=0(root) gid=0(root) groups=0(root)\n"}
    if path == "/root/exec":
        return {"ok": True, "exit": 0, "stdout": f"mock exec: {body.get('command', '')}\n", "stderr": ""}
    if path == "/frida/start":
        STATE["frida"] = True
        return {"ok": True, "started": True, "port": body.get("port", 27042)}
    if path == "/frida/stop":
        STATE["frida"] = False
        return {"ok": True, "stopped": True}
    if path == "/frida/status":
        return {"ok": True, "running": STATE["frida"]}
    if path == "/profile/helper/status":
        return {"ok": True, "stdout": "{\"ok\":true,\"profileExists\":true}", "mock": True}
    if path == "/profile/helper/env":
        return {"ok": True, "stdout": json.dumps({"ok": True, "android_id": STATE["fingerprint"]["ids"]["android_id"], "boot_id": STATE["fingerprint"]["ids"]["boot_id"]}), "mock": True}
    if path == "/profile/helper/dump":
        return {"ok": True, "stdout": json.dumps(STATE["fingerprint"]), "mock": True}
    if path == "/fingerprint/collect":
        out = dict(STATE["fingerprint"])
        out["ok"] = True
        return out
    if path == "/fingerprint/apply":
        STATE["fingerprint"] = body.get("profile", body) or STATE["fingerprint"]
        return {"ok": True, "accepted": True, "regenerateUnique": body.get("regenerateUnique", True), "mock": True}
    if path == "/fingerprint/set":
        return {"ok": True, "field": body.get("field"), "value": body.get("value"), "applied": True, "mock": True}
    if path == "/automation/run":
        return {"ok": True, "taskId": f"mock-{int(time.time())}", "language": body.get("language", "js"), "parsedActions": body.get("script", "").count("xenoid."), "mock": True}
    if path == "/input/tap":
        return {"ok": True, "driverLayer": True, "x": body.get("x"), "y": body.get("y"), "mock": True}
    if path == "/input/swipe":
        return {"ok": True, "driverLayer": True, **body, "mock": True}
    if path == "/app/install":
        return {"ok": True, "path": body.get("path"), "mock": True}
    if path == "/app/uninstall":
        return {"ok": True, "package": body.get("package"), "mock": True}
    if path == "/app/launch":
        return {"ok": True, "component": body.get("component"), "mock": True}
    if path == "/hide/status":
        return {"ok": True, "active": True, "policy": STATE["hide_policy"], "native": {"ok": True, "mock": True}}
    if path == "/hide/apply":
        STATE["hide_policy"] = body.get("policy", body)
        return {"ok": True, "accepted": True, "mock": True}
    if path == "/ota/check":
        return {"ok": True, **STATE["ota"]}
    if path == "/ota/apply":
        STATE["ota"]["channel"] = body.get("channel", "mock")
        return {"ok": True, "staged": True, "channel": STATE["ota"]["channel"], "mock": True}
    return {"ok": False, "error": "not found", "path": path, "method": method}


class Handler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(n).decode() if n else "{}"
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {"raw": raw}
        data = json.dumps(response(self.path, self.command, body), ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None: self._handle()
    def do_POST(self) -> None: self._handle()
    def log_message(self, fmt: str, *args: Any) -> None: return


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18765)
    args = ap.parse_args(argv)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(json.dumps({"ok": True, "mockDaemon": f"http://{args.host}:{args.port}"}), flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
