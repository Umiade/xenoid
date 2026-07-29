from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

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
}


def response(path: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    if path == "/health":
        return {"ok": True, "service": "xenoid-mock-daemon", "version": STATE["version"]}
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
