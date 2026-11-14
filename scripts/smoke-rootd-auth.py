#!/usr/bin/env python3
"""Smoke the bounded stdin-token xenoid-rootd protocol.

The default host scenario compiles and starts the native daemon against a
private temporary run directory. Pass --live to additionally exercise the
container's shared RuntimeManager bootstrap path.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import stat
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "native" / "xenoid-rootd" / "xenoid_rootd.c"
TOKEN = "0123456789abcdef0123456789abcdef"
REQUEST_ID = "abcdef0123456789abcdef0123456789"




def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def http(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            code = response.status
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        code = error.code
        raw = error.read(65537)
    value = json.loads(raw.decode("utf-8"))
    return code, value


def exec_headers(token: str = TOKEN, request_id: str = REQUEST_ID) -> dict[str, str]:
    return {
        "Content-Type": "text/plain; charset=utf-8",
        "X-Xenoid-Token": token,
        "X-Xenoid-Request-Id": request_id,
        "X-Xenoid-Timeout-Ms": "1000",
    }


def wait_ready(port: int, record: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any]]:
    deadline = time.monotonic() + 5
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            code, health = http(port, "GET", "/health")
            if code == 200 and record.is_file():
                process = json.loads(record.read_text(encoding="utf-8"))
                return health, process
        except (OSError, ValueError, json.JSONDecodeError) as error:
            last = error
        time.sleep(0.05)
    raise RuntimeError(f"rootd did not become ready: {type(last).__name__ if last else 'timeout'}")


def terminate_recorded_process(
    record: pathlib.Path,
    expected: dict[str, Any] | None,
    binary: pathlib.Path,
) -> None:
    try:
        metadata = record.lstat()
        value = json.loads(record.read_text(encoding="utf-8"))
        pid = value.get("pid")
        if (
            expected is None
            or value != expected
            or set(value) != {"schema", "pid", "startTime"}
            or value.get("schema") != "dev.xenoid.rootd-process/v1"
            or not isinstance(pid, int)
            or pid <= 1
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            return
        identity = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if identity.returncode != 0 or str(binary) not in identity.stdout:
            return
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not record.exists():
                return
            time.sleep(0.05)
        if record.read_text(encoding="utf-8") == json.dumps(
            expected, separators=(",", ":")
        ) + "\n":
            os.kill(pid, signal.SIGKILL)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError):
        pass


def host_runtime_checks() -> dict[str, Any]:
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        return {"ok": True, "skipped": True, "reason": "no host C compiler"}
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="xenoid-rootd-smoke-") as directory:
        root = pathlib.Path(directory)
        binary = root / "xenoid-rootd-host"
        run_dir = root / "run"
        record = run_dir / "process.json"
        build = subprocess.run(
            [
                cc,
                "-O2",
                "-pthread",
                "-o",
                str(binary),
                str(SRC),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if build.returncode != 0:
            return {"ok": False, "error": "host_compile_failed", "returncode": build.returncode}
        launcher = subprocess.Popen(
            [str(binary), str(port), str(run_dir)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process: dict[str, Any] | None = None
        try:
            if launcher.stdin is None:
                return {"ok": False, "error": "rootd_stdin_unavailable"}
            launcher.stdin.write((TOKEN + "\n").encode("ascii"))
            launcher.stdin.flush()
            launcher.stdin.close()
            health, process = wait_ready(port, record)
            unauth_code, unauth = http(
                port, "POST", "/exec", body=b"id", headers={
                    key: value for key, value in exec_headers().items()
                    if key != "X-Xenoid-Token"
                },
            )
            wrong_code, wrong = http(
                port, "POST", "/exec", body=b"id", headers=exec_headers("f" * 32)
            )
            get_code, get_result = http(port, "GET", "/exec")
            query_code, query_result = http(
                port, "POST", "/exec?cmd=id", body=b"id", headers=exec_headers()
            )
            bad_id_code, bad_id = http(
                port, "POST", "/exec", body=b"id", headers=exec_headers(request_id="A" * 32)
            )
            auth_code, auth = http(
                port, "POST", "/exec", body=b"id", headers=exec_headers()
            )
            ok = (
                health == {"ok": True, "schema": "dev.xenoid.rootd/v1", "service": "xenoid-rootd"}
                and set(process) == {"schema", "pid", "startTime"}
                and process["schema"] == "dev.xenoid.rootd-process/v1"
                and isinstance(process["pid"], int)
                and isinstance(process["startTime"], int)
                and unauth_code == wrong_code == 401
                and unauth.get("errorCode") == wrong.get("errorCode") == "rootd_unauthorized"
                and get_code == 405
                and get_result.get("errorCode") == "rootd_method_not_allowed"
                and query_code == 404
                and query_result.get("errorCode") == "rootd_not_found"
                and bad_id_code == 400
                and bad_id.get("errorCode") == "rootd_bad_request"
                and auth_code == 200
                and auth.get("schema") == "dev.xenoid.rootd-exec/v1"
                and auth.get("requestId") == REQUEST_ID
                and isinstance(auth.get("ok"), bool)
                and isinstance(auth.get("exitCode"), int)
                and isinstance(auth.get("stdout"), str)
                and set(auth).issubset({"ok", "schema", "requestId", "exitCode", "stdout", "errorCode"})
            )
            rendered = json.dumps({
                "health": health,
                "process": process,
                "unauthorized": unauth,
                "wrongToken": wrong,
                "getExec": get_result,
                "queryExec": query_result,
                "badRequestId": bad_id,
                "authenticated": auth,
            }, sort_keys=True)
            ok = ok and TOKEN not in rendered
            return {
                "ok": ok,
                "health": health,
                "processRecord": {"schema": process.get("schema"), "present": True},
                "unauthorized": {"code": unauth_code, "errorCode": unauth.get("errorCode")},
                "wrongToken": {"code": wrong_code, "errorCode": wrong.get("errorCode")},
                "getExec": {"code": get_code, "errorCode": get_result.get("errorCode")},
                "queryExec": {"code": query_code, "errorCode": query_result.get("errorCode")},
                "badRequestId": {"code": bad_id_code, "errorCode": bad_id.get("errorCode")},
                "authenticated": {
                    "code": auth_code,
                    "ok": auth.get("ok"),
                    "schema": auth.get("schema"),
                    "requestIdMatched": auth.get("requestId") == REQUEST_ID,
                    "errorCode": auth.get("errorCode"),
                },
            }
        finally:
            terminate_recorded_process(record, process, binary)
            if launcher.poll() is None:
                launcher.kill()
                launcher.wait(timeout=2)


def live_container_checks() -> dict[str, Any]:
    if not shutil.which("docker"):
        return {"ok": True, "skipped": True, "reason": "docker not found"}
    try:
        sys.path.insert(0, str(ROOT / "src"))
        from xenoid.backend import RuntimeManager
        from xenoid.config import resolve_instance

        context, cfg, lease = resolve_instance(project_root=ROOT)
        manager = RuntimeManager(context, cfg, lease)
        bootstrap = manager.reconcile_bootstrap()
        root = manager.daemon_client().root_status() if bootstrap.get("transportReady") else {
            "ok": False, "error": "daemon_transport_unavailable"
        }
        return {
            "ok": bool(bootstrap.get("transportReady") and root.get("ok")),
            "bootstrap": {
                key: bootstrap.get(key)
                for key in ("ok", "state", "generation", "errorCode", "transportReady")
            },
            "root": {"ok": root.get("ok"), "error": root.get("error")},
        }
    except Exception as error:
        return {"ok": False, "error": type(error).__name__}


def main() -> int:
    host_result = host_runtime_checks()
    result: dict[str, Any] = {
        "ok": bool(host_result.get("ok")),
        "hostRuntime": host_result,
    }
    if "--live" in sys.argv:
        live = live_container_checks()
        result["live"] = live
        result["ok"] = bool(result["ok"] and live.get("ok"))
    rendered = json.dumps(result, sort_keys=True)
    if TOKEN in rendered:
        result = {"ok": False, "error": "secret_in_result"}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
