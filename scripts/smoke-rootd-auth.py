#!/usr/bin/env python3
"""Smoke: xenoid-rootd token auth (source + optional host/runtime).

Proves unauthenticated /exec -> 401 and authenticated /exec -> 200.
Host runtime compiles the same C source with the system compiler when available.
Pass --live to also hit the container rootd (brief restart via ensure path).
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "native" / "xenoid-rootd" / "xenoid_rootd.c"
HELPER = ROOT / "daemon" / "app" / "src" / "main" / "java" / "dev" / "xenoid" / "daemon" / "RootHelper.java"
BACKEND = ROOT / "src" / "xenoid" / "backend.py"


def source_checks() -> dict:
    c = SRC.read_text()
    java = HELPER.read_text()
    py = BACKEND.read_text()
    needles = {
        "c_token_env": "XENOID_ROOTD_TOKEN" in c,
        "c_token_file": "/data/local/tmp/.xenoid-rootd.token" in c,
        "c_header": "x-xenoid-token" in c.lower() or "X-Xenoid-Token" in c,
        "c_401": "401" in c and "unauthorized" in c,
        "c_loopback": "INADDR_LOOPBACK" in c,
        "c_exec_auth": "authorized" in c and "/exec" in c,
        "java_header": "X-Xenoid-Token" in java,
        "java_token_private": "setRootdToken" in java and "/data/local/tmp/.xenoid-rootd.token" not in java,
        "java_no_su_fallback": "su -c" not in java and "which su" not in java,
        "backend_provision": "XENOID_ROOTD_TOKEN" in py and ".xenoid-rootd.token" in py,
        "backend_reuse_daemon_token": "daemon.token" in py and "ensure_rootd_root" in py,
    }
    missing = [k for k, v in needles.items() if not v]
    return {"ok": not missing, "missing": missing, "checks": needles}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(port: int, path: str, headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.getcode(), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def host_runtime_checks() -> dict:
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        return {"ok": True, "skipped": True, "reason": "no host C compiler"}
    token = "smoke-rootd-token-" + str(os.getpid())
    port = free_port()
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td)
        bin_path = t / "xenoid-rootd-host"
        r = subprocess.run([cc, "-O2", "-o", str(bin_path), str(SRC)], capture_output=True, text=True)
        if r.returncode != 0:
            return {"ok": False, "error": "host compile failed", "stderr": r.stderr[-500:]}
        env = os.environ.copy()
        env["XENOID_ROOTD_TOKEN"] = token
        proc = subprocess.Popen([str(bin_path), str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    code_h, body_h = http(port, "/")
                    if code_h == 200:
                        break
                except Exception:
                    time.sleep(0.05)
            else:
                return {"ok": False, "error": "rootd did not become ready"}

            code_unauth, body_unauth = http(port, "/exec?cmd=id")
            code_auth, body_auth = http(port, "/exec?cmd=id", {"X-Xenoid-Token": token})
            code_bad, body_bad = http(port, "/exec?cmd=id", {"X-Xenoid-Token": "wrong"})
            code_q, body_q = http(port, f"/exec?cmd=id&token={token}")

            ok = (
                code_unauth == 401
                and "unauthorized" in body_unauth
                and code_auth == 200
                and '"ok":true' in body_auth
                and code_bad == 401
                and code_q == 401
                and code_h == 200
            )
            return {
                "ok": ok,
                "health": {"code": code_h, "body": body_h.strip()[:80]},
                "unauth": {"code": code_unauth, "body": body_unauth.strip()[:120]},
                "auth": {"code": code_auth, "body": body_auth.strip()[:160]},
                "badToken": {"code": code_bad, "body": body_bad.strip()[:80]},
                "queryToken": {"code": code_q, "body": body_q.strip()[:80]},
                "port": port,
            }
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def live_container_checks() -> dict:
    if not shutil.which("docker"):
        return {"ok": True, "skipped": True, "reason": "docker not found"}
    try:
        sys.path.insert(0, str(ROOT / "src"))
        from xenoid.backend import RuntimeManager
        from xenoid.config import resolve_instance
        context, cfg, lease = resolve_instance(project_root=ROOT)
        rm = RuntimeManager(context, cfg, lease)
        prov = rm.ensure_rootd_root()
        if not prov.get("ok"):
            return {"ok": False, "error": "ensure_rootd_root failed", "prov": prov}

        unauth = rm.docker_exec(["sh", "-c",
            '(printf "GET /exec?cmd=id HTTP/1.0\r\n\r\n"; sleep 0.3) | toybox nc 127.0.0.1 18767'], timeout=10)
        auth = rm.docker_exec(["sh", "-c",
            'TOK=$(cat /data/local/tmp/.xenoid-rootd.token); '
            '(printf "GET /exec?cmd=id HTTP/1.0\r\nX-Xenoid-Token: %s\r\n\r\n" "$TOK"; sleep 0.3) | '
            'toybox nc 127.0.0.1 18767'], timeout=10)
        bu = str(unauth.get("stdout", ""))
        ba = str(auth.get("stdout", ""))
        ok = ("401" in bu and "unauthorized" in bu and "200" in ba and "uid=0" in ba)
        return {
            "ok": ok,
            "unauth": {"body": bu[:220]},
            "auth": {"body": ba[:220]},
            "prov": {k: prov.get(k) for k in ("ok", "listening", "runsAsRoot", "tokenProvisioned", "arch")},
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}



def main() -> int:
    live = "--live" in sys.argv
    src = source_checks()
    host = host_runtime_checks()
    result = {"ok": bool(src.get("ok") and host.get("ok")), "source": src, "hostRuntime": host}
    if live:
        live_r = live_container_checks()
        result["live"] = live_r
        result["ok"] = bool(result["ok"] and live_r.get("ok"))
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
