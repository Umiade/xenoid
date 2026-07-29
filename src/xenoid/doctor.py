from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .backend import RuntimeManager
from .config import XenoidConfig
from .daemon_client import DaemonClient

ROOT = Path(__file__).resolve().parents[2]
XENOID = ROOT / "xenoid" if (ROOT / "xenoid").exists() else ROOT / "bin" / "xenoid"


def _run(command: list[str], *, timeout: int = 180, env: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except Exception as exc:
        return {"ok": False, "command": command, "error": str(exc)}

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    result: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "command": command,
        "returncode": proc.returncode,
    }
    if stdout:
        try:
            result["data"] = json.loads(stdout)
        except json.JSONDecodeError:
            result["stdout"] = stdout[-4000:]
    if stderr:
        result["stderr"] = stderr[-4000:]
    return result


def _summary(name: str, section: dict[str, Any]) -> dict[str, Any]:
    summary = {"name": name, "ok": bool(section.get("ok"))}
    if section.get("skipped"):
        summary["skipped"] = True
    if section.get("reason"):
        summary["reason"] = section["reason"]
    return summary


def build_doctor_report(
    cfg: XenoidConfig,
    *,
    full: bool = False,
    require_runtime: bool = False,
) -> dict[str, Any]:
    manager = RuntimeManager(cfg)
    host_checks = [asdict(check) for check in manager.doctor()]
    host_ok = all(check["ok"] or check["name"] == "scrcpy" for check in host_checks)
    host = {"ok": host_ok, "checks": host_checks}

    preflight = manager.runtime_preflight()
    preflight["ok"] = bool(preflight.get("ok"))

    verify_env = dict(os.environ)
    verify_env["XENOID_SKIP_AUDIT"] = "1"
    verification = _run([str(ROOT / "scripts" / "verify.sh")], timeout=180, env=verify_env)

    status = manager.status()
    running = bool(status.get("ok") and status.get("running"))
    runtime: dict[str, Any] = {
        "ok": not require_runtime,
        "running": running,
        "status": status,
    }
    runtime_ready = False
    if running:
        connect = manager.adb_connect()
        boot = manager.adb(["shell", "getprop", "sys.boot_completed"])
        boot_ok = bool(boot.get("ok") and "1" in str(boot.get("stdout") or ""))
        forward = manager.forward_daemon_port()
        daemon = DaemonClient(port=cfg.daemon_port)
        health = daemon.health()
        root = daemon.root_status() if health.get("ok") else {"ok": False, "skipped": True}
        runtime_ready = bool(connect.get("ok") and boot_ok and forward.get("ok") and health.get("ok") and root.get("ok"))
        runtime.update({
            "ok": runtime_ready,
            "adbConnect": connect,
            "bootCompleted": boot,
            "daemonForward": forward,
            "daemonHealth": health,
            "rootStatus": root,
        })
    else:
        runtime.update({"skipped": True, "reason": "Android runtime is not running"})

    protection: dict[str, Any] = {
        "ok": not require_runtime,
        "skipped": True,
        "reason": "Android runtime is not ready",
    }
    if runtime_ready:
        kernel_module = manager.kernel_module_status()
        ebpf = manager.ebpf_status()
        image = manager.image_protection_status()
        hide = DaemonClient(port=cfg.daemon_port).hide_status()
        protection = {
            "ok": all(bool(step.get("ok")) for step in (kernel_module, ebpf, image, hide)),
            "kernelModule": kernel_module,
            "ebpf": ebpf,
            "image": image,
            "android": hide,
        }

    sections: dict[str, dict[str, Any]] = {
        "host": host,
        "preflight": preflight,
        "verification": verification,
        "runtime": runtime,
        "protection": protection,
    }

    if full:
        sections["build"] = _run([str(XENOID), "build", "all"], timeout=900)
        sections["ota"] = _run([str(XENOID), "ota", "make", "--version", "doctor"], timeout=300)
        sections["runtimeContext"] = _run([str(XENOID), "runtime-context"], timeout=300)
        sections["hookSurfaces"] = _run(["python3", "scripts/smoke-hook-surfaces.py"], timeout=180)
        if runtime_ready:
            sections["runtimeSmoke"] = _run(
                [str(ROOT / "scripts" / "smoke-runtime.sh"), "/tmp/xenoid-doctor-runtime.json"],
                timeout=360,
            )
        else:
            sections["runtimeSmoke"] = {
                "ok": not require_runtime,
                "skipped": True,
                "reason": "Android runtime is not ready",
            }

    checks = [_summary(name, section) for name, section in sections.items()]
    ok = all(check["ok"] for check in checks)
    complete = bool(ok and runtime_ready and (not full or sections["runtimeSmoke"].get("ok")))
    next_actions: list[str] = []
    if not host_ok or not preflight.get("ok"):
        next_actions.append("./xenoid install-runtime")
    if not running:
        next_actions.append("./xenoid up")
    elif not runtime_ready:
        next_actions.extend(["./xenoid logs", "./xenoid daemon health"])
    if not protection.get("ok") and running:
        next_actions.append("./xenoid up")
    if full and not sections["runtimeSmoke"].get("ok"):
        next_actions.append("./xenoid doctor --full --require-runtime")

    if not ok and not next_actions:
        next_actions.append("./xenoid doctor --full" if full else "./xenoid doctor")

    return {
        "schema": "dev.xenoid.doctor/v1",
        "ok": ok,
        "complete": complete,
        "full": full,
        "runtimeRequired": require_runtime,
        "runtimeAvailable": running,
        "checks": checks,
        "sections": sections,
        "nextActions": list(dict.fromkeys(next_actions)),
    }
