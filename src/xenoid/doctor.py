from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .backend import RuntimeManager
from .config import InstanceContext, InstanceLease, XenoidConfig
from .daemon_client import DaemonClient



_PROXY_CAPABILITY_KEYS = {
    "v4DnsProxy",
    "v4TcpProxy",
    "v4UdpProxy",
    "v6DnsProxy",
    "v6TcpProxy",
    "v6UdpProxy",
}


def _proxy_capabilities_ready(value: Any, udp_allowed: bool) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _PROXY_CAPABILITY_KEYS
        and all(isinstance(value.get(key), bool) for key in _PROXY_CAPABILITY_KEYS)
        and value.get("v4DnsProxy") is True
        and value.get("v6DnsProxy") is True
        and value.get("v4TcpProxy") is True
        and value.get("v6TcpProxy") is True
        and value.get("v4UdpProxy") is udp_allowed
        and (udp_allowed or value.get("v6UdpProxy") is False)
    )


def _run(
    command: list[str],
    *,
    timeout: int = 180,
    env: dict[str, str] | None = None,
    cwd: Path,
) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
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
    context: InstanceContext,
    cfg: XenoidConfig,
    lease: InstanceLease,
    *,
    full: bool = False,
    require_runtime: bool = False,
) -> dict[str, Any]:
    manager = RuntimeManager(context, cfg, lease)
    host_checks = [asdict(check) for check in manager.doctor()]
    host_ok = all(check["ok"] or check["name"] == "scrcpy" for check in host_checks)
    host = {"ok": host_ok, "checks": host_checks}

    preflight = manager.runtime_preflight()
    preflight["ok"] = bool(preflight.get("ok"))
    storage = manager.storage_status()
    storage["ok"] = bool(storage.get("ok"))


    instance_env = {
        **os.environ,
        "XENOID_PROJECT": str(context.project_root),
        "XENOID_INSTANCE": context.instance_name,
    }
    verify_env = {**instance_env, "XENOID_SKIP_AUDIT": "1"}
    verification = _run(
        [str(context.project_root / "scripts" / "verify.sh")],
        timeout=180,
        env=verify_env,
        cwd=context.project_root,
    )

    status = manager.status()
    running = bool(status.get("ok") and status.get("running"))
    google_services = status.get("googleServices")
    if not isinstance(google_services, dict):
        google_services = manager.google_services_status(
            require_runtime=require_runtime,
        )
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
        daemon = DaemonClient(
            context,
            lease,
            manager.docker_base_cmd(),
        )
        health = daemon.health()
        root = daemon.root_status() if health.get("ok") else {"ok": False, "skipped": True}
        sentinel = (
            manager.data_sentinel(create=False)
            if root.get("ok")
            else {"ok": False, "skipped": True}
        )
        runtime_ready = bool(
            connect.get("ok")
            and boot_ok
            and forward.get("ok")
            and health.get("ok")
            and root.get("ok")
            and sentinel.get("ok")
        )
        runtime.update({
            "ok": runtime_ready,
            "adbConnect": connect,
            "bootCompleted": boot,
            "daemonForward": forward,
            "daemonHealth": health,
            "rootStatus": root,
            "dataSentinel": sentinel,
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
        hide = daemon.hide_status()
        protection = {
            "ok": all(bool(step.get("ok")) for step in (kernel_module, ebpf, image, hide)),
            "kernelModule": kernel_module,
            "ebpf": ebpf,
            "image": image,
            "android": hide,
        }
    proxy: dict[str, Any] = {
        "ok": not require_runtime,
        "skipped": True,
        "reason": "Android runtime is not ready",
    }
    if runtime_ready:
        daemon_proxy = daemon.proxy_status()
        engine_proxy = manager.proxy_engine_status()
        enabled = daemon_proxy.get("enabled")
        generation = daemon_proxy.get("generation")
        check_id = daemon_proxy.get("checkId")
        epoch = daemon_proxy.get("runtimeEpoch")
        udp_allowed = daemon_proxy.get("udpAllowed")
        identity_ok = (
            daemon_proxy.get("ok") is True
            and isinstance(enabled, bool)
            and isinstance(generation, int)
            and not isinstance(generation, bool)
            and generation >= 0
            and isinstance(epoch, str)
            and bool(epoch)
            and isinstance(udp_allowed, bool)
            and daemon_proxy.get("instanceId") == context.instance_id
            and engine_proxy.get("ok") is True
            and engine_proxy.get("instanceId") == context.instance_id
            and engine_proxy.get("resourceTag") == context.resource_tag
            and engine_proxy.get("runtimeEpoch") == epoch
            and engine_proxy.get("generation") == generation
        )
        if enabled is True:
            report = daemon_proxy.get("report")
            probe = daemon_proxy.get("probe")
            ready = (
                identity_ok
                and isinstance(check_id, int)
                and not isinstance(check_id, bool)
                and check_id > 0
                and isinstance(report, dict)
                and report.get("generation") == generation
                and report.get("checkId") == check_id
                and report.get("phase") == "active"
                and report.get("structuralApplied") is True
                and report.get("dataPlaneVerified") is True
                and report.get("errorCode", "") == ""
                and _proxy_capabilities_ready(report.get("capabilities"), udp_allowed)
                and isinstance(probe, dict)
                and probe.get("checkId") == check_id
                and probe.get("errorCode") == ""
                and _proxy_capabilities_ready(probe.get("capabilities"), udp_allowed)
                and engine_proxy.get("phase") == "active"
                and engine_proxy.get("structuralApplied") is True
            )
        else:
            ready = (
                identity_ok
                and engine_proxy.get("phase") == "off"
                and engine_proxy.get("structuralApplied") is True
                and engine_proxy.get("dataPlaneVerified") is True
            )
        proxy = {
            "ok": bool(ready),
            "enabled": enabled,
            "daemon": daemon_proxy,
            "engine": engine_proxy,
        }


    sections: dict[str, dict[str, Any]] = {
        "host": host,
        "preflight": preflight,
        "storage": storage,
        "verification": verification,
        "runtime": runtime,
        "protection": protection,
        "proxy": proxy,
        "googleServices": google_services,
    }

    if full:
        xenoid = context.project_root / "xenoid"
        if not xenoid.exists():
            xenoid = context.project_root / "bin" / "xenoid"
        selected_cli = [str(xenoid), "--instance", context.instance_name]
        sections["build"] = _run(
            [*selected_cli, "build", "all"],
            timeout=900,
            env=instance_env,
            cwd=context.project_root,
        )
        sections["ota"] = _run(
            [*selected_cli, "ota", "make", "--version", "doctor"],
            timeout=300,
            env=instance_env,
            cwd=context.project_root,
        )
        sections["runtimeContext"] = _run(
            [*selected_cli, "runtime-context"],
            timeout=300,
            env=instance_env,
            cwd=context.project_root,
        )
        sections["hookSurfaces"] = _run(
            ["python3", "scripts/smoke-hook-surfaces.py"],
            timeout=180,
            env=instance_env,
            cwd=context.project_root,
        )
        if runtime_ready:
            sections["runtimeSmoke"] = _run(
                [str(context.project_root / "scripts" / "smoke-runtime.sh"), "/tmp/xenoid-doctor-runtime.json"],
                timeout=360,
                env=instance_env,
                cwd=context.project_root,
            )
        else:
            sections["runtimeSmoke"] = {
                "ok": not require_runtime,
                "skipped": True,
                "reason": "Android runtime is not ready",
            }
        if cfg.google_services_provider != "none":
            sections["googleServicesSmoke"] = (
                _run(
                    [
                        str(
                            context.project_root
                            / "scripts"
                            / "smoke-google-services-runtime.sh"
                        ),
                        "--instance",
                        context.instance_name,
                    ],
                    timeout=600,
                    env=instance_env,
                    cwd=context.project_root,
                )
                if runtime_ready
                else {
                    "ok": False,
                    "skipped": True,
                    "reason": "Android runtime is not ready",
                }
            )

    checks = [_summary(name, section) for name, section in sections.items()]
    ok = all(check["ok"] for check in checks)
    complete = bool(ok and runtime_ready and (not full or sections["runtimeSmoke"].get("ok")))
    next_actions: list[str] = []
    selected = f"./xenoid --instance {context.instance_name}"
    if not host_ok or not preflight.get("ok"):
        next_actions.append(f"{selected} install-runtime")
    if not running:
        next_actions.append(f"{selected} up")
    elif not runtime_ready:
        next_actions.extend([f"{selected} logs", f"{selected} daemon health"])
    if not protection.get("ok") and running:
        next_actions.append(f"{selected} up")
    if full and not sections["runtimeSmoke"].get("ok"):
        next_actions.append(f"{selected} doctor --full --require-runtime")
    if (
        cfg.google_services_provider != "none"
        and not google_services.get("ok")
    ):
        next_actions.append(
            f"{selected} google-services status --require-runtime"
        )

    if not ok and not next_actions:
        next_actions.append(f"{selected} doctor {'--full' if full else ''}".rstrip())

    return {
        "instance": {
            **context.public_dict(),
            "slot": lease.slot,
            "leaseState": lease.state,
        },
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
