from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Optional

from .backend import RuntimeManager
from .config import (
    InstanceContext,
    InstanceError,
    InstanceLease,
    XenoidConfig,
    resolve_instance,
)
from .daemon_client import DaemonClient
from .doctor import build_doctor_report
from .device_identity import (
    DeviceIdentityStore,
    converge_instance_identity,
    identity_field_key,
    public_identity_state,
    validate_identity_value,
)
from .proxy_controller import ProxyController
from .util import read_json_file
@dataclass(frozen=True)
class MCPRuntime:
    context: InstanceContext
    config: XenoidConfig
    lease: InstanceLease
    manager: RuntimeManager
    daemon: DaemonClient

    @classmethod
    def resolve(cls) -> "MCPRuntime":
        context, config, lease = resolve_instance()
        manager = RuntimeManager(context, config, lease)
        daemon = DaemonClient(context, lease, manager.docker_base_cmd())
        return cls(context, config, lease, manager, daemon)

    @property
    def subprocess_env(self) -> dict[str, str]:
        return {
            **os.environ,
            "XENOID_PROJECT": str(self.context.project_root),
            "XENOID_INSTANCE": self.context.instance_name,
        }




def respond(id_: Any, result: Any = None, error: Any = None) -> None:
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def tool(name: str, description: str, properties: Optional[dict[str, Any]] = None, required: Optional[list[str]] = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema}


def tools() -> list[dict[str, Any]]:
    return [
        tool(
            "xenoid_doctor",
            "Check installation, host dependencies, and the live runtime",
            {"full": {"type": "boolean"}, "requireRuntime": {"type": "boolean"}},
        ),
        tool("xenoid_verify_release", "Verify a Xenoid release bundle", {"archive": {"type": "string"}}, ["archive"]),
        tool("xenoid_package_release", "Package transferable Xenoid release bundle", {"version": {"type": "string"}}),
        tool("xenoid_runtime_context", "Create custom redroid Docker build context with Xenoid payloads", {"image": {"type": "string"}}),
        tool("xenoid_linux_binderfs", "Run/dry-run Linux binderfs setup", {"dryRun": {"type": "boolean"}}),
        tool("xenoid_runtime_build_image", "Build or dry-run custom redroid Docker image", {"image": {"type": "string"}, "tag": {"type": "string"}, "dryRun": {"type": "boolean"}}),
        tool("xenoid_config_show", "Show Xenoid config"),
        tool("xenoid_install_runtime_plan", "Dry-run macOS runtime dependency install plan"),
        tool("xenoid_up_plan", "Dry-run full Xenoid startup plan"),
        tool("xenoid_start", "Start the low-level Android runtime without full Xenoid state convergence", {"dryRun": {"type": "boolean"}, "startColima": {"type": "boolean"}, "installDaemonApk": {"type": "string"}, "adbRoot": {"type": "boolean"}, "recreate": {"type": "boolean"}}),
        tool("xenoid_stop", "Stop Xenoid Android runtime"),
        tool("xenoid_logs", "Collect Docker/ADB runtime logs", {"outDir": {"type": "string"}}),
        tool("xenoid_view", "Open scrcpy for Xenoid Android target"),
        tool("xenoid_status", "Get runtime status"),
        tool("xenoid_daemon_health", "Check Android daemon health"),
        tool("xenoid_daemon_ensure", "Ensure Android daemon API is reachable"),
        tool("xenoid_daemon_install", "Install and start daemon APK", {"apk": {"type": "string"}}, ["apk"]),
        tool("xenoid_proxy_status", "Show redacted proxy status for the fixed instance"),
        tool("xenoid_proxy_check", "Run a fresh instance/runtime-bound proxy check"),
        tool("xenoid_proxy_on", "Enable the fixed instance configured proxy source"),
        tool("xenoid_proxy_off", "Disable proxying while preserving the fixed instance source"),
        tool("xenoid_proxy_clear", "Disable and clear the fixed instance proxy source"),
        tool(
            "xenoid_proxy_select",
            "Select a proxy node for the fixed instance",
            {"name": {"type": "string"}},
            ["name"],
        ),
        tool("xenoid_location_list", "List supported device location countries without contacting the runtime"),
        tool("xenoid_location_status", "Show masked host and Android location identity state", {"check": {"type": "boolean"}}),
        tool(
            "xenoid_location_set",
            "Select the device location country and converge SIM, carrier, LTE cell, locale, and timezone",
            {"countryCode": {"type": "string"}},
            ["countryCode"],
        ),
        tool("xenoid_root_status", "Check daemon root/su helper status"),
        tool("xenoid_root_exec", "Run command through daemon root helper", {"command": {"type": "string"}}, ["command"]),
        tool("xenoid_frida_install", "Download and deploy frida-server", {"version": {"type": "string"}, "arch": {"type": "string"}, "outDir": {"type": "string"}, "remotePath": {"type": "string"}}),
        tool("xenoid_frida_fetch", "Download frida-server release asset", {"version": {"type": "string"}, "arch": {"type": "string"}, "outDir": {"type": "string"}}),
        tool("xenoid_frida_deploy", "Deploy frida-server to Android", {"path": {"type": "string"}, "remotePath": {"type": "string"}}, ["path"]),
        tool("xenoid_frida_deploy_scripts", "Deploy Xenoid Frida JS scripts to Android", {"scriptsDir": {"type": "string"}, "remoteDir": {"type": "string"}}),
        tool("xenoid_frida_load_script", "Load a Frida JS script into a package/process", {"package": {"type": "string"}, "script": {"type": "string"}, "spawn": {"type": "boolean"}}, ["package", "script"]),
        tool("xenoid_frida_start", "Start frida-server through daemon", {"port": {"type": "integer"}}),
        tool("xenoid_frida_stop", "Stop frida-server through daemon"),
        tool("xenoid_frida_status", "Check frida-server status through daemon"),
        tool("xenoid_input_deploy", "Deploy native /dev/uinput helper", {"path": {"type": "string"}, "remotePath": {"type": "string"}}, ["path"]),
        tool("xenoid_input_tap", "Tap using daemon low-level input API", {"x": {"type": "integer"}, "y": {"type": "integer"}}, ["x", "y"]),
        tool("xenoid_input_swipe", "Swipe using daemon low-level input API", {"x1": {"type": "integer"}, "y1": {"type": "integer"}, "x2": {"type": "integer"}, "y2": {"type": "integer"}, "durationMs": {"type": "integer"}}, ["x1", "y1", "x2", "y2"]),
        tool("xenoid_profile_deploy_helper", "Deploy native xenoid-profile helper", {"path": {"type": "string"}, "remotePath": {"type": "string"}}, ["path"]),
        tool("xenoid_profile_helper_status", "Query native profile helper status through daemon"),
        tool("xenoid_profile_helper_env", "Query native profile helper env summary through daemon"),
        tool("xenoid_profile_helper_dump", "Dump staged effective profile through daemon"),
        tool("xenoid_device_collect", "Collect Android device fingerprint through daemon"),
        tool("xenoid_device_apply", "Apply device fingerprint profile through daemon", {"profilePath": {"type": "string"}, "regenerateUnique": {"type": "boolean"}}, ["profilePath"]),
        tool("xenoid_device_generate_frida", "Generate Frida profile spoof script from fingerprint profile", {"profilePath": {"type": "string"}, "out": {"type": "string"}, "keepUnique": {"type": "boolean"}}, ["profilePath"]),
        tool("xenoid_device_generate_service_frida", "Generate service/system Frida spoof script from fingerprint profile", {"profilePath": {"type": "string"}, "out": {"type": "string"}, "keepUnique": {"type": "boolean"}}, ["profilePath"]),
        tool("xenoid_device_set", "Set one fingerprint field through daemon", {"field": {"type": "string"}, "value": {}}, ["field", "value"]),
        tool("xenoid_automation_plan", "Parse Xenoid JS automation task into ordered calls", {"scriptPath": {"type": "string"}}, ["scriptPath"]),
        tool("xenoid_automation_run_host", "Run/plan Xenoid JS automation task with host JS runner", {"scriptPath": {"type": "string"}, "execute": {"type": "boolean"}}, ["scriptPath"]),
        tool("xenoid_automation_run", "Run Xenoid JS automation task", {"scriptPath": {"type": "string"}}, ["scriptPath"]),
        tool("xenoid_app_install", "Install APK by Android-side path through daemon", {"path": {"type": "string"}}, ["path"]),
        tool("xenoid_app_uninstall", "Uninstall package through daemon", {"package": {"type": "string"}}, ["package"]),
        tool("xenoid_app_launch", "Launch component through daemon", {"component": {"type": "string"}}, ["component"]),
        tool("xenoid_hide_deploy", "Deploy native xenoid-hide helper", {"path": {"type": "string"}, "remotePath": {"type": "string"}}, ["path"]),
        tool("xenoid_hide_status", "Inspect environment hiding policy through daemon"),
        tool("xenoid_hide_overlay_status", "Inspect Xenoid overlay helper status-json"),
        tool("xenoid_hide_cleanup_overlay", "Cleanup Xenoid overlay bind mounts"),
        tool("xenoid_netctl_deploy", "Deploy low-level rtnetlink network identity helper", {"path": {"type": "string"}, "remotePath": {"type": "string"}}, ["path"]),
        tool("xenoid_netctl_status", "Inspect ioctl/rtnetlink MAC identity through xenoid-netctl", {"ifname": {"type": "string"}}),
        tool("xenoid_netctl_set_mac", "Set interface MAC through xenoid-netctl RTM_SETLINK path", {"mac": {"type": "string"}, "ifname": {"type": "string"}}, ["mac"]),
        tool("xenoid_hide_apply", "Apply environment hiding policy through daemon", {"policyPath": {"type": "string"}}),
        tool("xenoid_ebpf_build", "Build host-side eBPF path-hide program on Colima/Linux"),
        tool("xenoid_ebpf_load", "Load/attach host-side eBPF path-hide"),
        tool("xenoid_ebpf_status", "Status JSON for host-side eBPF path-hide"),
        tool("xenoid_ebpf_unload", "Unload/unpin host-side eBPF path-hide"),
        tool("xenoid_ota_make", "Create local Xenoid OTA bundle", {"version": {"type": "string"}}),
        tool("xenoid_ota_install_bundle", "Install local Xenoid OTA bundle", {"bundle": {"type": "string"}}, ["bundle"]),
        tool("xenoid_ota_check", "Check daemon OTA status"),
        tool("xenoid_ota_apply", "Apply daemon OTA channel", {"channel": {"type": "string"}}),
    ]


def text_result(data: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2, default=lambda o: getattr(o, "__dict__", str(o)))}]}
_PROXY_PRIVATE_KEYS = {
    "authorization",
    "ciphertext",
    "cookie",
    "header",
    "headers",
    "key",
    "masterkey",
    "password",
    "path",
    "privatekey",
    "source",
    "sourcevalue",
    "stagingpath",
    "subscription",
    "token",
    "uri",
    "url",
    "userinfo",
    "value",
}
def _is_stable_proxy_code(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and "a" <= value[0] <= "z"
        and all(("a" <= ch <= "z") or ch.isdigit() or ch == "_" for ch in value)
    )
def _is_sensitive_proxy_text(value: str) -> bool:
    lowered = value.lower()
    if "://" in lowered or value.startswith(("/", "~/")):
        return True
    if "@" in value:
        userinfo = value.split("@", 1)[0]
        if ":" in userinfo and not any(ch.isspace() for ch in userinfo):
            return True
    return False






def _sanitize_proxy_result(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if _is_sensitive_proxy_text(name):
                continue
            normalized = "".join(ch for ch in name.lower() if ch.isalnum())
            private = (
                normalized in _PROXY_PRIVATE_KEYS
                or normalized.endswith(
                    (
                        "authorization",
                        "ciphertext",
                        "cookie",
                        "headers",
                        "masterkey",
                        "password",
                        "privatekey",
                        "sourcevalue",
                        "stagingpath",
                        "token",
                        "userinfo",
                    )
                )
            )
            if private:
                continue
            if normalized in ("error", "message") and not _is_stable_proxy_code(item):
                clean[name] = "proxy_request_failed"
            else:
                clean[name] = _sanitize_proxy_result(item)
        return clean
    if isinstance(value, (list, tuple)):
        return [_sanitize_proxy_result(item) for item in value]
    if isinstance(value, str) and _is_sensitive_proxy_text(value):
        return "[redacted]"
    return value


def proxy_text_result(call: Any) -> dict[str, Any]:
    try:
        result = call()
    except InstanceError as exc:
        result = {"ok": False, "code": exc.code, "error": exc.code}
    except Exception:
        result = {
            "ok": False,
            "code": "daemon_unreachable",
            "error": "daemon_unreachable",
        }
    if not isinstance(result, dict):
        result = {
            "ok": False,
            "code": "daemon_response_invalid",
            "error": "daemon_response_invalid",
        }
    return text_result(_sanitize_proxy_result(result))


def _location_cli_result(runtime: MCPRuntime, command: list[str]) -> dict[str, Any]:
    """Run one location CLI command and surface its JSON result as tool output."""
    cli = runtime.context.project_root / "xenoid"
    try:
        proc = subprocess.run(
            [str(cli), "--instance", runtime.context.instance_name, *command],
            text=True,
            capture_output=True,
            cwd=runtime.context.project_root,
            env=runtime.subprocess_env,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError):
        return text_result({
            "ok": False,
            "code": "location_command_failed",
            "error": "location_command_failed",
        })
    try:
        data = json.loads(proc.stdout)
    except Exception:
        data = {
            "ok": False,
            "code": "location_command_failed",
            "error": "location_command_failed",
            "stderr": proc.stderr[-2000:],
        }
    if isinstance(data, dict):
        data["returncode"] = proc.returncode
    return text_result(data)


def call_tool(runtime: MCPRuntime, name: str, args: dict[str, Any]) -> Any:
    context = runtime.context
    cfg = runtime.config
    mgr = runtime.manager
    dc = runtime.daemon

    def edc() -> DaemonClient:
        mgr.ensure_daemon()
        return dc

    def epc() -> ProxyController:
        ensured = mgr.ensure_daemon()
        if not isinstance(ensured, dict) or ensured.get("ok") is not True:
            raise RuntimeError("daemon_unreachable")
        return ProxyController(context, cfg, runtime.lease, mgr, dc)

    if name == "xenoid_verify_release":
        script = context.project_root / "scripts" / "verify-release.py"
        proc = subprocess.run(
            [str(script), str(args["archive"])],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        try:
            data = json.loads(proc.stdout)
        except Exception:
            data = {"ok": False, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return text_result(data)
    if name == "xenoid_package_release":
        script = context.project_root / "scripts" / "package-release.sh"
        proc = subprocess.run(
            [str(script), str(args.get("version") or "dev")],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env={**runtime.subprocess_env, "REL": ""},
        )
        return text_result({"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode, "archive": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None})
    if name == "xenoid_doctor":
        return text_result(build_doctor_report(
            context,
            cfg,
            runtime.lease,
            full=bool(args.get("full", False)),
            require_runtime=bool(args.get("requireRuntime", False)),
        ))
    if name == "xenoid_runtime_context":
        return text_result(mgr.make_runtime_context(args.get("image")))
    if name == "xenoid_linux_binderfs":
        script = context.project_root / "scripts" / "setup-linux-binderfs.sh"
        cmd = [str(script)] + (["--dry-run"] if bool(args.get("dryRun", True)) else [])
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        return text_result({
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        })
    if name == "xenoid_runtime_build_image":
        ctx = mgr.make_runtime_context(args.get("image"))
        tag = str(args.get("tag") or "xenoid/redroid:local")
        if bool(args.get("dryRun", True)):
            return text_result({
                "ok": ctx.get("ok"),
                "dryRun": True,
                "context": ctx.get("context"),
                "command": [
                    *mgr.docker_base_cmd(),
                    "build",
                    "-t",
                    tag,
                    ctx.get("context"),
                ],
            })
        proc = subprocess.run(
            [*mgr.docker_base_cmd(), "build", "-t", tag, ctx.get("context")],
            text=True,
            capture_output=True,
        )
        return text_result({
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "tag": tag,
        })
    if name == "xenoid_config_show":
        return text_result({
            "instance": context.public_dict(),
            "config": cfg,
        })
    if name == "xenoid_install_runtime_plan":
        script = context.project_root / "scripts" / "install-macos-runtime.sh"
        proc = subprocess.run(
            [str(script), "--dry-run"],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        try: data = json.loads(proc.stdout)
        except Exception: data = {"ok": False, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return text_result(data)
    if name == "xenoid_up_plan":
        script = context.project_root / "scripts" / "xenoid-up.sh"
        proc = subprocess.run(
            [str(script), "--instance", context.instance_name, "--dry-run"],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        try: data = json.loads(proc.stdout)
        except Exception: data = {"ok": False, "stdout": proc.stdout, "stderr": proc.stderr}
        data["returncode"] = proc.returncode
        return text_result(data)
    if name == "xenoid_start":
        return text_result(mgr.start(dry_run=bool(args.get("dryRun", False)), start_colima=bool(args.get("startColima", False)), install_daemon_apk=args.get("installDaemonApk"), adb_root=bool(args.get("adbRoot", True)), recreate=bool(args.get("recreate", False))))
    if name == "xenoid_stop":
        return text_result(mgr.stop())
    if name == "xenoid_logs":
        return text_result(mgr.runtime_logs(args.get("outDir")))
    if name == "xenoid_view":
        return text_result(mgr.view())
    if name == "xenoid_status":
        return text_result(mgr.status())
    if name == "xenoid_daemon_health":
        return text_result(dc.health())
    if name == "xenoid_daemon_ensure":
        daemon_result = mgr.ensure_daemon()
        proxy = (
            mgr.reconcile_proxy_desired()
            if daemon_result.get("ok") else {"ok": False, "skipped": True}
        )
        return text_result({
            "ok": bool(daemon_result.get("ok") and proxy.get("ok")),
            "daemon": daemon_result,
            "proxyConverged": proxy,
        })
    if name == "xenoid_daemon_install":
        install = mgr.install_daemon(str(args["apk"]))
        start = (
            mgr.start_daemon_service()
            if install.get("ok") else {"ok": False, "skipped": True}
        )
        forward = (
            mgr.forward_daemon_port()
            if start.get("ok") else {"ok": False, "skipped": True}
        )
        rootd = (
            mgr.ensure_rootd_root()
            if forward.get("ok") else {"ok": False, "skipped": True}
        )
        ready = (
            mgr.ensure_daemon()
            if rootd.get("ok") else {"ok": False, "skipped": True}
        )
        proxy = (
            mgr.reconcile_proxy_desired()
            if ready.get("ok") else {"ok": False, "skipped": True}
        )
        return text_result({
            "ok": all(
                bool(step.get("ok"))
                for step in (install, start, forward, rootd, ready, proxy)
            ),
            "install": install,
            "start": start,
            "forward": forward,
            "rootd": rootd,
            "ready": ready,
            "proxyConverged": proxy,
        })
    if name == "xenoid_proxy_status":
        return proxy_text_result(lambda: epc().status())
    if name == "xenoid_proxy_check":
        return proxy_text_result(lambda: epc().status(check=True))
    if name == "xenoid_proxy_on":
        return proxy_text_result(lambda: epc().set_enabled(True))
    if name == "xenoid_proxy_off":
        return proxy_text_result(lambda: epc().set_enabled(False))
    if name == "xenoid_proxy_clear":
        return proxy_text_result(lambda: epc().clear())
    if name == "xenoid_proxy_select":
        selected_name = args.get("name")
        if not isinstance(selected_name, str) or not selected_name:
            return proxy_text_result(
                lambda: {
                    "ok": False,
                    "code": "invalid_request_schema",
                    "error": "invalid_request_schema",
                }
            )
        return proxy_text_result(lambda: epc().select(selected_name))
    if name == "xenoid_location_list":
        return _location_cli_result(runtime, ["location", "list"])
    if name == "xenoid_location_status":
        command = ["location", "status"]
        if args.get("check"):
            command.append("--check")
        return _location_cli_result(runtime, command)
    if name == "xenoid_location_set":
        country = args.get("countryCode")
        if not isinstance(country, str) or not country.strip():
            return text_result({
                "ok": False,
                "code": "location_country_invalid",
                "error": "location_country_invalid",
            })
        return _location_cli_result(runtime, ["location", "set", country.strip()])
    if name == "xenoid_root_status":
        return text_result(edc().root_status())
    if name == "xenoid_root_exec":
        return text_result(edc().root_exec(str(args["command"])))
    if name == "xenoid_frida_install":
        return text_result(mgr.install_frida(
            version=str(args.get("version") or "latest"),
            arch=str(args.get("arch") or "android-arm64"),
            out_dir=str(args["outDir"]) if args.get("outDir") else None,
            remote_path=str(args.get("remotePath") or "/data/system/.core/svc.bin"),
        ))
    if name == "xenoid_frida_fetch":
        return text_result(mgr.fetch_frida(
            version=str(args.get("version") or "latest"),
            arch=str(args.get("arch") or "android-arm64"),
            out_dir=str(args["outDir"]) if args.get("outDir") else None,
        ))
    if name == "xenoid_frida_deploy":
        return text_result(mgr.deploy_frida(str(args["path"]), str(args.get("remotePath") or "/data/system/.core/svc.bin")))
    if name == "xenoid_frida_deploy_scripts":
        return text_result(mgr.deploy_frida_scripts(str(args.get("scriptsDir") or "frida/scripts"), str(args.get("remoteDir") or "/data/local/tmp/xenoid-frida")))
    if name == "xenoid_frida_load_script":
        return text_result(mgr.load_frida_script(str(args["package"]), str(args["script"]), bool(args.get("spawn", False))))
    if name == "xenoid_frida_start":
        return text_result(edc().frida_start(int(args.get("port") or 27042)))
    if name == "xenoid_frida_stop":
        return text_result(edc().frida_stop())
    if name == "xenoid_frida_status":
        return text_result(edc().frida_status())
    if name == "xenoid_input_deploy":
        return text_result(mgr.deploy_input_helper(str(args["path"]), str(args.get("remotePath") or "/data/local/tmp/xenoid-input")))
    if name == "xenoid_input_tap":
        return text_result(edc().tap(int(args["x"]), int(args["y"])))
    if name == "xenoid_input_swipe":
        return text_result(edc().swipe(int(args["x1"]), int(args["y1"]), int(args["x2"]), int(args["y2"]), int(args.get("durationMs") or 300)))
    if name == "xenoid_profile_deploy_helper":
        return text_result(mgr.deploy_profile_helper(str(args["path"]), str(args.get("remotePath") or "/data/local/tmp/xenoid-profile-helper")))
    if name == "xenoid_profile_helper_status":
        return text_result(edc().profile_helper_status())
    if name == "xenoid_profile_helper_env":
        return text_result(edc().profile_helper_env())
    if name == "xenoid_profile_helper_dump":
        return text_result(edc().profile_helper_dump())
    if name == "xenoid_device_collect":
        return text_result(edc().collect_fingerprint())
    if name == "xenoid_device_apply":
        client = edc()
        return text_result(converge_instance_identity(
            context,
            mgr,
            client,
            read_json_file(str(args["profilePath"])),
            rotate_stable=bool(args.get("regenerateUnique", True)),
        ))
    if name == "xenoid_device_generate_frida":
        return text_result(mgr.generate_profile_frida(
            str(args["profilePath"]),
            str(args["out"]) if args.get("out") else None,
            bool(args.get("keepUnique", False)),
        ))
    if name == "xenoid_device_generate_service_frida":
        return text_result(mgr.generate_service_frida(
            str(args["profilePath"]),
            str(args["out"]) if args.get("out") else None,
            bool(args.get("keepUnique", False)),
        ))
    if name == "xenoid_device_set":
        field = str(args["field"])
        value = args["value"]
        key = identity_field_key(field)
        if key is not None:
            validate_identity_value(key, value)
        changed = edc().set_fingerprint_field(field, value)
        if key is not None and changed.get("ok") is True:
            state = DeviceIdentityStore(context).update_field(field, value)
            changed = {
                "ok": True,
                "daemon": changed,
                "identity": public_identity_state(state),
            }
        return text_result(changed)
    if name == "xenoid_automation_plan":
        return text_result(mgr.automation_plan(str(args["scriptPath"])))
    if name == "xenoid_automation_run_host":
        return text_result(mgr.automation_run_host(
            str(args["scriptPath"]),
            bool(args.get("execute", False)),
            dc.base,
        ))
    if name == "xenoid_automation_run":
        return text_result(edc().run_automation(str(args["scriptPath"])))
    if name == "xenoid_app_install":
        return text_result(edc().app_install(str(args["path"])))
    if name == "xenoid_app_uninstall":
        return text_result(edc().app_uninstall(str(args["package"])))
    if name == "xenoid_app_launch":
        return text_result(edc().app_launch(str(args["component"])))
    if name == "xenoid_hide_deploy":
        return text_result(mgr.deploy_hide_helper(str(args["path"]), str(args.get("remotePath") or "/data/local/tmp/xenoid-hide-helper")))
    if name == "xenoid_hide_status":
        return text_result(edc().hide_status())
    if name == "xenoid_hide_overlay_status":
        return text_result(mgr.overlay_status())
    if name == "xenoid_hide_cleanup_overlay":
        return text_result(mgr.overlay_cleanup())
    if name == "xenoid_hide_apply":
        policy = read_json_file(str(args["policyPath"])) if args.get("policyPath") else None
        return text_result(edc().hide_apply(policy))
    if name == "xenoid_ebpf_build":
        script = context.project_root / "scripts" / "build-ebpf.sh"
        proc = subprocess.run(
            [str(script)],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        for line in reversed((proc.stdout or "").splitlines()):
            if line.strip().startswith("{"):
                try:
                    data.update(json.loads(line.strip()))
                except Exception:
                    pass
                break
        return text_result(data)
    if name == "xenoid_ebpf_load":
        script = context.project_root / "scripts" / "load-ebpf.sh"
        proc = subprocess.run(
            [str(script), "load"],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        for line in reversed((proc.stdout or "").splitlines()):
            if line.strip().startswith("{"):
                try:
                    data.update(json.loads(line.strip()))
                except Exception:
                    pass
                break
        return text_result(data)
    if name == "xenoid_ebpf_status":
        script = context.project_root / "scripts" / "load-ebpf.sh"
        proc = subprocess.run(
            [str(script), "status"],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        for line in reversed((proc.stdout or "").splitlines()):
            if line.strip().startswith("{"):
                try:
                    data.update(json.loads(line.strip()))
                except Exception:
                    pass
                break
        return text_result(data)
    if name == "xenoid_ebpf_unload":
        script = context.project_root / "scripts" / "load-ebpf.sh"
        proc = subprocess.run(
            [str(script), "unload"],
            text=True,
            capture_output=True,
            cwd=context.project_root,
            env=runtime.subprocess_env,
        )
        data = {"ok": proc.returncode == 0, "stdout": proc.stdout, "stderr": proc.stderr}
        for line in reversed((proc.stdout or "").splitlines()):
            if line.strip().startswith("{"):
                try:
                    data.update(json.loads(line.strip()))
                except Exception:
                    pass
                break
        return text_result(data)
    if name == "xenoid_ota_make":
        return text_result(mgr.make_ota_bundle(str(args.get("version") or "0.1.0")))
    if name == "xenoid_ota_install_bundle":
        return text_result(mgr.apply_ota_bundle(str(args["bundle"])))
    if name == "xenoid_ota_check":
        return text_result(edc().ota_check())
    if name == "xenoid_ota_apply":
        return text_result(edc().ota_apply(str(args.get("channel") or "stable")))
    raise ValueError(f"unknown tool: {name}")


def handle(runtime: MCPRuntime, req: dict[str, Any]) -> None:
    method = req.get("method")
    id_ = req.get("id")
    if method == "initialize":
        respond(id_, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "xenoid", "version": "0.1.0"}})
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        respond(id_, {"tools": tools()})
    elif method == "tools/call":
        params = req.get("params", {})
        try:
            respond(id_, call_tool(runtime, params.get("name"), params.get("arguments") or {}))
        except InstanceError as exc:
            respond(id_, error={"code": -32000, "message": exc.code, "data": exc.as_dict()})
        except Exception as exc:
            respond(id_, error={"code": -32000, "message": str(exc)})
    else:
        respond(id_, error={"code": -32601, "message": f"method not found: {method}"})


def main() -> int:
    try:
        runtime = MCPRuntime.resolve()
    except InstanceError as exc:
        respond(None, error={"code": -32000, "message": exc.code, "data": exc.as_dict()})
        return 1
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            handle(runtime, json.loads(line))
        except Exception as exc:
            respond(None, error={"code": -32700, "message": str(exc)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
