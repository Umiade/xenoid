from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
import json
import os
import sys
import time
from dataclasses import dataclass, replace
from threading import Event, Lock
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Optional

from .backend import RuntimeManager
from .cellular import CellularError
from .convergence import ConvergenceExecutor, ConvergencePlanner
from .config import (
    InstanceContext,
    InstanceError,
    InstanceLease,
    XenoidConfig,
    resolve_instance,
)
from .cli import (
    _execute_device_regeneration,
    _google_services_disable_result,
    _google_services_enable_result,
    _location_converge,
    _location_failure,
)
from .daemon_client import DaemonClient
from .doctor import build_doctor_report
from .device_identity import (
    IdentityError,
    RegenerationJournal,
    DeviceIdentityStore,
    converge_instance_identity,
    identity_field_key,
    public_identity_state,
    validate_identity_value,
)
from .process import run_bounded
from .google_services import MICROG_PLAY_RELEASE
from .location import (
    DEFAULT_COUNTRY,
    LocationError,
    LocationStateStore,
    location_runtime_epoch,
    masked_android_status,
    normalize_country,
    public_summary,
    supported_countries,
)
from .proxy_controller import ProxyController
from .operation_lock import (
    EXPECTED_INSTANCE_ID_ENV,
    OPERATION_LOCK_TIMEOUT_ENV,
    instance_operation_lock,
)
from .util import bounded_timeout, command_timeout, read_json_file, validate_release_version


UP_TIMEOUT_SECONDS = 7200
_RESPONSE_LOCK = Lock()


@dataclass(frozen=True)
class MCPRuntime:
    context: InstanceContext
    config: XenoidConfig
    lease: InstanceLease
    manager: RuntimeManager
    daemon: DaemonClient
    operation_lock_held: bool = False
    operation_lock_timeout_seconds: Optional[float] = None

    @classmethod
    def resolve(cls) -> "MCPRuntime":
        context, config, lease = resolve_instance()
        manager = RuntimeManager(context, config, lease)
        daemon = DaemonClient(context, lease, manager.docker_base_cmd())
        return cls(context, config, lease, manager, daemon)

    @property
    def subprocess_env(self) -> dict[str, str]:
        environment = {
            **os.environ,
            "XENOID_PROJECT": str(self.context.project_root),
            "XENOID_INSTANCE": self.context.instance_name,
            EXPECTED_INSTANCE_ID_ENV: self.context.instance_id,
        }
        environment.pop("XENOID_OPERATION_LOCK_HELD", None)
        if self.operation_lock_timeout_seconds is None:
            environment.pop(OPERATION_LOCK_TIMEOUT_ENV, None)
        else:
            environment[OPERATION_LOCK_TIMEOUT_ENV] = str(
                self.operation_lock_timeout_seconds
            )
        return environment




def respond(id_: Any, result: Any = None, error: Any = None) -> None:
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    with _RESPONSE_LOCK:
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
        tool("xenoid_runtime_build_image", "Ensure or inspect the configured content-addressed runtime image", {"image": {"type": "string"}, "dryRun": {"type": "boolean"}}),
        tool("xenoid_config_show", "Show Xenoid config"),
        tool(
            "xenoid_google_services_status",
            "Show pinned Google services configuration, binding, image, rootfs, and live capability state",
            {"requireRuntime": {"type": "boolean"}},
        ),
        tool(
            "xenoid_google_services_enable",
            "Enable the pinned microG production Google services release on a fresh selected instance",
            {"release": {"type": "string"}},
        ),
        tool(
            "xenoid_google_services_disable",
            "Disable Google services on a fresh selected instance",
        ),
        tool("xenoid_install_runtime_plan", "Dry-run macOS runtime dependency install plan"),
        tool("xenoid_up_plan", "Dry-run full Xenoid startup plan"),
        tool(
            "xenoid_up",
            "Converge the complete selected Xenoid runtime and validate readiness",
            {
                "skipBuild": {"type": "boolean"},
            },
        ),
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
        tool(
            "xenoid_proxy_clear",
            "Disable and clear the fixed instance proxy source; explicit unreadable-state discard preserves evidence before source-less recovery",
            {"discardUnreadableState": {"type": "boolean"}},
        ),
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
        tool("xenoid_ebpf_build", "Build validated shared protection replacements"),
        tool("xenoid_ebpf_load", "Converge shared engine-host kmod/eBPF protection"),
        tool("xenoid_ebpf_status", "Safe shared engine-host protection status"),
        tool(
            "xenoid_ebpf_unload",
            "Maintenance-only eBPF unload with no active Xenoid runtimes",
            {"maintenance": {"type": "boolean"}},
            ["maintenance"],
        ),
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


def _feature_args(runtime: MCPRuntime, **values: Any) -> SimpleNamespace:
    return SimpleNamespace(
        context=runtime.context,
        config=runtime.config,
        lease=runtime.lease,
        project_root=runtime.context.project_root,
        instance_name=runtime.context.instance_name,
        _operation_lock_held=True,
        **values,
    )


def _location_result(runtime: MCPRuntime, country_code: str) -> dict[str, Any]:
    def operation() -> dict[str, Any]:
        args = _feature_args(runtime, country=country_code)
        try:
            store = LocationStateStore(runtime.context.state_root)
            target = normalize_country(country_code)
            store.ensure(runtime.context.instance_id, target)
            store.set_desired(target)
            return _location_converge(
                args,
                runtime.manager,
                store,
                rebind_proxy=True,
            )
        except (CellularError, LocationError, InstanceError) as exc:
            return _location_failure(exc.code)
        except Exception:
            return _location_failure("location_convergence_failed")

    with command_timeout(3600):
        return text_result(_locked_runtime_mutation(runtime, operation))


def _location_list_result(runtime: MCPRuntime) -> dict[str, Any]:
    try:
        store = LocationStateStore(runtime.context.state_root)
        try:
            state = store.load()
        except LocationError:
            state = None
        active = state.get("active") if isinstance(state, Mapping) else None
        return {
            "ok": True,
            "defaultCountry": DEFAULT_COUNTRY,
            "desiredCountry": (
                state.get("desiredCountry")
                if isinstance(state, Mapping)
                else None
            ),
            "activeCountry": (
                active.get("country")
                if isinstance(active, Mapping)
                else None
            ),
            "countries": supported_countries(),
        }
    except (CellularError, LocationError) as exc:
        return _location_failure(exc.code)


def _location_status_result(
    runtime: MCPRuntime,
    *,
    check: bool,
) -> dict[str, Any]:
    try:
        state = LocationStateStore(runtime.context.state_root).load()
        host = public_summary(state)
        container_id = runtime.manager.location_runtime_container_id()
        epoch = location_runtime_epoch(container_id) if container_id else ""
        android: dict[str, Any] = {
            "ok": False,
            "error": "runtime_not_running",
        }
        if epoch:
            try:
                android = masked_android_status(runtime.daemon.location_status())
            except Exception:
                android = {"ok": False, "error": "daemon_unreachable"}
        checked = True
        if check:
            active = state.get("active") if isinstance(state, Mapping) else None
            checked = bool(
                isinstance(active, Mapping)
                and android.get("ok") is True
                and android.get("state") == "active"
                and android.get("profileDigest") == active.get("profileDigest")
                and epoch
                and android.get("runtimeEpoch") == epoch
            )
        return {"ok": bool(checked), "host": host, "android": android}
    except (CellularError, LocationError, InstanceError) as exc:
        return _location_failure(exc.code)
    except Exception:
        return _location_failure("location_status_failed")


def _google_services_result(
    runtime: MCPRuntime,
    *,
    enabled: bool,
    release: Optional[str] = None,
) -> dict[str, Any]:
    args = _feature_args(
        runtime,
        release=release or MICROG_PLAY_RELEASE,
    )
    try:
        with command_timeout(3600):
            result = _locked_runtime_mutation(
                runtime,
                lambda: (
                    _google_services_enable_result(args)
                    if enabled
                    else _google_services_disable_result(args)
                ),
            )
    except InstanceError as exc:
        result = exc.as_dict()
    except (OSError, RuntimeError, ValueError):
        result = {
            "ok": False,
            "error": "google_services_runtime_not_ready",
        }
    return text_result(result)




def _locked_runtime_mutation(
    runtime: MCPRuntime,
    operation: Callable[[], dict[str, Any]],
    *,
    migrate_legacy_tokens: bool = True,
    allow_regeneration: bool = False,
) -> dict[str, Any]:
    def invoke_locked() -> dict[str, Any]:
        previous = bool(getattr(runtime.manager, "operation_lock_held", False))
        runtime.manager.operation_lock_held = True
        try:
            if not allow_regeneration:
                try:
                    regeneration = RegenerationJournal(runtime.context).load()
                except IdentityError as exc:
                    return exc.as_dict()
                if regeneration is not None:
                    return {
                        "ok": False,
                        "error": "device_regeneration_pending",
                        "phase": regeneration["phase"],
                    }
            if migrate_legacy_tokens:
                runtime.manager.migrate_legacy_token_state()
            return operation()
        finally:
            runtime.manager.operation_lock_held = previous

    with instance_operation_lock(runtime.context.state_root):
        return invoke_locked()


def _up_executor_result(runtime: MCPRuntime, args: dict[str, Any]) -> dict[str, Any]:
    if set(args) - {"skipBuild"}:
        return text_result({
            "ok": False,
            "code": "invalid_request_schema",
            "error": "invalid_request_schema",
        })
    skip_build = args.get("skipBuild", False)
    if not isinstance(skip_build, bool):
        return text_result({
            "ok": False,
            "code": "invalid_request_schema",
            "error": "invalid_request_schema",
        })

    def converge() -> dict[str, Any]:
        with command_timeout(UP_TIMEOUT_SECONDS):
            try:
                regeneration = RegenerationJournal(runtime.context).load()
            except IdentityError as exc:
                return exc.as_dict()
            if regeneration is not None:
                namespace = SimpleNamespace(
                    context=runtime.context,
                    config=runtime.config,
                    lease=runtime.lease,
                    project_root=runtime.context.project_root,
                    instance_name=runtime.context.instance_name,
                    skip_build=skip_build,
                    dry_run=False,
                    restart_legacy_transaction=False,
                    _operation_lock_held=True,
                )
                return _execute_device_regeneration(namespace)
            return ConvergenceExecutor(runtime.manager).run(
                progress=lambda _event: None,
                skip_build=skip_build,
            )

    result = _locked_runtime_mutation(
        runtime,
        converge,
        allow_regeneration=True,
    )
    return text_result(result)


def _status_result(manager: RuntimeManager) -> dict[str, Any]:
    result = manager.status()
    if isinstance(result.get("recommendedAction"), str):
        return result
    if result.get("pendingJournalPhase") or result.get("pendingJournal"):
        action = "resume"
    elif result.get("error") in {
        "resource_conflict",
        "ownership_mismatch",
        "runtime_identity_mismatch",
    }:
        action = "resource-conflict"
    elif result.get("running") is True:
        action = (
            "no-op"
            if result.get("containerContractMatches", True) is True
            else "recreate"
        )
    elif "containerContractMatches" in result:
        action = (
            "start"
            if result.get("containerContractMatches") is True
            else "recreate"
        )
    else:
        runtime_image = result.get("runtimeImage")
        action = (
            "image-required"
            if isinstance(runtime_image, Mapping)
            and runtime_image.get("ok") is not True
            else "create"
        )
    result["recommendedAction"] = action
    return result


def call_tool(runtime: MCPRuntime, name: str, args: dict[str, Any]) -> Any:
    context = runtime.context
    cfg = runtime.config
    mgr = runtime.manager
    dc = runtime.daemon

    def require_bootstrap() -> dict[str, Any]:
        reconciled = mgr.reconcile_bootstrap()
        if (
            not isinstance(reconciled, dict)
            or reconciled.get("transportReady") is not True
            or reconciled.get("controlReady") is not True
        ):
            code = reconciled.get("code") if isinstance(reconciled, dict) else None
            safe = (
                code
                if isinstance(code, str)
                and code.replace("_", "").isalnum()
                and code[:1].isalpha()
                else "daemon_unreachable"
            )
            raise InstanceError(safe, safe)
        return reconciled

    def edc() -> DaemonClient:
        require_bootstrap()
        return dc

    def epc() -> ProxyController:
        require_bootstrap()
        return ProxyController(context, cfg, runtime.lease, mgr, dc)

    if name == "xenoid_verify_release":
        script = context.project_root / "scripts" / "verify-release.py"
        proc = run_bounded(
            [str(script), str(args["archive"])],
            cwd=context.project_root,
            env=runtime.subprocess_env,
            deadline=time.monotonic() + 600.0,
            project_root=context.project_root,
        )
        try:
            data = json.loads(proc.stdout_tail)
        except Exception:
            data = {
                "ok": False,
                "state": proc.state,
                "errorCode": proc.error_code or "release_verification_failed",
                "stderr": proc.stderr_tail,
            }
        data["returncode"] = proc.returncode
        return text_result(data)
    if name == "xenoid_package_release":
        try:
            requested_version = args.get("version")
            version = validate_release_version(
                "dev" if requested_version is None else requested_version
            )
        except ValueError:
            return text_result({
                "ok": False,
                "code": "release_version_invalid",
                "error": "release_version_invalid",
            })
        script = context.project_root / "scripts" / "package-release.sh"
        proc = run_bounded(
            [str(script), version],
            cwd=context.project_root,
            env={**runtime.subprocess_env, "REL": ""},
            deadline=time.monotonic() + 7200.0,
            project_root=context.project_root,
        )
        stdout = proc.stdout_tail.strip()
        return text_result({
            "ok": proc.ok,
            "state": proc.state,
            "errorCode": proc.error_code,
            "stdout": stdout,
            "stderr": proc.stderr_tail,
            "returncode": proc.returncode,
            "archive": stdout.splitlines()[-1] if stdout else None,
        })
    if name == "xenoid_doctor":
        return text_result(build_doctor_report(
            context,
            cfg,
            runtime.lease,
            full=bool(args.get("full", False)),
            require_runtime=bool(args.get("requireRuntime", False)),
        ))
    if name == "xenoid_google_services_status":
        return text_result(
            mgr.google_services_status(
                require_runtime=bool(args.get("requireRuntime", False)),
            )
        )
    if name == "xenoid_google_services_enable":
        release = args.get("release")
        return _google_services_result(
            runtime,
            enabled=True,
            release=release if isinstance(release, str) else None,
        )
    if name == "xenoid_google_services_disable":
        return _google_services_result(runtime, enabled=False)
    if name == "xenoid_runtime_context":
        return text_result(mgr.make_runtime_context(args.get("image")))
    if name == "xenoid_linux_binderfs":
        script = context.project_root / "scripts" / "setup-linux-binderfs.sh"
        cmd = [str(script)] + (["--dry-run"] if bool(args.get("dryRun", True)) else [])
        proc = run_bounded(
            cmd,
            cwd=context.project_root,
            env=runtime.subprocess_env,
            deadline=time.monotonic() + 900.0,
            project_root=context.project_root,
        )
        return text_result({
            "ok": proc.ok,
            "state": proc.state,
            "errorCode": proc.error_code,
            "returncode": proc.returncode,
            "stdout": proc.stdout_tail,
            "stderr": proc.stderr_tail,
        })
    if name == "xenoid_runtime_build_image":
        if bool(args.get("dryRun", True)):
            try:
                record = mgr.runtime_image_input_record(args.get("image"))
                return text_result({"ok": True, "dryRun": True, **record})
            except (InstanceError, OSError, RuntimeError, ValueError) as exc:
                return text_result({
                    "ok": False,
                    "dryRun": True,
                    "error": getattr(
                        exc,
                        "code",
                        "runtime_image_input_invalid",
                    ),
                    "message": str(exc),
                })
        return text_result(mgr.ensure_runtime_image(args.get("image")))
    if name == "xenoid_config_show":
        return text_result({
            "instance": context.public_dict(),
            "config": cfg,
        })
    if name == "xenoid_install_runtime_plan":
        script = context.project_root / "scripts" / "install-macos-runtime.sh"
        proc = run_bounded(
            [str(script), "--dry-run"],
            cwd=context.project_root,
            env=runtime.subprocess_env,
            deadline=time.monotonic() + 900.0,
            project_root=context.project_root,
        )
        try:
            data = json.loads(proc.stdout_tail)
        except Exception:
            data = {"ok": False, "state": proc.state, "errorCode": proc.error_code, "stdout": proc.stdout_tail, "stderr": proc.stderr_tail}
        data["returncode"] = proc.returncode
        return text_result(data)
    if name == "xenoid_up_plan":
        try:
            plan = ConvergencePlanner(mgr).inspect(skip_build=False)
            return text_result(plan.to_dict())
        except (InstanceError, OSError, RuntimeError, ValueError) as exc:
            return text_result({
                "ok": False,
                "error": getattr(exc, "code", "convergence_inspection_failed"),
            })
    if name == "xenoid_up":
        return _up_executor_result(runtime, args)
    if name == "xenoid_start":
        return text_result(_locked_runtime_mutation(
            runtime,
            lambda: mgr.start(dry_run=bool(args.get("dryRun", False)), start_colima=bool(args.get("startColima", False)), install_daemon_apk=args.get("installDaemonApk"), adb_root=bool(args.get("adbRoot", True)), recreate=bool(args.get("recreate", False))),
            migrate_legacy_tokens=not bool(args.get("dryRun", False)),
        ))
    if name == "xenoid_stop":
        return text_result(_locked_runtime_mutation(runtime, mgr.stop))
    if name == "xenoid_logs":
        return text_result(mgr.runtime_logs(args.get("outDir")))
    if name == "xenoid_view":
        return text_result(mgr.view())
    if name == "xenoid_status":
        return text_result(_status_result(mgr))
    if name == "xenoid_daemon_health":
        return text_result(dc.health())
    if name == "xenoid_daemon_ensure":
        bootstrap = mgr.reconcile_bootstrap()
        proxy = (
            mgr.reconcile_proxy_desired()
            if bootstrap.get("controlReady") is True
            else {"ok": False, "skipped": True}
        )
        return text_result({
            "ok": bool(bootstrap.get("ok") and proxy.get("ok")),
            "bootstrap": bootstrap,
            "proxyConverged": proxy,
        })
    if name == "xenoid_daemon_install":
        install = mgr.install_daemon(str(args["apk"]))
        bootstrap = (
            mgr.reconcile_bootstrap()
            if install.get("ok")
            else {"ok": False, "skipped": True}
        )
        proxy = (
            mgr.reconcile_proxy_desired()
            if bootstrap.get("controlReady") is True
            else {"ok": False, "skipped": True}
        )
        if proxy.get("ok") is not True:
            mgr._discard_pending_proxy_restore()
        return text_result({
            "ok": all(
                bool(step.get("ok"))
                for step in (install, bootstrap, proxy)
            ),
            "install": install,
            "bootstrap": bootstrap,
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
        discard_unreadable = args.get("discardUnreadableState", False)
        if (
            set(args) - {"discardUnreadableState"}
            or not isinstance(discard_unreadable, bool)
        ):
            return proxy_text_result(
                lambda: {
                    "ok": False,
                    "code": "invalid_request_schema",
                    "error": "invalid_request_schema",
                }
            )
        return proxy_text_result(
            lambda: epc().clear(discard_unreadable_state=discard_unreadable)
        )
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
        return text_result(_location_list_result(runtime))
    if name == "xenoid_location_status":
        return text_result(
            _location_status_result(runtime, check=bool(args.get("check")))
        )
    if name == "xenoid_location_set":
        country = args.get("countryCode")
        if not isinstance(country, str) or not country.strip():
            return text_result({
                "ok": False,
                "code": "location_country_invalid",
                "error": "location_country_invalid",
            })
        return _location_result(runtime, country.strip())
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
        execute = bool(args.get("execute", False))
        if execute:
            require_bootstrap()
        return text_result(mgr.automation_run_host(
            str(args["scriptPath"]),
            execute,
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
    if name == "xenoid_netctl_deploy":
        return text_result(mgr.deploy_netctl_helper(
            str(args["path"]),
            str(args.get("remotePath") or "/data/local/tmp/xenoid-netctl"),
        ))
    if name == "xenoid_netctl_status":
        return text_result(mgr.netctl_status(
            str(args.get("ifname") or "rmnet_data0"),
        ))
    if name == "xenoid_netctl_set_mac":
        return text_result(mgr.netctl_set_mac(
            str(args["mac"]),
            str(args.get("ifname") or "rmnet_data0"),
        ))
    if name == "xenoid_hide_apply":
        policy = read_json_file(str(args["policyPath"])) if args.get("policyPath") else None
        return text_result(edc().hide_apply(policy))
    if name == "xenoid_ebpf_build":
        with command_timeout(1200):
            return text_result(mgr.build_shared_protection())
    if name == "xenoid_ebpf_load":
        with command_timeout(1200):
            return text_result(mgr.maintain_shared_protection())
    if name == "xenoid_ebpf_status":
        with command_timeout(300):
            return text_result(mgr.shared_protection_status())
    if name == "xenoid_ebpf_unload":
        with command_timeout(600):
            return text_result(
                mgr.unload_shared_ebpf(
                    maintenance=args.get("maintenance") is True,
                )
            )
    if name == "xenoid_ota_make":
        requested_version = args.get("version")
        return text_result(mgr.make_ota_bundle(
            "0.1.0" if requested_version is None else requested_version
        ))
    if name == "xenoid_ota_install_bundle":
        return text_result(mgr.apply_ota_bundle(str(args["bundle"])))
    if name == "xenoid_ota_check":
        return text_result(edc().ota_check())
    if name == "xenoid_ota_apply":
        return text_result(edc().ota_apply(str(args.get("channel") or "stable")))
    raise ValueError(f"unknown tool: {name}")


_STDIO_READ_ONLY_TOOLS = frozenset({
    "xenoid_config_show",
    "xenoid_doctor",
    "xenoid_google_services_status",
    "xenoid_install_runtime_plan",
    "xenoid_up_plan",
    "xenoid_logs",
    "xenoid_view",
    "xenoid_status",
    "xenoid_daemon_health",
    "xenoid_location_list",
    "xenoid_location_status",
    "xenoid_hide_overlay_status",
    "xenoid_netctl_status",
    "xenoid_ebpf_status",
})


def _refresh_stdio_runtime(runtime: MCPRuntime) -> MCPRuntime:
    context, config, lease = resolve_instance(
        runtime.context.instance_name,
        project_root=runtime.context.project_root,
    )
    manager = RuntimeManager(context, config, lease)
    daemon = DaemonClient(context, lease, manager.docker_base_cmd())
    return MCPRuntime(
        context,
        config,
        lease,
        manager,
        daemon,
        operation_lock_timeout_seconds=runtime.operation_lock_timeout_seconds,
    )

def _legacy_proxy_recovery_allowed(
    runtime: MCPRuntime,
    name: str,
    arguments: Mapping[str, Any],
) -> bool:
    if name == "xenoid_proxy_clear" and arguments.get(
        "discardUnreadableState"
    ) is not True:
        return False
    if name not in {"xenoid_proxy_set", "xenoid_proxy_clear"}:
        return False
    try:
        digest = RegenerationJournal(
            runtime.context
        ).legacy_source_digest()
        state = ConvergenceExecutor(runtime.manager).journal.load()
    except (IdentityError, InstanceError, OSError, ValueError):
        return False
    return bool(
        isinstance(state, Mapping)
        and state.get("operationId") == digest[:32]
        and isinstance(state.get("regenerationTransactionId"), str)
        and "quarantined" in state.get("completed", [])
    )


def _call_stdio_tool(
    runtime: MCPRuntime,
    name: str,
    arguments: dict[str, Any],
    cancellation: Event | None = None,
) -> Any:
    initial = _refresh_stdio_runtime(runtime)
    initial.manager.cancellation_event = cancellation
    if name in _STDIO_READ_ONLY_TOOLS:
        return call_tool(initial, name, arguments)
    with instance_operation_lock(initial.context.state_root):
        current = _refresh_stdio_runtime(initial)
        current.manager.cancellation_event = cancellation
        if current.context.instance_id != initial.context.instance_id:
            raise InstanceError(
                "instance_identity_mismatch",
                "instance identity changed during an operation",
            )
        locked = replace(current, operation_lock_held=True)
        locked.manager.cancellation_event = cancellation
        locked.manager.operation_lock_held = True
        if name != "xenoid_up":
            try:
                regeneration = RegenerationJournal(locked.context).load()
            except IdentityError as exc:
                if (
                    exc.code == "device_regeneration_legacy_pending"
                    and _legacy_proxy_recovery_allowed(
                        locked,
                        name,
                        arguments,
                    )
                ):
                    regeneration = None
                else:
                    return text_result(exc.as_dict())
            if regeneration is not None:
                return text_result(
                    {
                        "ok": False,
                        "error": "device_regeneration_pending",
                        "phase": regeneration["phase"],
                    }
                )
        if not bool(arguments.get("dryRun", False)):
            locked.manager.migrate_legacy_token_state()
        return call_tool(locked, name, arguments)


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
            respond(
                id_,
                _call_stdio_tool(
                    runtime,
                    params.get("name"),
                    params.get("arguments") or {},
                ),
            )
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
        respond(
            None,
            error={
                "code": -32000,
                "message": exc.code,
                "data": exc.as_dict(),
            },
        )
        return 1
    executor = ThreadPoolExecutor(max_workers=8)
    pending: dict[str | int, tuple[Future[Any], Event]] = {}
    pending_lock = Lock()

    def call_worker(
        request_id: str | int,
        name: str,
        arguments: dict[str, Any],
        cancellation: Event,
    ) -> None:
        try:
            respond(
                request_id,
                _call_stdio_tool(
                    runtime,
                    name,
                    arguments,
                    cancellation,
                ),
            )
        except InstanceError as exc:
            respond(
                request_id,
                error={
                    "code": -32000,
                    "message": exc.code,
                    "data": exc.as_dict(),
                },
            )
        except Exception as exc:
            respond(
                request_id,
                error={"code": -32000, "message": str(exc)},
            )
        finally:
            with pending_lock:
                pending.pop(request_id, None)

    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                method = request.get("method")
                if method == "tools/call":
                    request_id = request.get("id")
                    if not isinstance(request_id, (str, int)):
                        respond(
                            request_id,
                            error={
                                "code": -32600,
                                "message": "invalid request id",
                            },
                        )
                        continue
                    params = request.get("params")
                    params = params if isinstance(params, dict) else {}
                    name = params.get("name")
                    arguments = params.get("arguments")
                    if not isinstance(name, str) or not isinstance(
                        arguments or {},
                        dict,
                    ):
                        respond(
                            request_id,
                            error={
                                "code": -32602,
                                "message": "invalid tool arguments",
                            },
                        )
                        continue
                    cancellation = Event()
                    with pending_lock:
                        if request_id in pending:
                            respond(
                                request_id,
                                error={
                                    "code": -32600,
                                    "message": "duplicate request id",
                                },
                            )
                            continue
                        future = executor.submit(
                            call_worker,
                            request_id,
                            name,
                            arguments or {},
                            cancellation,
                        )
                        pending[request_id] = (future, cancellation)
                    continue
                if method == "notifications/cancelled":
                    params = request.get("params")
                    request_id = (
                        params.get("requestId")
                        if isinstance(params, dict)
                        else None
                    )
                    with pending_lock:
                        operation = pending.get(request_id)
                    if operation is not None:
                        operation[1].set()
                        operation[0].cancel()
                    continue
                handle(runtime, request)
            except Exception as exc:
                respond(
                    None,
                    error={"code": -32700, "message": str(exc)},
                )
    finally:
        with pending_lock:
            operations = list(pending.values())
        for _, cancellation in operations:
            cancellation.set()
        executor.shutdown(wait=True, cancel_futures=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
