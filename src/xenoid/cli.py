from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import getpass
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from .backend import RuntimeManager
from .cellular import CellularError, encode_profile_v1
from .config import (
    InstanceError,
    initialize_instance,
    list_instances,
    merge_config,
    resolve_instance,
    resolve_project_root,
    save_config,
    select_instance_name,
)
from .daemon_client import (
    CAMERA_MUTATION_TIMEOUT_SECONDS,
    PROXY_MAX_SOURCE_BYTES,
    DaemonClient,
)
from .doctor import build_doctor_report
from .device_identity import (
    DeviceIdentityStore,
    converge_instance_identity,
    identity_field_key,
    public_identity_state,
    validate_identity_value,
)
from .location import (
    DEFAULT_COUNTRY,
    LocationError,
    LocationStateStore,
    STAGE_SCHEMA,
    convergence_action,
    location_runtime_epoch,
    masked_android_status,
    normalize_country,
    public_summary,
    supported_countries,
)
from .proxy_controller import ProxyController
from .util import json_dumps, read_json_file, write_json_file




def print_json(data: Any) -> None:
    print(json_dumps(data))
def runtime(args: argparse.Namespace) -> RuntimeManager:
    return RuntimeManager(args.context, args.config, args.lease)


def daemon(
    args: argparse.Namespace,
    manager: Optional[RuntimeManager] = None,
) -> DaemonClient:
    active_manager = manager or runtime(args)
    return DaemonClient(
        args.context,
        args.lease,
        active_manager.docker_base_cmd(),
    )


def command_env(args: argparse.Namespace) -> dict[str, str]:
    return {
        **os.environ,
        "XENOID_PROJECT": str(args.project_root),
        "XENOID_INSTANCE": args.instance_name,
    }


def run_script(args: argparse.Namespace, name: str) -> dict[str, Any]:
    script = args.project_root / "scripts" / name
    proc = subprocess.run(
        [str(script)],
        text=True,
        capture_output=True,
        cwd=args.project_root,
        env=command_env(args),
    )
    return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}


def cmd_install_runtime(args: argparse.Namespace) -> int:
    script = args.project_root / "scripts" / "install-macos-runtime.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        cwd=args.project_root,
        env=command_env(args),
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    report = build_doctor_report(
        args.context,
        args.config,
        args.lease,
        full=args.full,
        require_runtime=args.require_runtime,
    )
    if args.out:
        write_json_file(Path(args.out), report)
    print_json(report)
    return 0 if report["ok"] else 1




def cmd_up(args: argparse.Namespace) -> int:
    script = args.context.project_root / "scripts" / "xenoid-up.sh"
    cmd = [str(script), "--instance", args.context.instance_name]
    if args.dry_run:
        cmd.append("--dry-run")
    if args.skip_build:
        cmd.append("--skip-build")
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        cwd=str(args.context.project_root),
        env=command_env(args),
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}
    print_json(result)
    return 0 if result.get("ok") else 1






def cmd_linux_binderfs(args: argparse.Namespace) -> int:
    script = args.context.project_root / "scripts" / "setup-linux-binderfs.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        cwd=args.context.project_root,
        env=command_env(args),
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_runtime_context(args: argparse.Namespace) -> int:
    result = runtime(args).make_runtime_context(args.image)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_make_rootfs(args: argparse.Namespace) -> int:
    result = runtime(args).ensure_rootfs_images()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_daemon(args: argparse.Namespace) -> int:
    result = run_script(args, "build-daemon.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_input(args: argparse.Namespace) -> int:
    result = run_script(args, "build-native-input.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_hide(args: argparse.Namespace) -> int:
    result = run_script(args, "build-native-hide.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_profile(args: argparse.Namespace) -> int:
    result = run_script(args, "build-native-profile.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_netctl(args: argparse.Namespace) -> int:
    result = run_script(args, "build-native-netctl.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_gralloc(args: argparse.Namespace) -> int:
    result = run_script(args, "build-gralloc.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_ril(args: argparse.Namespace) -> int:
    result = run_script(args, "build-ril.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_radio_config(args: argparse.Namespace) -> int:
    result = run_script(args, "build-radio-config.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_verify_release(args: argparse.Namespace) -> int:
    script = args.project_root / "scripts" / "verify-release.py"
    proc = subprocess.run(
        [str(script), args.archive],
        text=True,
        capture_output=True,
        cwd=args.project_root,
        env=command_env(args),
    )
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    return 0 if proc.returncode == 0 else proc.returncode


def cmd_package_release(args: argparse.Namespace) -> int:
    script = args.project_root / "scripts" / "package-release.sh"
    proc = subprocess.run(
        [str(script), args.version],
        text=True,
        capture_output=True,
        cwd=args.project_root,
        env={**command_env(args), "REL": ""},
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "archive": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None}
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_all(args: argparse.Namespace) -> int:
    root = args.project_root
    commands = [
        ("daemon", [root / "scripts" / "build-daemon.sh"]),
        ("input", [root / "scripts" / "build-native-input.sh"]),
        ("hide", [root / "scripts" / "build-native-hide.sh"]),
        ("profile", [root / "scripts" / "build-native-profile.sh"]),
        ("rootd", [root / "scripts" / "build-native-rootd.sh"]),
        ("netctl", [root / "scripts" / "build-native-netctl.sh"]),
        ("overlay", [root / "scripts" / "build-native-overlay.sh", "arm64"]),
        ("zygote", [root / "scripts" / "build-native-zygote.sh", "arm64"]),
        ("sensorsHal", [root / "scripts" / "build-sensors-hal.sh", "arm64"]),
        ("gralloc", [root / "scripts" / "build-gralloc.sh", "arm64"]),
        ("cameraProvider", [root / "scripts" / "build-camera-hal.sh", "arm64"]),
        ("ril", [root / "scripts" / "build-ril.sh", "arm64"]),
        ("radioConfig", [root / "scripts" / "build-radio-config.sh", "arm64"]),
        ("shimArm64", [root / "scripts" / "build-native-shim.sh", "arm64", "prop"]),
        ("pivot", [root / "scripts" / "build-native-for-arch.sh", "xenoid-pivot", root / "native" / "xenoid-pivot" / "xenoid_pivot.c", root / "native" / "xenoid-pivot" / "xenoid-pivot", "arm64", "static"]),
        ("propArea", [root / "scripts" / "build-native-for-arch.sh", "xenoid-prop-area", root / "native" / "xenoid-hide" / "xenoid_prop_area.c", root / "native" / "xenoid-hide" / "xenoid-prop-area", "arm64"]),
        ("ssaid", [root / "scripts" / "build-native-for-arch.sh", "xenoid-ssaid", root / "native" / "xenoid-hide" / "xenoid_ssaid.c", root / "native" / "xenoid-hide" / "xenoid-ssaid", "arm64"]),
        (
            "proxySandbox",
            [root / "scripts" / "build-proxy-sandbox.sh"],
        ),
    ]
    steps: dict[str, Any] = {}
    for name, command in commands:
        proc = subprocess.run(
            [str(part) for part in command],
            text=True,
            capture_output=True,
            cwd=root,
            env=command_env(args),
        )
        steps[name] = {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    result = {"ok": all(step["ok"] for step in steps.values()), "steps": steps}
    print_json(result)
    return 0 if result["ok"] else 1




def cmd_init(args: argparse.Namespace) -> int:
    context, cfg, lease = initialize_instance(
        args.instance_name,
        project_root=args.project_root,
        overrides={k: v for k, v in {"image": args.image, "backend": args.backend}.items() if v is not None},
        template_path=getattr(args, "config", None),
        from_instance=getattr(args, "from_instance", None),
    )
    print_json({
        "ok": True,
        "instance": context.public_dict(),
        "slot": lease.slot,
        "config": cfg,
    })
    return 0


def cmd_instance_list(args: argparse.Namespace) -> int:
    print_json({
        "ok": True,
        "instances": list_instances(project_root=args.project_root),
    })
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    print_json({
        "ok": True,
        "instance": args.context.public_dict(),
        "config": args.config,
    })
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    overrides = {
        "backend": args.backend,
        "image": args.image,
        "runtime_image_tag": args.runtime_image_tag,
        "auto_build_runtime_image": args.auto_build_runtime_image,
        "docker_context": args.docker_context,
        "network_dns_servers": args.network_dns_servers,
    }
    cfg = merge_config(args.context, overrides)
    save_config(args.context, cfg)
    args.config = cfg
    print_json({
        "ok": True,
        "instance": args.context.public_dict(),
        "config": cfg,
    })
    return 0


def cmd_runtime_build_image(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    if args.dry_run:
        # A dry-run is a plan: it must not contact the Docker engine, so it
        # also works with an unconfigured or unreachable docker context.
        planned_context = str(mgr.context.state_root / "runtime-context" / "<pending>")
        print_json({"ok": True, "dryRun": True, "context": planned_context, "command": [*mgr.docker_base_cmd(), "build", "-t", args.tag, planned_context]})
        return 0
    ctx = mgr.make_runtime_context(args.image)
    if not ctx.get("ok"):
        print_json(ctx); return 1
    proc = subprocess.run([*(runtime(args).docker_base_cmd()), "build", "-t", args.tag, ctx.get("context")], text=True, capture_output=True)
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "tag": args.tag, "context": ctx.get("context")}
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_start(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    result = mgr.start(dry_run=args.dry_run, wait=not args.no_wait, install_daemon_apk=args.install_daemon, start_colima=args.start_colima, adb_root=not args.no_adb_root, skip_preflight=args.skip_preflight, recreate=args.recreate, defer_proxy=args.defer_proxy)
    print_json(result)
    return 0 if result.get("ok") or args.dry_run else 1


def cmd_stop(args: argparse.Namespace) -> int:
    result = runtime(args).stop()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_logs(args: argparse.Namespace) -> int:
    result = runtime(args).runtime_logs(args.out_dir)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_view(args: argparse.Namespace) -> int:
    result = runtime(args).view()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_status(args: argparse.Namespace) -> int:
    result = runtime(args).status()
    print_json(result)
    return 0 if result.get("ok") and result.get("running") else 1


def cmd_adb(args: argparse.Namespace) -> int:
    result = runtime(args).adb(args.adb_args)
    print_json(result)
    return 0 if result.get("ok") else 1


def daemon_ensured(args: argparse.Namespace) -> DaemonClient:
    manager = runtime(args)
    manager.ensure_daemon()
    return daemon(args, manager)



def cmd_daemon_ensure(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    daemon_result = mgr.ensure_daemon(
        readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
    )
    proxy = (
        mgr.reconcile_proxy_desired()
        if daemon_result.get("ok") else {"ok": False, "skipped": True}
    )
    result = {
        "ok": bool(daemon_result.get("ok") and proxy.get("ok")),
        "daemon": daemon_result,
        "proxyConverged": proxy,
    }
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_daemon_health(args: argparse.Namespace) -> int:
    result = daemon(args).health()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_daemon_install(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    install = mgr.install_daemon(args.apk)
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
        mgr.ensure_daemon(readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS)
        if rootd.get("ok") else {"ok": False, "skipped": True}
    )
    proxy = (
        mgr.reconcile_proxy_desired()
        if ready.get("ok") else {"ok": False, "skipped": True}
    )
    result = {
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
    }
    print_json(result)
    return 0 if result["ok"] else 1


def cmd_daemon_start(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    start = mgr.start_daemon_service()
    forward = (
        mgr.forward_daemon_port()
        if start.get("ok") else {"ok": False, "skipped": True}
    )
    rootd = (
        mgr.ensure_rootd_root()
        if forward.get("ok") else {"ok": False, "skipped": True}
    )
    ready = (
        mgr.ensure_daemon(readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS)
        if rootd.get("ok") else {"ok": False, "skipped": True}
    )
    proxy = (
        mgr.reconcile_proxy_desired()
        if ready.get("ok") else {"ok": False, "skipped": True}
    )
    result = {
        "ok": all(
            bool(step.get("ok"))
            for step in (start, forward, rootd, ready, proxy)
        ),
        "start": start,
        "forward": forward,
        "rootd": rootd,
        "ready": ready,
        "proxyConverged": proxy,
    }
    print_json(result)
    return 0 if result["ok"] else 1
_PROXY_ENDPOINT_SCHEMES = {"http", "https", "socks5", "socks5h"}
_PROXY_URI_SCHEMES = {
    "anytls",
    "hysteria",
    "hysteria2",
    "http",
    "https",
    "hy2",
    "mierus",
    "shadowsocks",
    "socks",
    "socks5",
    "socks5h",
    "ss",
    "ssr",
    "trojan",
    "tuic",
    "vless",
    "vmess",
}
_PROXY_CLASH_KEYS = {
    "proxies",
    "proxy-groups",
    "proxy-providers",
}
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


def _proxy_failure(code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "error": code}
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


def _emit_proxy_result(result: dict[str, Any]) -> int:
    sanitized = _sanitize_proxy_result(result)
    if not isinstance(sanitized, dict):
        sanitized = _proxy_failure("proxy_request_failed")
    print_json(sanitized)
    return 0 if sanitized.get("ok") is True else 1


def _call_proxy_daemon(
    args: argparse.Namespace,
    operation: Callable[[DaemonClient], dict[str, Any]],
) -> dict[str, Any]:
    try:
        client = daemon_ensured(args)
        result = operation(client)
    except InstanceError as exc:
        return _proxy_failure(exc.code)
    except Exception:
        return _proxy_failure("daemon_unreachable")
    if not isinstance(result, dict):
        return _proxy_failure("daemon_response_invalid")
    return result
def _call_proxy_controller(
    args: argparse.Namespace,
    operation: Callable[[ProxyController], dict[str, Any]],
    *,
    ensure_daemon: bool = True,
) -> dict[str, Any]:
    try:
        manager = runtime(args)
        if ensure_daemon:
            ensured = manager.ensure_daemon()
            if not isinstance(ensured, dict) or ensured.get("ok") is not True:
                return _proxy_failure("daemon_unreachable")
        controller = ProxyController(
            args.context,
            args.config,
            args.lease,
            manager,
            daemon(args, manager),
        )
        result = operation(controller)
    except InstanceError as exc:
        return _proxy_failure(exc.code)
    except Exception:
        return _proxy_failure("proxy_reconcile_failed")
    if not isinstance(result, dict):
        return _proxy_failure("proxy_reconcile_failed")
    return result




def _read_bounded_proxy_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    remaining = PROXY_MAX_SOURCE_BYTES + 1
    while remaining > 0:
        chunk = os.read(fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_proxy_source_file(value: str) -> tuple[Optional[str], Optional[str]]:
    fd: Optional[int] = None
    try:
        source_path = os.path.expanduser(os.fspath(value))
        before = os.lstat(source_path)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            return None, "source_file_invalid"
        if before.st_size > PROXY_MAX_SOURCE_BYTES:
            return None, "source_too_large"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(source_path, flags)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            return None, "source_file_invalid"
        raw = _read_bounded_proxy_fd(fd)
        after = os.fstat(fd)
        if (
            len(raw) > PROXY_MAX_SOURCE_BYTES
            or after.st_size > PROXY_MAX_SOURCE_BYTES
        ):
            return None, "source_too_large"
        if (
            not raw
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.getuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or after.st_size != len(raw)
        ):
            return None, "source_file_invalid"
        return raw.decode("utf-8"), None
    except UnicodeError:
        return None, "source_invalid"
    except (OSError, TypeError, ValueError):
        return None, "source_file_invalid"
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_proxy_stdin() -> tuple[Optional[str], Optional[str]]:
    try:
        binary_stream = getattr(sys.stdin, "buffer", None)
        if binary_stream is not None:
            raw = binary_stream.read(PROXY_MAX_SOURCE_BYTES + 1)
        else:
            raw = sys.stdin.read(PROXY_MAX_SOURCE_BYTES + 1).encode("utf-8")
        if len(raw) > PROXY_MAX_SOURCE_BYTES:
            return None, "source_too_large"
        if not raw:
            return None, "source_invalid"
        return raw.decode("utf-8"), None
    except UnicodeError:
        return None, "source_invalid"
    except (OSError, ValueError):
        return None, "source_read_failed"


def _read_proxy_prompt() -> tuple[Optional[str], Optional[str]]:
    try:
        value = getpass.getpass("Proxy source: ")
    except (EOFError, KeyboardInterrupt, OSError):
        return None, "source_read_failed"
    try:
        if not value:
            return None, "source_invalid"
        if len(value.encode("utf-8")) > PROXY_MAX_SOURCE_BYTES:
            return None, "source_too_large"
    except UnicodeError:
        return None, "source_invalid"
    return value, None


def _uri_lines_kind(text: str) -> Optional[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    schemes: list[str] = []
    for line in lines:
        try:
            parsed = urlsplit(line)
        except ValueError:
            return None
        scheme = parsed.scheme.lower()
        if (
            scheme not in _PROXY_URI_SCHEMES
            or not line.lower().startswith(f"{scheme}://")
        ):
            return None
        schemes.append(scheme)
    if len(lines) == 1 and schemes[0] in _PROXY_ENDPOINT_SCHEMES:
        return "endpoint"
    return "uri_list"


def _infer_proxy_kind(text: str) -> Optional[str]:
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return None
    try:
        parsed_json = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        parsed_json = None
    if (
        isinstance(parsed_json, dict)
        and any(key in parsed_json for key in _PROXY_CLASH_KEYS)
    ):
        return "clash"

    top_level_keys: set[str] = set()
    for line in stripped.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key = line.split(":", 1)[0].strip()
        if key:
            top_level_keys.add(key)
    if top_level_keys.intersection(_PROXY_CLASH_KEYS):
        return "clash"

    direct = _uri_lines_kind(stripped)
    if direct is not None:
        return direct

    compact = "".join(stripped.split())
    if compact and all(ch.isalnum() or ch in "+/=_-" for ch in compact):
        standard = compact.replace("-", "+").replace("_", "/")
        standard += "=" * ((-len(standard)) % 4)
        try:
            decoded = base64.b64decode(standard, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeError, ValueError):
            decoded = ""
        if _uri_lines_kind(decoded) is not None:
            return "uri_list"
    return None


def _proxy_source_input(
    args: argparse.Namespace,
) -> tuple[Optional[str], Optional[str]]:
    if getattr(args, "prompt", False):
        return _read_proxy_prompt()
    if getattr(args, "stdin", False):
        return _read_proxy_stdin()
    file_value = getattr(args, "source_file", None)
    if file_value is None:
        file_value = getattr(args, "file", None)
    if not isinstance(file_value, str):
        return None, "source_file_invalid"
    return _read_proxy_source_file(file_value)


def _atomic_write_proxy_export(target: str, data: bytes) -> Optional[str]:
    directory_fd: Optional[int] = None
    temporary_name: Optional[str] = None
    temporary_fd: Optional[int] = None
    try:
        expanded = os.path.expanduser(os.fspath(target))
        parent, name = os.path.split(expanded)
        if not name or name in (".", ".."):
            return "export_target_invalid"
        directory_fd = os.open(
            parent or ".",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is not None and not stat.S_ISREG(before.st_mode):
            return "export_target_invalid"

        for _ in range(32):
            candidate = f".{name}.tmp-{secrets.token_hex(8)}"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None or temporary_name is None:
            return "export_failed"

        view = memoryview(data)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                return "export_failed"
            view = view[written:]
        os.fchmod(temporary_fd, 0o600)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if before is None:
            if current is not None:
                return "export_target_invalid"
        elif (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            return "export_target_invalid"

        os.replace(
            temporary_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        return None
    except (OSError, TypeError, ValueError):
        return "export_failed"
    finally:
        if temporary_fd is not None:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if directory_fd is not None and temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


def cmd_proxy_status(args: argparse.Namespace) -> int:
    result = _call_proxy_controller(
        args,
        lambda controller: controller.status(check=args.check),
    )
    return _emit_proxy_result(result)


def cmd_proxy_set(args: argparse.Namespace) -> int:
    source, error = _proxy_source_input(args)
    if error is not None or source is None:
        return _emit_proxy_result(_proxy_failure(error or "source_invalid"))
    kind = args.kind or _infer_proxy_kind(source)
    if kind is None:
        return _emit_proxy_result(_proxy_failure("source_invalid"))
    result = _call_proxy_controller(
        args,
        lambda controller: controller.set_source(
            kind,
            source,
            args.enable,
            selected_node=args.name or "",
            udp_allowed=args.udp,
            allow_insecure_http=args.allow_insecure_http,
        ),
    )
    return _emit_proxy_result(result)


def cmd_proxy_enabled(args: argparse.Namespace) -> int:
    result = _call_proxy_controller(
        args,
        lambda controller: controller.set_enabled(args.proxy_enabled),
    )
    return _emit_proxy_result(result)


def cmd_proxy_clear(args: argparse.Namespace) -> int:
    return _emit_proxy_result(
        _call_proxy_controller(args, lambda controller: controller.clear())
    )


def cmd_proxy_reconcile(args: argparse.Namespace) -> int:
    return _emit_proxy_result(
        _call_proxy_controller(args, lambda controller: controller.reconcile_desired())
    )


def cmd_proxy_list(args: argparse.Namespace) -> int:
    status_result = _call_proxy_controller(
        args,
        lambda controller: controller.reconcile_for_list(),
    )
    if not status_result.get("ok"):
        return _emit_proxy_result(status_result)
    report = status_result.get("report")
    nodes: list[str] = []
    node_count = 0
    selected = ""
    if isinstance(report, dict):
        observed_nodes = report.get("nodes")
        if isinstance(observed_nodes, list):
            nodes = [node for node in observed_nodes if isinstance(node, str)]
        observed_count = report.get("nodeCount")
        if isinstance(observed_count, int) and not isinstance(observed_count, bool):
            node_count = max(0, observed_count)
        observed_selected = report.get("selectedNode")
        if isinstance(observed_selected, str):
            selected = observed_selected
    if not nodes and isinstance(selected, str) and selected and node_count > 0:
        nodes = [selected]
    return _emit_proxy_result(
        {
            "ok": True,
            "nodeCount": node_count,
            "selectedNode": selected if isinstance(selected, str) else "",
            "nodes": nodes,
            "complete": len(nodes) == node_count,
        }
    )


def cmd_proxy_select(args: argparse.Namespace) -> int:
    return _emit_proxy_result(
        _call_proxy_controller(args, lambda controller: controller.select(args.name))
    )


def cmd_proxy_export(args: argparse.Namespace) -> int:
    exported = _call_proxy_daemon(args, lambda client: client.proxy_export())
    if not exported.get("ok"):
        return _emit_proxy_result(exported)
    source = exported.get("source")
    if not isinstance(source, dict):
        return _emit_proxy_result(_proxy_failure("source_missing"))
    kind = source.get("kind")
    value = source.get("value")
    if kind not in ("endpoint", "uri_list", "clash", "subscription") or not isinstance(value, str):
        return _emit_proxy_result(_proxy_failure("daemon_response_invalid"))
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        return _emit_proxy_result(_proxy_failure("daemon_response_invalid"))
    if not raw or len(raw) > PROXY_MAX_SOURCE_BYTES:
        return _emit_proxy_result(_proxy_failure("daemon_response_invalid"))
    error = _atomic_write_proxy_export(args.out, raw)
    if error is not None:
        return _emit_proxy_result(_proxy_failure(error))
    return _emit_proxy_result(
        {
            "ok": True,
            "kind": kind,
            "digest": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
    )


def cmd_proxy_prepare(args: argparse.Namespace) -> int:
    return _emit_proxy_result(
        _call_proxy_controller(
            args,
            lambda controller: controller.prepare(args.asset),
            ensure_daemon=False,
        )
    )

_CAMERA_PRIVATE_KEYS = {
    "bytes",
    "command",
    "digest",
    "path",
    "sha256",
    "token",
    "upload",
    "uri",
    "url",
}


def _sanitize_camera_result(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            normalized = "".join(ch for ch in str(key).lower() if ch.isalnum())
            private = (
                normalized in _CAMERA_PRIVATE_KEYS
                or normalized.endswith(("bytes", "command", "digest", "path", "sha256", "token", "uri", "url"))
                or normalized.startswith("original")
                or "decoder" in normalized
                or "mediabytes" in normalized
                or "stagingpath" in normalized
            )
            if not private:
                clean[str(key)] = _sanitize_camera_result(item)
        return clean
    if isinstance(value, list):
        return [_sanitize_camera_result(item) for item in value]
    return value


def _emit_camera_result(result: dict[str, Any]) -> int:
    sanitized = _sanitize_camera_result(result)
    if not isinstance(sanitized, dict):
        sanitized = {"ok": False, "error": "invalid camera response"}
    print_json(sanitized)
    return 0 if bool(sanitized.get("ok")) else 1


def _camera_ready(
    args: argparse.Namespace,
) -> tuple[Optional[RuntimeManager], Optional[DaemonClient]]:
    try:
        manager = runtime(args)
        ensured = manager.ensure_daemon(
            readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
        )
        if not ensured.get("ok"):
            return None, None
        return manager, daemon(args, manager)
    except Exception:
        return None, None

def _camera_request(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = call()
    except Exception:
        return {"ok": False, "error": "camera request failed"}
    if not isinstance(result, dict):
        return {"ok": False, "error": "invalid camera response"}
    return result


def cmd_camera_status(args: argparse.Namespace) -> int:
    manager, client = _camera_ready(args)
    if manager is None or client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    if not args.check:
        return _emit_camera_result(_camera_request(client.camera_status))

    try:
        permission = manager.grant_daemon_camera_permission()
    except Exception:
        permission = {"ok": False}
    if not permission.get("ok"):
        return _emit_camera_result({"ok": False, "error": "camera permission grant failed"})
    run_id = secrets.token_hex(16)
    authorization = _camera_request(lambda: client.camera_self_test_start(run_id))
    if not authorization.get("ok"):
        result = dict(authorization)
        result.setdefault("runId", run_id)
        result.setdefault("state", "error")
        result.setdefault("error", "camera self-test authorization failed")
        return _emit_camera_result(result)
    try:
        launch = manager.launch_camera_self_test(run_id)
    except Exception:
        launch = {"ok": False}
    if not launch.get("ok"):
        return _emit_camera_result({
            "ok": False,
            "runId": run_id,
            "state": "error",
            "error": "camera self-test launch failed",
        })

    deadline = time.monotonic() + 90.0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        status = _camera_request(lambda: client.camera_self_test_status(timeout=min(5.0, remaining)))
        if status.get("runId") == run_id:
            state = status.get("state")
            if state == "success":
                result = dict(status)
                result["ok"] = bool(status.get("ok"))
                if not result["ok"]:
                    result.setdefault("error", "camera self-test failed")
                return _emit_camera_result(result)
            if state == "error":
                result = dict(status)
                result["ok"] = False
                result.setdefault("error", "camera self-test failed")
                return _emit_camera_result(result)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.5, remaining))
    return _emit_camera_result({
        "ok": False,
        "runId": run_id,
        "state": "error",
        "error": "camera self-test timed out",
    })


def cmd_camera_set(args: argparse.Namespace) -> int:
    try:
        source = Path(args.file).expanduser().resolve(strict=True)
        source_stat = source.stat()
    except (OSError, RuntimeError, TypeError):
        return _emit_camera_result({
            "ok": False,
            "error": "camera source must be a nonempty regular file",
        })
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size <= 0:
        return _emit_camera_result({
            "ok": False,
            "error": "camera source must be a nonempty regular file",
        })

    manager, client = _camera_ready(args)
    if manager is None or client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})

    staging_path: Optional[str] = None
    result: dict[str, Any]
    try:
        staged = manager.stage_camera_source(source)
        if not staged.get("ok"):
            result = {"ok": False, "error": str(staged.get("error") or "camera source upload failed")}
        else:
            staging_path = staged.get("stagingPath")
            size = staged.get("size")
            digest = staged.get("sha256")
            if not isinstance(staging_path, str) or not isinstance(size, int) or not isinstance(digest, str):
                result = {"ok": False, "error": "camera source staging failed"}
            else:
                result = _camera_request(lambda: client.camera_source(args.kind, staging_path, size, digest))
    except Exception:
        result = {"ok": False, "error": "camera source staging failed"}
    finally:
        if staging_path is not None:
            try:
                manager.cleanup_camera_staging(staging_path)
            except Exception:
                pass
    return _emit_camera_result(result)


def cmd_camera_mode(args: argparse.Namespace) -> int:
    _, client = _camera_ready(args)
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(lambda: client.camera_settings(args.mode)))


def cmd_camera_clear(args: argparse.Namespace) -> int:
    _, client = _camera_ready(args)
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(lambda: client.camera_clear(args.kind)))


def cmd_camera_apply(args: argparse.Namespace) -> int:
    _, client = _camera_ready(args)
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(client.camera_apply))


def _location_failure(code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "error": code}


# Daemon failures that mean the rootd/publish control plane is down; the
# converge loop may repair it once or twice before giving up.
_LOCATION_REPAIRABLE_CODES = frozenset({
    "daemon_unreachable",
    "location_profile_publish_failed",
    "location_state_publish_failed",
    "location_property_publish_failed",
    "location_apn_publish_failed",
})


def _location_daemon_apk(args: argparse.Namespace) -> Optional[str]:
    apk = args.project_root / "daemon" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
    return str(apk) if apk.is_file() else None


def _location_epoch(manager: RuntimeManager) -> str:
    container_id = manager.location_runtime_container_id()
    return location_runtime_epoch(container_id) if container_id else ""


def _location_android_status(client: DaemonClient) -> Optional[dict[str, Any]]:
    try:
        status = client.location_status()
    except Exception:
        return None
    if not isinstance(status, dict) or status.get("ok") is not True:
        return None
    if status.get("state") == "absent":
        return None
    return status


def _location_error_code(result: Any, fallback: str) -> str:
    if isinstance(result, dict):
        for key in ("code", "error"):
            candidate = result.get(key)
            if isinstance(candidate, str):
                if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", candidate):
                    return candidate
                # Daemon exceptions arrive as "java.lang.IllegalStateException:
                # location_<code>"; recover the stable code token.
                embedded = re.search(r"location_[a-z0-9_]{1,63}", candidate)
                if embedded:
                    return embedded.group(0)
    return fallback


def _location_stage(
    store: LocationStateStore,
    client: DaemonClient,
    state: Mapping[str, Any],
    runtime_epoch: str,
    *,
    mark: bool,
) -> None:
    profile = store.target_profile(state)
    encoded = encode_profile_v1(profile)
    request = {
        "schema": STAGE_SCHEMA,
        "profile": profile,
        "encodedProfile": base64.b64encode(encoded).decode("ascii"),
        "profileDigest": profile["identityDigest"],
        "locationKey": profile["locationKey"],
        "runtimeEpoch": runtime_epoch,
    }
    result = client.location_stage(request)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise LocationError(_location_error_code(result, "location_stage_failed"))
    if mark:
        store.mark_staged(runtime_epoch)


def _location_converge(
    args: argparse.Namespace,
    manager: RuntimeManager,
    store: LocationStateStore,
    *,
    rebind_proxy: bool,
) -> dict[str, Any]:
    """Drive the persisted location transaction to a verified steady state."""
    recreated = False
    verify_failures = 0
    repairs = 0
    verified_payload: Optional[dict[str, Any]] = None

    def repair_if_possible() -> bool:
        nonlocal repairs
        if repairs >= 2:
            return False
        repairs += 1
        repaired = manager.repair_control_plane()
        return bool(isinstance(repaired, dict) and repaired.get("ok") is True)

    for _ in range(12):
        state = store.load()
        if state is None:
            raise LocationError("location_state_missing")
        epoch = _location_epoch(manager)
        client: Optional[DaemonClient] = None
        android: Optional[dict[str, Any]] = None
        if epoch:
            ensured = manager.ensure_daemon(readiness_timeout=90.0)
            if not (isinstance(ensured, dict) and ensured.get("ok") is True):
                # A fresh container can lose the adb lease or the exec'd rootd
                # right after start reports success; repair instead of failing
                # the whole transaction on the transient.
                repair_if_possible()
                ensured = manager.ensure_daemon(readiness_timeout=60.0)
            if isinstance(ensured, dict) and ensured.get("ok") is True:
                client = daemon(args, manager)
                android = _location_android_status(client)
        action = convergence_action(state, android, epoch)
        step = action.get("step")
        if step == "noop":
            break
        if step == "bootstrap":
            started = manager.start(
                wait=True,
                install_daemon_apk=_location_daemon_apk(args),
                start_colima=manager.should_use_colima(),
                adb_root=False,
                skip_preflight=True,
                recreate=False,
                defer_proxy=True,
            )
            if not isinstance(started, dict) or started.get("ok") is not True:
                raise LocationError("location_runtime_start_failed")
            continue
        if step == "stage":
            if not epoch or client is None:
                raise LocationError("daemon_unreachable")
            try:
                _location_stage(store, client, state, epoch, mark=True)
            except LocationError as failure:
                if failure.code in _LOCATION_REPAIRABLE_CODES and repair_if_possible():
                    continue
                raise
            if action.get("recreate"):
                store.arm_restart()
            continue
        if step == "recreate":
            started = manager.start(
                wait=True,
                install_daemon_apk=_location_daemon_apk(args),
                start_colima=manager.should_use_colima(),
                adb_root=False,
                skip_preflight=True,
                recreate=True,
                defer_proxy=True,
            )
            if not isinstance(started, dict) or started.get("ok") is not True:
                raise LocationError("location_recreate_failed")
            recreated = True
            continue
        if step == "resume":
            store.mark_restarted(str(action["runtimeEpoch"]))
            continue
        if step == "verify":
            if not epoch or client is None:
                raise LocationError("daemon_unreachable")
            if action.get("restage"):
                try:
                    _location_stage(store, client, state, epoch, mark=False)
                except LocationError as failure:
                    if failure.code in _LOCATION_REPAIRABLE_CODES and repair_if_possible():
                        continue
                    raise
                state = store.load()
                if state is None:
                    raise LocationError("location_state_missing")
            digest = store.target_profile(state)["identityDigest"]
            verified = client.location_verify(digest, epoch)
            if (
                isinstance(verified, dict)
                and verified.get("ok") is True
                and verified.get("verified") is True
            ):
                verified_payload = verified
                if action.get("promote"):
                    store.promote(epoch)
                else:
                    store.mark_validated(epoch)
                continue
            if not action.get("promote"):
                # Active refresh failed read-back: escalate once into the pending
                # restore transaction so the identity is restaged and the container
                # epoch rotates exactly once through the same crash-safe path.
                active = state.get("active")
                if not isinstance(active, Mapping):
                    raise LocationError(_location_error_code(verified, "location_identity_unverified"))
                store.set_desired(str(active["country"]))
                continue
            verify_code = _location_error_code(verified, "location_identity_unverified")
            if verify_code in _LOCATION_REPAIRABLE_CODES and repair_if_possible():
                continue
            # A fresh container can outlast one verify budget while the data
            # call comes up after the app-data wipe; allow exactly one retry.
            verify_failures += 1
            if verify_failures < 2:
                continue
            raise LocationError(verify_code)
        raise LocationError("location_phase_invalid")
    else:
        raise LocationError("location_convergence_failed")

    legacy_cleaned = True
    try:
        store.drop_legacy()
    except LocationError:
        legacy_cleaned = False
    proxy_rebind: dict[str, Any] = {"ok": True, "skipped": True}
    if rebind_proxy:
        try:
            rebound = manager.reconcile_proxy_desired()
            proxy_rebind = rebound if isinstance(rebound, dict) else _location_failure(
                "proxy_reconcile_failed"
            )
        except Exception:
            proxy_rebind = _location_failure("proxy_reconcile_failed")
    state = store.load()
    result: dict[str, Any] = {
        "ok": True,
        "recreated": recreated,
        "identity": public_summary(state),
        "android": masked_android_status(verified_payload),
        "proxyRebind": proxy_rebind,
    }
    if not legacy_cleaned:
        result["legacyCleanup"] = False
    return result


def cmd_location_list(args: argparse.Namespace) -> int:
    try:
        store = LocationStateStore(args.context.state_root)
        try:
            state = store.load()
        except LocationError:
            state = None
        active = state.get("active") if isinstance(state, Mapping) else None
        result = {
            "ok": True,
            "defaultCountry": DEFAULT_COUNTRY,
            "desiredCountry": state.get("desiredCountry") if isinstance(state, Mapping) else None,
            "activeCountry": active.get("country") if isinstance(active, Mapping) else None,
            "countries": supported_countries(),
        }
    except (CellularError, LocationError) as exc:
        result = _location_failure(exc.code)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_location_status(args: argparse.Namespace) -> int:
    try:
        store = LocationStateStore(args.context.state_root)
        state = store.load()
        host = public_summary(state)
        manager = runtime(args)
        epoch = _location_epoch(manager)
        android: dict[str, Any] = {"ok": False, "error": "runtime_not_running"}
        if epoch:
            try:
                android = masked_android_status(daemon(args, manager).location_status())
            except Exception:
                android = {"ok": False, "error": "daemon_unreachable"}
        checked = True
        if args.check:
            active = state.get("active") if isinstance(state, Mapping) else None
            checked = bool(
                isinstance(active, Mapping)
                and android.get("ok") is True
                and android.get("state") == "active"
                and android.get("profileDigest") == active.get("profileDigest")
                and epoch
                and android.get("runtimeEpoch") == epoch
            )
        result = {"ok": bool(checked), "host": host, "android": android}
    except (CellularError, LocationError, InstanceError) as exc:
        result = _location_failure(exc.code)
    except Exception:
        result = _location_failure("location_status_failed")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_location_set(args: argparse.Namespace) -> int:
    try:
        manager = runtime(args)
        store = LocationStateStore(args.context.state_root)
        target = normalize_country(args.country)
        store.ensure(args.context.instance_id, target)
        store.set_desired(target)
        result = _location_converge(args, manager, store, rebind_proxy=True)
    except (CellularError, LocationError, InstanceError) as exc:
        result = _location_failure(exc.code)
    except Exception:
        result = _location_failure("location_convergence_failed")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_location_apply(args: argparse.Namespace) -> int:
    """Internal production path used by xenoid-up: converge the persisted location."""
    try:
        manager = runtime(args)
        store = LocationStateStore(args.context.state_root)
        default = normalize_country(args.default) if args.default else None
        state, _ = store.ensure(args.context.instance_id, default)
        store.set_desired(str(state["desiredCountry"]))
        result = _location_converge(args, manager, store, rebind_proxy=False)
    except (CellularError, LocationError, InstanceError) as exc:
        result = _location_failure(exc.code)
    except Exception:
        result = _location_failure("location_convergence_failed")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_cellular_status(args: argparse.Namespace) -> int:
    """Low-level radio smoke view: daemon location state plus radio properties."""
    try:
        manager = runtime(args)
        store = LocationStateStore(args.context.state_root)
        try:
            host = public_summary(store.load())
        except LocationError:
            host = {"state": "invalid"}
        client = daemon_ensured(args)
        location = masked_android_status(client.location_status())
        props: dict[str, str] = {}
        for name in (
            "persist.xenoid.radio.profile_digest",
            "persist.xenoid.radio.lte_band",
            "persist.xenoid.radio.lte_bandwidth_khz",
            "gsm.operator.numeric",
            "gsm.sim.state",
            "persist.sys.locale",
            "persist.sys.timezone",
        ):
            out = manager.adb(["shell", "getprop", name])
            props[name] = out.get("stdout", "").strip() if out.get("ok") else ""
        result = {"ok": bool(location.get("ok")), "host": host, "radio": props, "location": location}
    except (CellularError, LocationError, InstanceError) as exc:
        result = _location_failure(exc.code)
    except Exception:
        result = _location_failure("cellular_status_failed")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_root_status(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).root_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_root_exec(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).root_exec(" ".join(args.command))
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_fetch(args: argparse.Namespace) -> int:
    result = runtime(args).fetch_frida(version=args.version, arch=args.arch, out_dir=args.out_dir)
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_frida_install(args: argparse.Namespace) -> int:
    result = runtime(args).install_frida(
        version=args.version,
        arch=args.arch,
        out_dir=args.out_dir,
        remote_path=args.remote_path,
    )
    print_json(result)
    return 0 if result.get("ok") else 1



def cmd_frida_deploy_scripts(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_frida_scripts(args.scripts_dir, args.remote_dir)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_load_script(args: argparse.Namespace) -> int:
    result = runtime(args).load_frida_script(args.package, args.script, spawn=args.spawn, oneshot=args.oneshot)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_deploy(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_frida(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_start(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).frida_start(port=args.port)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_stop(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).frida_stop()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_status(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).frida_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1



def cmd_profile_deploy_helper(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_profile_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_profile_helper_status(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).profile_helper_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_env(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).profile_helper_env()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_dump(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).profile_helper_dump()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_collect(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).collect_fingerprint()
    if args.out and result.get("ok", True):
        write_json_file(args.out, result)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_apply(args: argparse.Namespace) -> int:
    profile = read_json_file(args.profile)
    manager = runtime(args)
    ensured = manager.ensure_daemon()
    if not isinstance(ensured, dict) or ensured.get("ok") is not True:
        result: dict[str, Any] = {
            "ok": False,
            "error": "daemon_unreachable",
            "daemon": ensured,
        }
    else:
        if args.keep_unique and not args.instance_identity:
            # Legacy --keep-unique path: apply profile without host identity convergence.
            result = daemon(args, manager).apply_fingerprint(profile, regenerate_unique=False)
        else:
            result = converge_instance_identity(
                args.context,
                manager,
                daemon(args, manager),
                profile,
                rotate_stable=not args.keep_unique and not args.instance_identity,
            )
    if args.generate_frida:
        result = {
            "daemon": result,
            "fridaProfile": manager.generate_profile_frida(
                args.profile,
                args.frida_out,
                True,
            ),
        }
        result["ok"] = bool(
            result["daemon"].get("ok")
            and result["fridaProfile"].get("ok")
        )
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_generate_service_frida(args: argparse.Namespace) -> int:
    result = runtime(args).generate_service_frida(args.profile, args.out, args.keep_unique)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_device_generate_frida(args: argparse.Namespace) -> int:
    result = runtime(args).generate_profile_frida(args.profile, args.out, args.keep_unique)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_device_set(args: argparse.Namespace) -> int:
    value: Any = args.value
    key = identity_field_key(args.field)
    if key is not None:
        validate_identity_value(key, value)
    result = daemon_ensured(args).set_fingerprint_field(args.field, value)
    if key is not None and result.get("ok") is True:
        state = DeviceIdentityStore(args.context).update_field(args.field, value)
        result = {
            "ok": True,
            "daemon": result,
            "identity": public_identity_state(state),
        }
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_automation_plan(args: argparse.Namespace) -> int:
    result = runtime(args).automation_plan(args.script)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run_host(args: argparse.Namespace) -> int:
    manager = runtime(args)
    result = manager.automation_run_host(
        args.script,
        execute=args.execute,
        endpoint=daemon(args, manager).base,
    )
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).run_automation(args.script)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_deploy(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_input_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_input_tap(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).tap(args.x, args.y)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_swipe(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).swipe(args.x1, args.y1, args.x2, args.y2, args.duration_ms)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_install(args: argparse.Namespace) -> int:
    source = Path(args.path).expanduser()
    if source.is_file():
        manager = runtime(args)
        remote = "/data/local/tmp/xenoid-install.apk"
        upload = manager.adb(["push", str(source.resolve()), remote])
        if not upload.get("ok"):
            print_json({"ok": False, "error": "APK upload failed", "upload": upload})
            return 1
        result = daemon_ensured(args).app_install(remote)
        result["upload"] = upload
        result["cleanup"] = manager.adb(["shell", "rm", "-f", remote])
        result["source"] = str(source.resolve())
    else:
        result = daemon_ensured(args).app_install(args.path)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_uninstall(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).app_uninstall(args.package)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_launch(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).app_launch(args.component)
    print_json(result)
    return 0 if result.get("ok", False) else 1



def cmd_hide_deploy(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_hide_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_deploy_overlay(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_hide_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_netctl_deploy(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_netctl_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_netctl_status(args: argparse.Namespace) -> int:
    result = runtime(args).netctl_status(args.ifname)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_netctl_set_mac(args: argparse.Namespace) -> int:
    result = runtime(args).netctl_set_mac(args.mac, args.ifname)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_overlay_status(args: argparse.Namespace) -> int:
    result = runtime(args).overlay_status()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_cleanup_overlay(args: argparse.Namespace) -> int:
    result = runtime(args).overlay_cleanup()
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_hide_status(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).hide_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_hide_apply(args: argparse.Namespace) -> int:
    policy = read_json_file(args.policy) if args.policy else None
    result = daemon_ensured(args).hide_apply(policy)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_ota_make(args: argparse.Namespace) -> int:
    result = runtime(args).make_ota_bundle(args.version)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ota_install_bundle(args: argparse.Namespace) -> int:
    result = runtime(args).apply_ota_bundle(args.bundle)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ota_check(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).ota_check()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_ota_apply(args: argparse.Namespace) -> int:
    result = daemon_ensured(args).ota_apply(args.channel)
    print_json(result)
    return 0 if result.get("ok", False) else 1







def _ebpf_script_args(args: argparse.Namespace) -> list[str]:
    out: list[str] = []
    mode = getattr(args, "mode", None)
    if mode == "colima":
        out.append("--colima")
    elif mode == "local":
        out.append("--local")
    elif mode == "ssh":
        out.extend(["--ssh", args.ssh])
        if getattr(args, "ssh_port", None):
            out.extend(["--ssh-port", str(args.ssh_port)])
    return out


def cmd_ebpf_build(args: argparse.Namespace) -> int:
    script = args.context.project_root / "scripts" / "build-ebpf.sh"
    cmd = [str(script), *_ebpf_script_args(args)]
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        cwd=args.context.project_root,
        env=command_env(args),
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}
    # Prefer script JSON line when present.
    for line in reversed((proc.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                result.update(json.loads(line))
            except Exception:
                pass
            break
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ebpf_action(args: argparse.Namespace) -> int:
    script = args.context.project_root / "scripts" / "load-ebpf.sh"
    action = args.ebpf_action
    cmd = [str(script), *_ebpf_script_args(args), action]
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        cwd=args.context.project_root,
        env=command_env(args),
    )
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script), "action": action}
    for line in reversed((proc.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                result.update(json.loads(line))
            except Exception:
                pass
            break
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_mcp_config(args: argparse.Namespace) -> int:
    print_json({
        "mcpServers": {
            "xenoid": {
                "command": sys.executable,
                "args": ["-m", "xenoid.mcp_server"],
                "env": {
                    "XENOID_PROJECT": str(args.context.project_root),
                    "XENOID_INSTANCE": args.context.instance_name,
                },
            }
        }
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="xenoid", description="Xenoid Android runtime CLI")
    p.add_argument(
        "--instance",
        help="immutable instance name (default: XENOID_INSTANCE or default)",
    )
    sub = p.add_subparsers(dest="top_command", required=True)

    s = sub.add_parser("install-runtime", help="install macOS runtime dependencies via Homebrew and start Colima")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_install_runtime)

    s = sub.add_parser("doctor", help="check installation, host dependencies, and the live runtime")
    s.add_argument("--full", action="store_true", help="also build artifacts and run exhaustive runtime smoke checks")
    s.add_argument("--require-runtime", action="store_true", help="fail when Android is not running and ready")
    s.add_argument("--out", help="also write the JSON report to this path")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("up", help="build and start full Xenoid stack")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--skip-build", action="store_true", help="use prebuilt artifacts (release target); fails if any required binary is missing")
    s.set_defaults(func=cmd_up)


    s = sub.add_parser("linux-binderfs", help="setup Linux binderfs devices for redroid")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_linux_binderfs)



    s = sub.add_parser("runtime-build-image", help="build custom redroid Docker image with Xenoid payloads")
    s.add_argument("--image", help="base redroid image")
    s.add_argument("--tag", default="xenoid/redroid:local")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_runtime_build_image)

    s = sub.add_parser("runtime-context", help="create custom redroid Docker build context with Xenoid payloads")
    s.add_argument("--image", help="base redroid image")
    s.set_defaults(func=cmd_runtime_context)

    s = sub.add_parser("make-rootfs", help="build/refresh ext4 rootfs+data loop images for the pivot entrypoint")
    s.set_defaults(func=cmd_make_rootfs)

    s = sub.add_parser("build", help="build daemon APK and native helpers")
    bsub = s.add_subparsers(required=True)
    bd = bsub.add_parser("daemon")
    bd.set_defaults(func=cmd_build_daemon)
    bi = bsub.add_parser("input")
    bi.set_defaults(func=cmd_build_input)
    bh = bsub.add_parser("hide")
    bh.set_defaults(func=cmd_build_hide)
    bp = bsub.add_parser("profile")
    bp.set_defaults(func=cmd_build_profile)
    bn = bsub.add_parser("netctl")
    bn.set_defaults(func=cmd_build_netctl)
    bg = bsub.add_parser("gralloc")
    bg.set_defaults(func=cmd_build_gralloc)
    br = bsub.add_parser("ril")
    br.set_defaults(func=cmd_build_ril)
    brc = bsub.add_parser("radio-config")
    brc.set_defaults(func=cmd_build_radio_config)
    ba = bsub.add_parser("all")
    ba.set_defaults(func=cmd_build_all)

    s = sub.add_parser("verify-release", help="verify a Xenoid release bundle manifest and required artifacts")
    s.add_argument("archive")
    s.set_defaults(func=cmd_verify_release)

    s = sub.add_parser("package-release", help="package transferable Xenoid release bundle")
    s.add_argument("--version", default="dev")
    s.set_defaults(func=cmd_package_release)


    s = sub.add_parser("instance", help="list initialized Xenoid instances")
    instance_sub = s.add_subparsers(dest="instance_command", required=True)
    instance_list = instance_sub.add_parser("list", help="list initialized instances")
    instance_list.set_defaults(func=cmd_instance_list)

    s = sub.add_parser("config", help="show or update selected instance config")
    csub = s.add_subparsers(required=True)
    cs = csub.add_parser("show")
    cs.set_defaults(func=cmd_config_show)
    cset = csub.add_parser("set")
    cset.add_argument("--backend")
    cset.add_argument("--image")
    cset.add_argument("--runtime-image-tag")
    cset.add_argument("--docker-context")
    cset.add_argument(
        "--network-dns-server",
        dest="network_dns_servers",
        action="append",
        metavar="ADDRESS",
    )
    cset.add_argument("--auto-build-runtime-image", action=argparse.BooleanOptionalAction, default=None)
    cset.set_defaults(func=cmd_config_set)

    s = sub.add_parser("init", help="initialize the selected immutable instance")
    s.add_argument("--image")
    s.add_argument("--backend")
    s.add_argument("--config", help="operational config template to merge (e.g. examples/config-macos-colima.json)")
    s.add_argument("--from", dest="from_instance", help="clone operational config from an existing instance")
    s.set_defaults(func=cmd_init)


    s = sub.add_parser("start", help="start the low-level Android runtime without full Xenoid state convergence")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--no-wait", action="store_true", help="do not wait for adb boot")
    s.add_argument("--start-colima", action="store_true", help="run colima start before docker run")
    s.add_argument("--install-daemon", help="install daemon APK after boot")
    s.add_argument("--no-adb-root", action="store_true", help="skip adb root after boot")
    s.add_argument("--skip-preflight", action="store_true", help="skip runtime preflight checks")
    s.add_argument("--recreate", action="store_true", help="replace an existing container so image and runtime arguments take effect")
    s.add_argument("--defer-proxy", action="store_true", help="defer proxy convergence to the caller (internal up/location path)")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("stop", help="stop Android runtime")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("logs", help="collect Docker/ADB runtime logs")
    s.add_argument("--out-dir")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("view", help="open scrcpy for the Xenoid Android target")
    s.set_defaults(func=cmd_view)

    s = sub.add_parser("status", help="runtime status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("adb", help="run adb against xenoid target")
    s.add_argument("adb_args", nargs=argparse.REMAINDER)
    s.set_defaults(func=cmd_adb)

    s = sub.add_parser("daemon", help="daemon API helpers")
    dsub = s.add_subparsers(required=True)
    h = dsub.add_parser("health")
    h.set_defaults(func=cmd_daemon_health)
    di = dsub.add_parser("install")
    di.add_argument("apk")
    di.set_defaults(func=cmd_daemon_install)
    ds = dsub.add_parser("start")
    ds.set_defaults(func=cmd_daemon_start)
    de = dsub.add_parser("ensure")
    de.set_defaults(func=cmd_daemon_ensure)
    s = sub.add_parser("location", help="manage the explicit, proxy-independent device location identity")
    location = s.add_subparsers(required=True)
    location_list = location.add_parser("list", help="list supported countries without contacting the runtime")
    location_list.set_defaults(func=cmd_location_list)
    location_status = location.add_parser("status", help="show masked host and Android location identity state")
    location_status.add_argument("--check", action="store_true", help="require matching active host and Android digests in the current runtime epoch")
    location_status.set_defaults(func=cmd_location_status)
    location_set = location.add_parser("set", help="select a country and converge SIM, carrier, LTE cell, locale, and timezone")
    location_set.add_argument("country", help="ISO 3166-1 alpha-2 country code (see location list)")
    location_set.set_defaults(func=cmd_location_set)
    location_apply = location.add_parser("apply", help="converge the persisted location identity (internal up path)")
    location_apply.add_argument("--default", help="country applied when no location state exists yet")
    location_apply.set_defaults(func=cmd_location_apply)

    s = sub.add_parser("cellular", help="low-level cellular radio smoke view")
    cellular = s.add_subparsers(required=True)
    cellular_status = cellular.add_parser("status", help="show masked location state and radio properties")
    cellular_status.set_defaults(func=cmd_cellular_status)

    s = sub.add_parser(
        "proxy",
        help="manage the selected instance global proxy without putting credentials in argv",
    )
    proxy = s.add_subparsers(required=True)
    proxy_status = proxy.add_parser("status", help="show redacted proxy status")
    proxy_status.add_argument(
        "--check",
        action="store_true",
        help="request and wait for a fresh instance/runtime-bound check",
    )
    proxy_status.set_defaults(func=cmd_proxy_status)

    def add_proxy_policy_flags(
        command: argparse.ArgumentParser,
        *,
        include_kind: bool = True,
    ) -> None:
        if include_kind:
            command.add_argument(
                "--kind",
                choices=["endpoint", "uri_list", "clash", "subscription"],
                help="source structure (inferred from content when omitted)",
            )
        command.add_argument("--name", help="desired node name")
        command.add_argument(
            "--udp",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="allow UDP proxying (default: --udp)",
        )
        command.add_argument(
            "--allow-insecure-http",
            action="store_true",
            help="explicitly allow an insecure HTTP source",
        )
        command.add_argument(
            "--enable",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="enable after configuring (default: --enable)",
        )

    proxy_set = proxy.add_parser(
        "set",
        help="set a source from stdin or a current-user-owned mode-0600 file",
    )
    proxy_set_input = proxy_set.add_mutually_exclusive_group(required=True)
    proxy_set_input.add_argument(
        "--stdin",
        action="store_true",
        help="read at most 1 MiB from stdin",
    )
    proxy_set_input.add_argument(
        "--prompt",
        action="store_true",
        help="read one endpoint or URI without terminal echo",
    )
    proxy_set_input.add_argument(
        "--source-file",
        metavar="FILE",
        help="read a regular, non-symlink, current-user-owned mode-0600 file",
    )
    add_proxy_policy_flags(proxy_set)
    proxy_set.set_defaults(func=cmd_proxy_set)
    proxy_subscribe = proxy.add_parser(
        "subscribe",
        help="set an online configuration URL from stdin or a private file",
    )
    proxy_subscribe_input = proxy_subscribe.add_mutually_exclusive_group(required=True)
    proxy_subscribe_input.add_argument(
        "--stdin",
        action="store_true",
        help="read one HTTP(S) subscription URL from stdin",
    )
    proxy_subscribe_input.add_argument(
        "--prompt",
        action="store_true",
        help="read one subscription URL without terminal echo",
    )
    proxy_subscribe_input.add_argument(
        "--source-file",
        metavar="FILE",
        help="read one HTTP(S) subscription URL from a mode-0600 file",
    )
    add_proxy_policy_flags(proxy_subscribe, include_kind=False)
    proxy_subscribe.set_defaults(func=cmd_proxy_set, kind="subscription")

    proxy_import = proxy.add_parser(
        "import",
        help="import a regular, non-symlink, current-user-owned mode-0600 FILE",
    )
    proxy_import.add_argument(
        "file",
        metavar="FILE",
        help="Clash or URI-list source; must be current-user-owned mode 0600",
    )
    add_proxy_policy_flags(proxy_import)
    proxy_import.set_defaults(func=cmd_proxy_set, stdin=False, source_file=None)

    proxy_on = proxy.add_parser("on", help="enable the configured source")
    proxy_on.set_defaults(func=cmd_proxy_enabled, proxy_enabled=True)
    proxy_off = proxy.add_parser(
        "off",
        help="disable proxying while preserving the configured source",
    )
    proxy_off.set_defaults(func=cmd_proxy_enabled, proxy_enabled=False)
    proxy_clear = proxy.add_parser("clear", help="disable and clear the configured source")
    proxy_clear.set_defaults(func=cmd_proxy_clear)
    proxy_list = proxy.add_parser(
        "list",
        help="list only nodes present in redacted agent status observations",
    )
    proxy_list.set_defaults(func=cmd_proxy_list)
    proxy_select = proxy.add_parser("select", help="select an observed node")
    proxy_select.add_argument("name", metavar="NAME")
    proxy_select.set_defaults(func=cmd_proxy_select)
    proxy_export = proxy.add_parser(
        "export",
        help="atomically export source bytes to a private mode-0600 file",
    )
    proxy_export.add_argument("--out", required=True, metavar="FILE")
    proxy_export.set_defaults(func=cmd_proxy_export)
    proxy_prepare = proxy.add_parser(
        "prepare",
        help="prepare the digest-pinned proxy engine asset on the Docker engine host",
    )
    proxy_prepare.add_argument("--asset", metavar="FILE")
    proxy_prepare.set_defaults(func=cmd_proxy_prepare)
    proxy_reconcile = proxy.add_parser(
        "reconcile",
        help="converge the persisted proxy desired state (internal up path)",
    )
    proxy_reconcile.set_defaults(func=cmd_proxy_reconcile)

    s = sub.add_parser("camera", help="configure Android-owned camera media")
    camera = s.add_subparsers(required=True)
    camera_status = camera.add_parser("status", help="show camera source and activation status")
    camera_status.add_argument("--check", action="store_true", help="run a fresh ordinary-app capture self-test")
    camera_status.set_defaults(func=cmd_camera_status)
    camera_set = camera.add_parser("set", help="validate, persist, and publish a camera source")
    camera_set.add_argument("kind", choices=["photo", "video"])
    camera_set.add_argument("file", metavar="FILE")
    camera_set.set_defaults(func=cmd_camera_set)
    camera_mode = camera.add_parser("mode", help="set camera rendering mode")
    camera_mode.add_argument("mode", choices=["naturalized", "faithful"])
    camera_mode.set_defaults(func=cmd_camera_mode)
    camera_clear = camera.add_parser("clear", help="clear configured camera sources")
    camera_clear.add_argument("kind", choices=["photo", "video", "all"])
    camera_clear.set_defaults(func=cmd_camera_clear)
    camera_apply = camera.add_parser("apply", help="reconcile persisted camera state")
    camera_apply.set_defaults(func=cmd_camera_apply)

    s = sub.add_parser("root", help="root helper status and commands")
    root = s.add_subparsers(required=True)
    rs = root.add_parser("status")
    rs.set_defaults(func=cmd_root_status)
    re = root.add_parser("exec")
    re.add_argument("command", nargs=argparse.REMAINDER)
    re.set_defaults(func=cmd_root_exec)

    s = sub.add_parser("frida", help="frida-server lifecycle")
    fr = s.add_subparsers(required=True)
    ff = fr.add_parser("fetch")
    ff.add_argument("--version", default="latest")
    ff.add_argument("--arch", default="android-arm64")
    ff.add_argument("--out-dir")
    ff.set_defaults(func=cmd_frida_fetch)
    fi = fr.add_parser("install", help="download and deploy frida-server")
    fi.add_argument("--version", default="latest")
    fi.add_argument("--arch", default="android-arm64")
    fi.add_argument("--out-dir")
    fi.add_argument("--remote-path", default="/data/system/.core/svc.bin")
    fi.set_defaults(func=cmd_frida_install)
    fds = fr.add_parser("deploy-scripts")
    fds.add_argument("--scripts-dir", default="frida/scripts")
    fds.add_argument("--remote-dir", default="/data/local/tmp/xenoid-frida")
    fds.set_defaults(func=cmd_frida_deploy_scripts)
    fls = fr.add_parser("load-script")
    fls.add_argument("package")
    fls.add_argument("script")
    fls.add_argument("--spawn", action="store_true")
    fls.add_argument("--oneshot", action="store_true", help="do not eternalize; hooks unload when the CLI exits (smoke use)")
    fls.set_defaults(func=cmd_frida_load_script)
    fd = fr.add_parser("deploy")
    fd.add_argument("path")
    fd.add_argument("--remote-path", default="/data/system/.core/svc.bin")
    fd.set_defaults(func=cmd_frida_deploy)
    fs = fr.add_parser("start")
    fs.add_argument("--port", type=int, default=27042)
    fs.set_defaults(func=cmd_frida_start)
    fst = fr.add_parser("stop")
    fst.set_defaults(func=cmd_frida_stop)
    fstat = fr.add_parser("status")
    fstat.set_defaults(func=cmd_frida_status)

    s = sub.add_parser("profile", help="native profile helper operations")
    prof = s.add_subparsers(required=True)
    pd = prof.add_parser("deploy-helper")
    pd.add_argument("path")
    pd.add_argument("--remote-path", default="/data/local/tmp/xenoid-profile-helper")
    pd.set_defaults(func=cmd_profile_deploy_helper)
    ps = prof.add_parser("status")
    ps.set_defaults(func=cmd_profile_helper_status)
    pe = prof.add_parser("env")
    pe.set_defaults(func=cmd_profile_helper_env)
    pdu = prof.add_parser("dump")
    pdu.set_defaults(func=cmd_profile_helper_dump)

    s = sub.add_parser("device", help="fingerprint collect/apply/set")
    dev = s.add_subparsers(required=True)
    c = dev.add_parser("collect")
    c.add_argument("--out")
    c.set_defaults(func=cmd_device_collect)
    a = dev.add_parser("apply")
    a.add_argument("profile")
    identity_mode = a.add_mutually_exclusive_group()
    identity_mode.add_argument("--keep-unique", action="store_true")
    identity_mode.add_argument(
        "--instance-identity",
        action="store_true",
        help="converge host-owned stable and boot-scoped instance identity",
    )
    a.add_argument("--generate-frida", action="store_true", help="also generate a Frida profile spoof script")
    a.add_argument("--frida-out")
    a.set_defaults(func=cmd_device_apply)
    gsf = dev.add_parser("generate-service-frida")
    gsf.add_argument("profile")
    gsf.add_argument("--out")
    gsf.add_argument("--keep-unique", action="store_true")
    gsf.set_defaults(func=cmd_device_generate_service_frida)
    gf = dev.add_parser("generate-frida")
    gf.add_argument("profile")
    gf.add_argument("--out")
    gf.add_argument("--keep-unique", action="store_true")
    gf.set_defaults(func=cmd_device_generate_frida)
    st = dev.add_parser("set")
    st.add_argument("field")
    st.add_argument("value")
    st.set_defaults(func=cmd_device_set)

    s = sub.add_parser("automation", help="automation tasks")
    aut = s.add_subparsers(required=True)
    pplan = aut.add_parser("plan")
    pplan.add_argument("script")
    pplan.set_defaults(func=cmd_automation_plan)
    rh = aut.add_parser("run-host")
    rh.add_argument("script")
    rh.add_argument("--execute", action="store_true", help="execute through daemon API instead of only planning")
    rh.set_defaults(func=cmd_automation_run_host)
    r = aut.add_parser("run")
    r.add_argument("script")
    r.set_defaults(func=cmd_automation_run)

    s = sub.add_parser("input", help="low-level input injection through daemon")
    inp = s.add_subparsers(required=True)
    idep = inp.add_parser("deploy")
    idep.add_argument("path")
    idep.add_argument("--remote-path", default="/data/local/tmp/xenoid-input")
    idep.set_defaults(func=cmd_input_deploy)
    it = inp.add_parser("tap")
    it.add_argument("x", type=int)
    it.add_argument("y", type=int)
    it.set_defaults(func=cmd_input_tap)
    isw = inp.add_parser("swipe")
    isw.add_argument("x1", type=int)
    isw.add_argument("y1", type=int)
    isw.add_argument("x2", type=int)
    isw.add_argument("y2", type=int)
    isw.add_argument("duration_ms", type=int, nargs="?", default=300)
    isw.set_defaults(func=cmd_input_swipe)

    s = sub.add_parser("app", help="install/uninstall/launch apps through daemon")
    app = s.add_subparsers(required=True)
    ai = app.add_parser("install")
    ai.add_argument("path")
    ai.set_defaults(func=cmd_app_install)
    au = app.add_parser("uninstall")
    au.add_argument("package")
    au.set_defaults(func=cmd_app_uninstall)
    al = app.add_parser("launch")
    al.add_argument("component")
    al.set_defaults(func=cmd_app_launch)

    s = sub.add_parser("hide", help="environment hiding policy")
    hid = s.add_subparsers(required=True)
    hd = hid.add_parser("deploy")
    hd.add_argument("path")
    hd.add_argument("--remote-path", default="/data/local/tmp/xenoid-hide-helper")
    hd.set_defaults(func=cmd_hide_deploy)
    hs = hid.add_parser("status")
    hs.set_defaults(func=cmd_hide_status)
    hos = hid.add_parser("overlay-status")
    hos.set_defaults(func=cmd_hide_overlay_status)
    hco = hid.add_parser("cleanup-overlay")
    hco.set_defaults(func=cmd_hide_cleanup_overlay)
    hov = hid.add_parser("deploy-overlay")
    hov.add_argument("path", nargs="?", default="native/xenoid-hide/xenoid-overlay-x86_64")
    hov.add_argument("--remote-path", default="/data/local/tmp/xenoid-overlay-helper")
    hov.set_defaults(func=cmd_hide_deploy_overlay)
    ha = hid.add_parser("apply")
    ha.add_argument("policy", nargs="?")
    ha.set_defaults(func=cmd_hide_apply)


    s = sub.add_parser("ebpf", help="host-side eBPF system hooks (path-hide); distinct from Frida app hooks")
    eb = s.add_subparsers(required=True)
    def _ebpf_mode(ep: argparse.ArgumentParser) -> None:
        ep.add_argument("--mode", choices=["colima", "local", "ssh"], default=None, help="engine host mode (default: auto)")
        ep.add_argument("--ssh", default=None, help="user@host when --mode ssh")
        ep.add_argument("--ssh-port", default=None, help="ssh port when --mode ssh")
    eb_build = eb.add_parser("build", help="build eBPF program + libbpf loader on engine host")
    _ebpf_mode(eb_build)
    eb_build.set_defaults(func=cmd_ebpf_build)
    for action, help_text in (("load", "load and attach eBPF path-hide"), ("status", "JSON status of pinned eBPF"), ("unload", "unpin/unload eBPF")):
        ep = eb.add_parser(action, help=help_text)
        _ebpf_mode(ep)
        ep.set_defaults(func=cmd_ebpf_action, ebpf_action=action)


    s = sub.add_parser("netctl", help="low-level rtnetlink network identity helper")
    net = s.add_subparsers(required=True)
    nd = net.add_parser("deploy")
    nd.add_argument("path", nargs="?", default="native/xenoid-netctl/xenoid-netctl-x86_64")
    nd.add_argument("--remote-path", default="/data/local/tmp/xenoid-netctl")
    nd.set_defaults(func=cmd_netctl_deploy)
    ns = net.add_parser("status")
    ns.add_argument("--ifname", default="rmnet_data0")
    ns.set_defaults(func=cmd_netctl_status)
    nm = net.add_parser("set-mac")
    nm.add_argument("mac")
    nm.add_argument("--ifname", default="rmnet_data0")
    nm.set_defaults(func=cmd_netctl_set_mac)


    s = sub.add_parser("ota", help="OTA operations")
    ota = s.add_subparsers(required=True)
    om = ota.add_parser("make")
    om.add_argument("--version", default="0.1.0")
    om.set_defaults(func=cmd_ota_make)
    oi = ota.add_parser("install-bundle")
    oi.add_argument("bundle")
    oi.set_defaults(func=cmd_ota_install_bundle)
    oc = ota.add_parser("check")
    oc.set_defaults(func=cmd_ota_check)
    oa = ota.add_parser("apply")
    oa.add_argument("--channel", default="stable")
    oa.set_defaults(func=cmd_ota_apply)

    s = sub.add_parser("mcp-config", help="print MCP server config")
    s.set_defaults(func=cmd_mcp_config)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.project_root = resolve_project_root()
        args.instance_name = select_instance_name(args.instance)
        unresolved = args.top_command in {
            "build",
            "init",
            "install-runtime",
            "package-release",
            "verify-release",
        }
        listing = args.top_command == "instance" and args.instance_command == "list"
        if not unresolved and not listing:
            args.context, args.config, args.lease = resolve_instance(
                args.instance_name,
                project_root=args.project_root,
            )
        return int(args.func(args))
    except InstanceError as exc:
        print_json(exc.as_dict())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
