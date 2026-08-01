from __future__ import annotations

import argparse
import json
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .backend import RuntimeManager
from .config import XenoidConfig, load_config, save_config, merge_config
from .daemon_client import CAMERA_MUTATION_TIMEOUT_SECONDS, DaemonClient
from .doctor import build_doctor_report
from .util import json_dumps, read_json_file, write_json_file


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def print_json(data: Any) -> None:
    print(json_dumps(data))


def run_script(name: str) -> dict[str, Any]:
    script = project_root() / "scripts" / name
    proc = subprocess.run([str(script)], text=True, capture_output=True, cwd=str(project_root()))
    return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}


def cmd_install_runtime(args: argparse.Namespace) -> int:
    script = project_root() / "scripts" / "install-macos-runtime.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(project_root()))
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    report = build_doctor_report(load_config(), full=args.full, require_runtime=args.require_runtime)
    if args.out:
        write_json_file(Path(args.out), report)
    print_json(report)
    return 0 if report["ok"] else 1




def cmd_up(args: argparse.Namespace) -> int:
    script = project_root() / "scripts" / "xenoid-up.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else []) + (["--skip-build"] if args.skip_build else [])
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(project_root()))
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "script": str(script)}
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_runtime_compose(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).make_compose(args.out)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_linux_binderfs(args: argparse.Namespace) -> int:
    script = project_root() / "scripts" / "setup-linux-binderfs.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(project_root()))
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_runtime_context(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).make_runtime_context(args.image)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_make_rootfs(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).ensure_rootfs_images()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_daemon(args: argparse.Namespace) -> int:
    result = run_script("build-daemon.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_input(args: argparse.Namespace) -> int:
    result = run_script("build-native-input.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_hide(args: argparse.Namespace) -> int:
    result = run_script("build-native-hide.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_profile(args: argparse.Namespace) -> int:
    result = run_script("build-native-profile.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_netctl(args: argparse.Namespace) -> int:
    result = run_script("build-native-netctl.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_gralloc(args: argparse.Namespace) -> int:
    result = run_script("build-gralloc.sh")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_verify_release(args: argparse.Namespace) -> int:
    script = project_root() / "scripts" / "verify-release.py"
    proc = subprocess.run([str(script), args.archive], text=True, capture_output=True, cwd=str(project_root()))
    print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    return 0 if proc.returncode == 0 else proc.returncode


def cmd_package_release(args: argparse.Namespace) -> int:
    script = project_root() / "scripts" / "package-release.sh"
    proc = subprocess.run([str(script), args.version], text=True, capture_output=True, cwd=str(project_root()), env={**__import__("os").environ, "REL": ""})
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip(), "archive": proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None}
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_all(args: argparse.Namespace) -> int:
    root = project_root()
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
        ("shimArm64", [root / "scripts" / "build-native-shim.sh", "arm64", "prop"]),
        ("pivot", [root / "scripts" / "build-native-for-arch.sh", "xenoid-pivot", root / "native" / "xenoid-pivot" / "xenoid_pivot.c", root / "native" / "xenoid-pivot" / "xenoid-pivot", "arm64", "static"]),
        ("propArea", [root / "scripts" / "build-native-for-arch.sh", "xenoid-prop-area", root / "native" / "xenoid-hide" / "xenoid_prop_area.c", root / "native" / "xenoid-hide" / "xenoid-prop-area", "arm64"]),
        ("ssaid", [root / "scripts" / "build-native-for-arch.sh", "xenoid-ssaid", root / "native" / "xenoid-hide" / "xenoid_ssaid.c", root / "native" / "xenoid-hide" / "xenoid-ssaid", "arm64"]),
    ]
    steps: dict[str, Any] = {}
    for name, command in commands:
        proc = subprocess.run([str(part) for part in command], text=True, capture_output=True, cwd=str(root))
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
    cfg = XenoidConfig(image=args.image or XenoidConfig().image, backend=args.backend or XenoidConfig().backend)
    path = save_config(cfg)
    print_json({"ok": True, "config": str(path), "data": cfg})
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    print_json(load_config())
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    overrides = {
        "backend": args.backend,
        "image": args.image,
        "runtime_image_tag": args.runtime_image_tag,
        "auto_build_runtime_image": args.auto_build_runtime_image,
        "docker_context": args.docker_context,
        "network_enabled": args.network_enabled,
        "network_name": args.network_name,
        "network_subnet": args.network_subnet,
        "network_gateway": args.network_gateway,
        "network_ip": args.network_ip,
        "network_mac": args.network_mac,
    }
    cfg = merge_config(overrides)
    path = save_config(cfg)
    print_json({"ok": True, "config": str(path), "data": cfg})
    return 0


def cmd_runtime_build_image(args: argparse.Namespace) -> int:
    mgr = RuntimeManager(load_config())
    ctx = mgr.make_runtime_context(args.image)
    if not ctx.get("ok"):
        print_json(ctx); return 1
    if args.dry_run:
        print_json({"ok": True, "dryRun": True, "context": ctx.get("context"), "command": [*(RuntimeManager(load_config()).docker_base_cmd()), "build", "-t", args.tag, ctx.get("context")]})
        return 0
    proc = subprocess.run([*(RuntimeManager(load_config()).docker_base_cmd()), "build", "-t", args.tag, ctx.get("context")], text=True, capture_output=True)
    result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr, "tag": args.tag, "context": ctx.get("context")}
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_start(args: argparse.Namespace) -> int:
    mgr = RuntimeManager(load_config())
    result = mgr.start(dry_run=args.dry_run, wait=not args.no_wait, install_daemon_apk=args.install_daemon, start_colima=args.start_colima, adb_root=not args.no_adb_root, skip_preflight=args.skip_preflight, recreate=args.recreate)
    print_json(result)
    return 0 if result.get("ok") or args.dry_run else 1


def cmd_stop(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).stop()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_logs(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).runtime_logs(args.out_dir)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_view(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).view()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_status(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).status()
    print_json(result)
    return 0 if result.get("ok") and result.get("running") else 1


def cmd_adb(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).adb(args.adb_args)
    print_json(result)
    return 0 if result.get("ok") else 1


def daemon() -> DaemonClient:
    cfg = load_config()
    return DaemonClient(port=cfg.daemon_port)


def daemon_ensured() -> DaemonClient:
    RuntimeManager(load_config()).ensure_daemon()
    return daemon()



def cmd_daemon_ensure(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).ensure_daemon(
        readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
    )
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_daemon_health(args: argparse.Namespace) -> int:
    result = daemon().health()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_daemon_install(args: argparse.Namespace) -> int:
    mgr = RuntimeManager(load_config())
    install = mgr.install_daemon(args.apk)
    if not install.get("ok"):
        print_json(install)
        return 1
    start = mgr.start_daemon_service()
    forward = mgr.forward_daemon_port() if start.get("ok") else {"ok": False, "skipped": True}
    rootd = mgr.ensure_rootd_root() if start.get("ok") else {"ok": False, "skipped": True}
    result = {
        "ok": bool(install.get("ok") and start.get("ok") and forward.get("ok") and rootd.get("ok")),
        "install": install,
        "start": start,
        "forward": forward,
        "rootd": rootd,
    }
    print_json(result)
    return 0 if result["ok"] else 1


def cmd_daemon_start(args: argparse.Namespace) -> int:
    mgr = RuntimeManager(load_config())
    start = mgr.start_daemon_service()
    forward = mgr.forward_daemon_port() if start.get("ok") else {"ok": False, "skipped": True}
    rootd = mgr.ensure_rootd_root() if start.get("ok") else {"ok": False, "skipped": True}
    result = {"ok": bool(start.get("ok") and forward.get("ok") and rootd.get("ok")), "start": start, "forward": forward, "rootd": rootd}
    print_json(result)
    return 0 if result["ok"] else 1

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


def _camera_ready() -> tuple[Optional[RuntimeManager], Optional[DaemonClient]]:
    try:
        cfg = load_config()
        manager = RuntimeManager(cfg)
        ensured = manager.ensure_daemon(
            readiness_timeout=CAMERA_MUTATION_TIMEOUT_SECONDS
        )
        if not ensured.get("ok"):
            return None, None
        return manager, DaemonClient(port=cfg.daemon_port)
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
    manager, client = _camera_ready()
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

    manager, client = _camera_ready()
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
    _, client = _camera_ready()
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(lambda: client.camera_settings(args.mode)))


def cmd_camera_clear(args: argparse.Namespace) -> int:
    _, client = _camera_ready()
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(lambda: client.camera_clear(args.kind)))


def cmd_camera_apply(args: argparse.Namespace) -> int:
    _, client = _camera_ready()
    if client is None:
        return _emit_camera_result({"ok": False, "error": "camera daemon unavailable"})
    return _emit_camera_result(_camera_request(client.camera_apply))


def cmd_root_status(args: argparse.Namespace) -> int:
    result = daemon_ensured().root_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_root_exec(args: argparse.Namespace) -> int:
    result = daemon_ensured().root_exec(" ".join(args.command))
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_fetch(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).fetch_frida(version=args.version, arch=args.arch, out_dir=args.out_dir)
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_frida_install(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).install_frida(
        version=args.version,
        arch=args.arch,
        out_dir=args.out_dir,
        remote_path=args.remote_path,
    )
    print_json(result)
    return 0 if result.get("ok") else 1



def cmd_frida_deploy_scripts(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_frida_scripts(args.scripts_dir, args.remote_dir)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_load_script(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).load_frida_script(args.package, args.script, spawn=args.spawn, oneshot=args.oneshot)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_deploy(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_frida(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_frida_start(args: argparse.Namespace) -> int:
    result = daemon_ensured().frida_start(port=args.port)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_stop(args: argparse.Namespace) -> int:
    result = daemon_ensured().frida_stop()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_status(args: argparse.Namespace) -> int:
    result = daemon_ensured().frida_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1



def cmd_profile_deploy_helper(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_profile_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_profile_helper_status(args: argparse.Namespace) -> int:
    result = daemon_ensured().profile_helper_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_env(args: argparse.Namespace) -> int:
    result = daemon_ensured().profile_helper_env()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_dump(args: argparse.Namespace) -> int:
    result = daemon_ensured().profile_helper_dump()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_collect(args: argparse.Namespace) -> int:
    result = daemon_ensured().collect_fingerprint()
    if args.out and result.get("ok", True):
        write_json_file(args.out, result)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_apply(args: argparse.Namespace) -> int:
    profile = read_json_file(args.profile)
    result = daemon_ensured().apply_fingerprint(profile, regenerate_unique=not args.keep_unique)
    if args.generate_frida:
        result = {"daemon": result, "fridaProfile": RuntimeManager(load_config()).generate_profile_frida(args.profile, args.frida_out, args.keep_unique)}
        result["ok"] = bool(result["daemon"].get("ok") and result["fridaProfile"].get("ok"))
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_generate_service_frida(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).generate_service_frida(args.profile, args.out, args.keep_unique)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_device_generate_frida(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).generate_profile_frida(args.profile, args.out, args.keep_unique)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_device_set(args: argparse.Namespace) -> int:
    value: Any = args.value
    result = daemon_ensured().set_fingerprint_field(args.field, value)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_automation_plan(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).automation_plan(args.script)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run_host(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).automation_run_host(args.script, execute=args.execute, endpoint=args.endpoint)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run(args: argparse.Namespace) -> int:
    result = daemon_ensured().run_automation(args.script)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_deploy(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_input_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_input_tap(args: argparse.Namespace) -> int:
    result = daemon_ensured().tap(args.x, args.y)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_swipe(args: argparse.Namespace) -> int:
    result = daemon_ensured().swipe(args.x1, args.y1, args.x2, args.y2, args.duration_ms)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_install(args: argparse.Namespace) -> int:
    source = Path(args.path).expanduser()
    if source.is_file():
        manager = RuntimeManager(load_config())
        remote = "/data/local/tmp/xenoid-install.apk"
        upload = manager.adb(["push", str(source.resolve()), remote])
        if not upload.get("ok"):
            print_json({"ok": False, "error": "APK upload failed", "upload": upload})
            return 1
        result = daemon_ensured().app_install(remote)
        result["upload"] = upload
        result["cleanup"] = manager.adb(["shell", "rm", "-f", remote])
        result["source"] = str(source.resolve())
    else:
        result = daemon_ensured().app_install(args.path)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_uninstall(args: argparse.Namespace) -> int:
    result = daemon_ensured().app_uninstall(args.package)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_launch(args: argparse.Namespace) -> int:
    result = daemon_ensured().app_launch(args.component)
    print_json(result)
    return 0 if result.get("ok", False) else 1



def cmd_hide_deploy(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_hide_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_deploy_overlay(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_hide_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_netctl_deploy(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).deploy_netctl_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_netctl_status(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).netctl_status(args.ifname)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_netctl_set_mac(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).netctl_set_mac(args.mac, args.ifname)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_overlay_status(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).overlay_status()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_hide_cleanup_overlay(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).overlay_cleanup()
    print_json(result)
    return 0 if result.get("ok") else 1

def cmd_hide_status(args: argparse.Namespace) -> int:
    result = daemon_ensured().hide_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_hide_apply(args: argparse.Namespace) -> int:
    policy = read_json_file(args.policy) if args.policy else None
    result = daemon_ensured().hide_apply(policy)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_ota_make(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).make_ota_bundle(args.version)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ota_install_bundle(args: argparse.Namespace) -> int:
    result = RuntimeManager(load_config()).apply_ota_bundle(args.bundle)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ota_check(args: argparse.Namespace) -> int:
    result = daemon_ensured().ota_check()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_ota_apply(args: argparse.Namespace) -> int:
    result = daemon_ensured().ota_apply(args.channel)
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
    script = project_root() / "scripts" / "build-ebpf.sh"
    cmd = [str(script), *_ebpf_script_args(args)]
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(project_root()))
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
    script = project_root() / "scripts" / "load-ebpf.sh"
    action = args.ebpf_action
    cmd = [str(script), *_ebpf_script_args(args), action]
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(project_root()))
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
                "env": {"XENOID_PROJECT": str(Path.cwd())},
            }
        }
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="xenoid", description="Xenoid Android runtime CLI")
    sub = p.add_subparsers(required=True)

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

    s = sub.add_parser("runtime-compose", help="generate docker-compose.yml for linux-docker backend")
    s.add_argument("--out", default="dist/docker-compose.yml")
    s.set_defaults(func=cmd_runtime_compose)


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
    ba = bsub.add_parser("all")
    ba.set_defaults(func=cmd_build_all)

    s = sub.add_parser("verify-release", help="verify a Xenoid release bundle manifest and required artifacts")
    s.add_argument("archive")
    s.set_defaults(func=cmd_verify_release)

    s = sub.add_parser("package-release", help="package transferable Xenoid release bundle")
    s.add_argument("--version", default="dev")
    s.set_defaults(func=cmd_package_release)


    s = sub.add_parser("config", help="show or update xenoid config")
    csub = s.add_subparsers(required=True)
    cs = csub.add_parser("show")
    cs.set_defaults(func=cmd_config_show)
    cset = csub.add_parser("set")
    cset.add_argument("--backend")
    cset.add_argument("--image")
    cset.add_argument("--runtime-image-tag")
    cset.add_argument("--docker-context")
    cset.add_argument("--network-enabled", action=argparse.BooleanOptionalAction, default=None)
    cset.add_argument("--network-name")
    cset.add_argument("--network-subnet")
    cset.add_argument("--network-gateway")
    cset.add_argument("--network-ip")
    cset.add_argument("--network-mac")
    cset.add_argument("--auto-build-runtime-image", action=argparse.BooleanOptionalAction, default=None)
    cset.set_defaults(func=cmd_config_set)

    s = sub.add_parser("init", help="create .xenoid/config.json")
    s.add_argument("--image")
    s.add_argument("--backend")
    s.set_defaults(func=cmd_init)


    s = sub.add_parser("start", help="start the low-level Android runtime without full Xenoid state convergence")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--no-wait", action="store_true", help="do not wait for adb boot")
    s.add_argument("--start-colima", action="store_true", help="run colima start before docker run")
    s.add_argument("--install-daemon", help="install daemon APK after boot")
    s.add_argument("--no-adb-root", action="store_true", help="skip adb root after boot")
    s.add_argument("--skip-preflight", action="store_true", help="skip runtime preflight checks")
    s.add_argument("--recreate", action="store_true", help="replace an existing container so image and runtime arguments take effect")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("stop", help="stop Android runtime")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("logs", help="collect Docker/ADB runtime logs")
    s.add_argument("--out-dir", default=".xenoid/logs")
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
    ff.add_argument("--out-dir", default=".xenoid/frida")
    ff.set_defaults(func=cmd_frida_fetch)
    fi = fr.add_parser("install", help="download and deploy frida-server")
    fi.add_argument("--version", default="latest")
    fi.add_argument("--arch", default="android-arm64")
    fi.add_argument("--out-dir", default=".xenoid/frida")
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
    a.add_argument("--keep-unique", action="store_true")
    a.add_argument("--generate-frida", action="store_true", help="also generate a Frida profile spoof script")
    a.add_argument("--frida-out", default=".xenoid/frida/generated-profile.js")
    a.set_defaults(func=cmd_device_apply)
    gsf = dev.add_parser("generate-service-frida")
    gsf.add_argument("profile")
    gsf.add_argument("--out", default=".xenoid/frida/generated-service-profile.js")
    gsf.add_argument("--keep-unique", action="store_true")
    gsf.set_defaults(func=cmd_device_generate_service_frida)
    gf = dev.add_parser("generate-frida")
    gf.add_argument("profile")
    gf.add_argument("--out", default=".xenoid/frida/generated-profile.js")
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
    rh.add_argument("--endpoint", default="http://127.0.0.1:18765")
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
    ns.add_argument("--ifname", default="eth0")
    ns.set_defaults(func=cmd_netctl_status)
    nm = net.add_parser("set-mac")
    nm.add_argument("mac")
    nm.add_argument("--ifname", default="eth0")
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
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
