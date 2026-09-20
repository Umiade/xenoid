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
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Mapping, Optional
from urllib.parse import urlsplit

from . import __version__
from .backend import RuntimeManager
from .convergence import ConvergenceExecutor, ConvergencePlan
from .artifacts import ALL_TARGETS, TARGETS, ArtifactBuilder, ArtifactError
from .cellular import CellularError, encode_profile_v1
from .config import (
    InstanceError,
    initialize_instance,
    list_instances,
    merge_config,
    resolve_instance,
    resolve_project_root,
    rotate_instance_network,
    save_config,
    select_instance_name,
)
from .daemon_client import (
    KEYBOX_MAX_SOURCE_BYTES,
    PROXY_MAX_SOURCE_BYTES,
    DaemonClient,
)
from .doctor import build_doctor_report
from .device_identity import (
    REGENERATION_PHASES,
    DeviceIdentityStore,
    IdentityError,
    RegenerationJournal,
    converge_instance_identity,
    generate_boot_id,
    generate_stable_target,
    identity_field_key,
    materialize_profile,
    public_identity_state,
    stable_identity_digest,
    validate_identity_value,
)
from .google_services import (
    AVAILABILITY_PRODUCTION,
    MICROG_PLAY_RELEASE,
    PROVIDER_NONE,
    PROVIDER_MICROG,
    GoogleBindingStore,
    GoogleServicesError,
    binding_matches,
    import_microg,
    ensure_google_services_assets,
    import_mindthegapps,
    load_release_spec,
    quick_validate_assets,
    registered_releases,
    registry_public,
    resolve_google_runtime_spec,
)
from .process import run_bounded
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
from .operation_lock import (
    EXPECTED_INSTANCE_ID_ENV,
    OPERATION_LOCK_TIMEOUT_ENV,
    instance_operation_lock,
    operation_lock_is_held,
)
from .proxy_controller import ProxyController
from .storage import (
    StorageError,
    StorageStateStore,
)
from .util import (
    bounded_timeout,
    command_timeout,
    json_dumps,
    read_json_file,
    validate_release_version,
    write_json_file,
)



_KEYBOX_CHUNK_BYTES = 1024 * 1024
_KEYBOX_PRIVATE_MODES = frozenset({0o400, 0o600})


class _KeyboxFileError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _same_keybox_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _private_keybox_file(state: os.stat_result) -> bool:
    return (
        stat.S_ISREG(state.st_mode)
        and state.st_uid == os.getuid()
        and stat.S_IMODE(state.st_mode) in _KEYBOX_PRIVATE_MODES
        and 0 < state.st_size <= KEYBOX_MAX_SOURCE_BYTES
    )


@contextmanager
def _validated_keybox_source(
    path: str,
) -> Iterator[tuple[BinaryIO, int, str, os.stat_result]]:
    try:
        source = Path(path).expanduser()
        before = os.lstat(source)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _KeyboxFileError("keybox_file_invalid") from exc
    if not _private_keybox_file(before):
        raise _KeyboxFileError("keybox_file_invalid")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise _KeyboxFileError("keybox_file_invalid")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source, flags)
    except (OSError, ValueError) as exc:
        raise _KeyboxFileError("keybox_file_invalid") from exc

    try:
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except (OSError, ValueError) as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise _KeyboxFileError("keybox_file_invalid") from exc
    try:
        try:
            opened = os.fstat(descriptor)
            linked = os.lstat(source)
        except OSError as exc:
            raise _KeyboxFileError("keybox_file_changed") from exc
        if (
            not _private_keybox_file(opened)
            or not _same_keybox_file(before, opened)
            or not _same_keybox_file(opened, linked)
        ):
            raise _KeyboxFileError("keybox_file_changed")

        digest = hashlib.sha256()
        total = 0
        while True:
            try:
                chunk = stream.read(_KEYBOX_CHUNK_BYTES)
            except OSError as exc:
                raise _KeyboxFileError("keybox_file_changed") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > KEYBOX_MAX_SOURCE_BYTES:
                raise _KeyboxFileError("keybox_file_changed")
            digest.update(chunk)

        try:
            after = os.fstat(descriptor)
            linked_after = os.lstat(source)
        except OSError as exc:
            raise _KeyboxFileError("keybox_file_changed") from exc
        if (
            total != before.st_size
            or not _private_keybox_file(after)
            or not _same_keybox_file(opened, after)
            or not _same_keybox_file(after, linked_after)
        ):
            raise _KeyboxFileError("keybox_file_changed")
        try:
            stream.seek(0)
        except OSError as exc:
            raise _KeyboxFileError("keybox_file_changed") from exc
        yield stream, total, digest.hexdigest(), after
    finally:
        try:
            stream.close()
        except OSError:
            pass


def print_json(data: Any) -> None:
    print(json_dumps(data))


def runtime(args: argparse.Namespace) -> RuntimeManager:
    manager = RuntimeManager(args.context, args.config, args.lease)
    manager.operation_lock_held = bool(getattr(args, "_operation_lock_held", False))
    return manager


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
    environment = {
        **os.environ,
        "XENOID_PROJECT": str(args.project_root),
        "XENOID_INSTANCE": args.instance_name,
    }
    environment.pop("XENOID_OPERATION_LOCK_HELD", None)
    if getattr(args, "_operation_lock_held", False):
        environment[EXPECTED_INSTANCE_ID_ENV] = args.context.instance_id
    return environment


@contextmanager
def cli_operation_lock(args: argparse.Namespace) -> Iterator[None]:
    if operation_lock_is_held(args.context.instance_id):
        yield
        return
    timeout: Optional[float] = None
    raw_timeout = os.environ.get(OPERATION_LOCK_TIMEOUT_ENV)
    if raw_timeout is not None:
        try:
            timeout = float(raw_timeout)
        except ValueError as exc:
            raise InstanceError(
                "instance_lock_timeout_invalid",
                "instance operation lock timeout is invalid",
            ) from exc
        if timeout < 0 or timeout > 300:
            raise InstanceError(
                "instance_lock_timeout_invalid",
                "instance operation lock timeout is invalid",
            )
    with instance_operation_lock(args.context.state_root, timeout_seconds=timeout):
        yield


def run_script(args: argparse.Namespace, name: str) -> dict[str, Any]:
    script = args.project_root / "scripts" / name
    proc = run_bounded(
        [str(script)],
        cwd=args.project_root,
        env=command_env(args),
        deadline=time.monotonic() + 900.0,
        project_root=args.project_root,
    )
    return {
        "ok": proc.ok,
        "state": proc.state,
        "errorCode": proc.error_code,
        "returncode": proc.returncode,
        "stdout": proc.stdout_tail,
        "stderr": proc.stderr_tail,
        "script": name,
    }


def cmd_install_runtime(args: argparse.Namespace) -> int:
    script = args.project_root / "scripts" / "install-macos-runtime.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = run_bounded(
        cmd,
        cwd=args.project_root,
        env=command_env(args),
        deadline=time.monotonic() + 3600.0,
        project_root=args.project_root,
    )
    result = {"ok": proc.ok, "state": proc.state, "errorCode": proc.error_code, "returncode": proc.returncode, "stdout": proc.stdout_tail, "stderr": proc.stderr_tail, "script": script.name}
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



_UP_TIMEOUT_SECONDS = 7200.0


def _write_up_progress(event: Mapping[str, Any]) -> None:
    sys.stderr.write(
        json.dumps(
            dict(event),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stderr.flush()


def _execute_convergence(
    args: argparse.Namespace,
    *,
    manager: Optional[RuntimeManager] = None,
    regeneration_capability: Any = None,
) -> dict[str, Any]:
    executor = ConvergenceExecutor(manager or runtime(args))
    with command_timeout(_UP_TIMEOUT_SECONDS):
        return executor.run(
            progress=_write_up_progress,
            skip_build=bool(getattr(args, "skip_build", False)),
            dry_run=bool(getattr(args, "dry_run", False)),
            regeneration_capability=regeneration_capability,
        )

def _prepare_google_assets_for_up(args: argparse.Namespace) -> dict[str, Any]:
    provider = args.config.google_services_provider
    release = args.config.google_services_release
    if provider == PROVIDER_NONE:
        return {"ok": True, "skipped": True}
    spec = load_release_spec(args.context.project_root, release)
    if spec.availability != AVAILABILITY_PRODUCTION:
        raise GoogleServicesError(
            "google_services_release_retired",
            "the configured Google services release is retired; create a new instance",
        )
    if bool(args.dry_run) or bool(args.skip_build):
        quick_validate_assets(args.context.project_root, spec)
        return {"ok": True, "downloaded": False, "existing": True}
    _write_up_progress(
        {
            "schema": "dev.xenoid.progress/v1",
            "command": "up",
            "phase": "google-assets",
            "state": "started",
            "durationMs": 0,
            "detail": "acquiring",
        }
    )
    result = ensure_google_services_assets(args.context.project_root, spec)
    _write_up_progress(
        {
            "schema": "dev.xenoid.progress/v1",
            "command": "up",
            "phase": "google-assets",
            "state": "passed",
            "durationMs": 0,
            "detail": (
                "downloaded"
                if result.get("downloaded") is True
                else "ready"
            ),
        }
    )
    return result


def cmd_up(args: argparse.Namespace) -> int:
    manager = runtime(args)
    engine = (
        {"ok": manager.engine_reachable(), "started": False, "error": "engine_unavailable"}
        if bool(args.dry_run)
        else manager.ensure_engine_started()
    )
    if engine.get("started") is True:
        _write_up_progress(
            {
                "schema": "dev.xenoid.progress/v1",
                "command": "up",
                "phase": "engine",
                "state": "passed",
                "durationMs": 0,
                "detail": "started",
            }
        )
    if engine.get("ok") is not True:
        print_json({"command": "up", "ok": False, "dryRun": bool(args.dry_run), **engine})
        return 1

    def locked_body() -> tuple[Optional[dict[str, Any]], Optional[int]]:
        # The journal load, resume execution, asset preparation, and
        # convergence all run under the instance operation lock so a pending
        # v3 regeneration cannot race a concurrent up/regenerate. A pending
        # journal is resumed before any Google asset acquisition, which its
        # own post-journal steps do not need.
        journal = RegenerationJournal(args.context)
        try:
            regeneration = journal.load()
        except IdentityError as exc:
            return _regeneration_exception_result(args.context, exc), None
        if regeneration is not None:
            if bool(args.dry_run):
                return _regeneration_dry_run_result(regeneration), None
            try:
                return _execute_device_regeneration(args), None
            except (IdentityError, InstanceError, LocationError, StorageError) as exc:
                return _regeneration_exception_result(args.context, exc), None
        try:
            _prepare_google_assets_for_up(args)
        except GoogleServicesError as exc:
            print_json(exc.as_dict())
            return None, 1
        capability = (
            {"transactionId": regeneration["transactionId"]}
            if regeneration is not None
            else None
        )
        executor = ConvergenceExecutor(manager)
        with command_timeout(_UP_TIMEOUT_SECONDS):
            return executor.run(
                progress=_write_up_progress,
                skip_build=bool(args.skip_build),
                dry_run=bool(args.dry_run),
                regeneration_capability=capability,
            ), None

    # The journal decision and any resume must share the operation lock even
    # for a dry run: a concurrent regeneration could otherwise prepare and
    # crash between the unlocked load and the executor's own lock, yielding
    # a stale convergence preview instead of the v3 resume preview.
    with cli_operation_lock(args):
        result, exit_code = locked_body()
    if exit_code is not None or result is None:
        return exit_code if exit_code is not None else 1
    print_json(result)
    return 0 if result.get("ok") else 1



def cmd_linux_binderfs(args: argparse.Namespace) -> int:
    script = args.context.project_root / "scripts" / "setup-linux-binderfs.sh"
    cmd = [str(script)] + (["--dry-run"] if args.dry_run else [])
    proc = run_bounded(
        cmd,
        cwd=args.context.project_root,
        env=command_env(args),
        deadline=time.monotonic() + 900.0,
        project_root=args.context.project_root,
    )
    result = {"ok": proc.ok, "state": proc.state, "errorCode": proc.error_code, "returncode": proc.returncode, "stdout": proc.stdout_tail, "stderr": proc.stderr_tail}
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


def _run_artifact_build(
    args: argparse.Namespace,
    targets: tuple[str, ...],
    *,
    force: bool = False,
) -> int:
    result = ArtifactBuilder(
        args.project_root,
        environment=command_env(args),
    ).ensure(targets, force=force)
    print_json(result)

    target_results = result.get("targets")
    if not isinstance(target_results, dict):
        return 1
    expected_targets = set(targets)
    if set(target_results) != expected_targets:
        return 1
    successful = all(
        isinstance(target_results[target], dict)
        and target_results[target].get("status") in {"built", "reused"}
        for target in targets
    )
    return 0 if (
        result.get("schema") == "dev.xenoid.artifacts/v1"
        and result.get("ok") is True
        and result.get("status") == "passed"
        and successful
    ) else 1


def cmd_build_target(args: argparse.Namespace) -> int:
    target = args.artifact_target
    if target not in TARGETS:
        result = {
            "schema": "dev.xenoid.artifacts/v1",
            "ok": False,
            "status": "failed",
            "manifestSha256": None,
            "targets": {
                str(target): {
                    "status": "failed",
                    "durationMs": 0,
                    "code": "artifact_target_unknown",
                },
            },
        }
        print_json(result)
        return 1
    return _run_artifact_build(
        args,
        (target,),
        force=bool(getattr(args, "artifact_force", False)),
    )


def cmd_verify_release(args: argparse.Namespace) -> int:
    script = args.project_root / "scripts" / "verify-release.py"
    proc = run_bounded(
        [str(script), args.archive],
        cwd=args.project_root,
        env=command_env(args),
        deadline=time.monotonic() + 600.0,
        project_root=args.project_root,
    )
    if proc.stdout_tail:
        print(proc.stdout_tail)
    if proc.stderr_tail:
        print(proc.stderr_tail, file=sys.stderr)
    return 0 if proc.ok else (proc.returncode or 1)


def cmd_package_release(args: argparse.Namespace) -> int:
    try:
        version = validate_release_version(args.version)
    except ValueError:
        print_json({
            "ok": False,
            "code": "release_version_invalid",
            "error": "release_version_invalid",
        })
        return 2
    if version != __version__:
        print_json({
            "ok": False,
            "code": "release_version_mismatch",
            "error": "release_version_mismatch",
            "requestedVersion": version,
            "packageVersion": __version__,
        })
        return 2
    script = args.project_root / "scripts" / "package-release.sh"
    proc = run_bounded(
        [str(script), version],
        cwd=args.project_root,
        env={**command_env(args), "REL": ""},
        deadline=time.monotonic() + 7200.0,
        project_root=args.project_root,
    )
    stdout = proc.stdout_tail.strip()
    result = {
        "ok": proc.ok,
        "returncode": proc.returncode,
        "state": proc.state,
        "errorCode": proc.error_code,
        "stdout": stdout,
        "stderr": proc.stderr_tail.strip(),
        "archive": stdout.splitlines()[-1] if stdout else None,
    }
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_build_all(args: argparse.Namespace) -> int:
    return _run_artifact_build(
        args,
        ALL_TARGETS,
        force=bool(getattr(args, "force", False)),
    )




def cmd_init(args: argparse.Namespace) -> int:
    overrides = {
        key: value
        for key, value in {
            "image": args.image,
            "backend": args.backend,
        }.items()
        if value is not None
    }
    if bool(args.no_google_services):
        overrides.update(
            {
                "google_services_provider": PROVIDER_NONE,
                "google_services_release": PROVIDER_NONE,
            }
        )
    context, cfg, lease = initialize_instance(
        args.instance_name,
        project_root=args.project_root,
        overrides=overrides,
        template_path=getattr(args, "config", None),
        from_instance=getattr(args, "from_instance", None),
    )
    print_json(
        {
            "ok": True,
            "instance": context.public_dict(),
            "slot": lease.slot,
            "config": cfg,
        }
    )
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

def cmd_google_services_import(args: argparse.Namespace) -> int:
    result = import_mindthegapps(
        args.context.project_root,
        Path(args.archive).expanduser(),
        Path(args.certificate).expanduser(),
    )
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_google_services_import_microg(args: argparse.Namespace) -> int:
    result = import_microg(
        args.context.project_root,
        Path(args.gmscore).expanduser(),
        Path(args.gsfproxy).expanduser(),
    )
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_google_services_status(args: argparse.Namespace) -> int:
    result = runtime(args).google_services_status(
        require_runtime=bool(args.require_runtime),
    )
    print_json(result)
    return 0 if result.get("ok") else 1


def _google_services_enable_result(args: argparse.Namespace) -> dict[str, Any]:
    spec = load_release_spec(args.context.project_root, args.release)
    if spec.availability != AVAILABILITY_PRODUCTION:
        raise GoogleServicesError(
            "google_services_release_retired",
            "the requested Google services release is retired and cannot be newly selected",
        )
    if (
        args.config.google_services_provider == spec.provider
        and args.config.google_services_release == args.release
    ):
        result = runtime(args).google_services_status()
        result["unchanged"] = True
        result["runtimeReady"] = bool(result.get("ready"))
        result["runtimeError"] = result.get("error")
        result["ok"] = bool(result.get("configured") and result.get("hostReady"))
        return result
    quick_validate_assets(args.context.project_root, spec)
    mutable = runtime(args).google_services_configuration_mutable()
    if mutable.get("ok") is not True:
        return mutable
    cfg = merge_config(
        args.context,
        {
            "google_services_provider": spec.provider,
            "google_services_release": args.release,
            "auto_build_runtime_image": True,
        },
    )
    save_config(args.context, cfg)
    args.config = cfg
    manager = RuntimeManager(args.context, cfg, args.lease)
    manager.operation_lock_held = bool(
        getattr(args, "_operation_lock_held", False)
    )
    result = manager.google_services_status()
    result["changed"] = True
    result["runtimeReady"] = bool(result.get("ready"))
    result["runtimeError"] = result.get("error")
    result["error"] = None
    result["ok"] = True
    result["nextActions"] = [
        f"./xenoid --instance {args.context.instance_name} up"
    ]
    return result


def cmd_google_services_enable(args: argparse.Namespace) -> int:
    result = _google_services_enable_result(args)
    print_json(result)
    return 0 if result.get("ok") else 1


def _google_services_disable_result(args: argparse.Namespace) -> dict[str, Any]:
    if (
        args.config.google_services_provider == PROVIDER_NONE
        and args.config.google_services_release == PROVIDER_NONE
    ):
        result = runtime(args).google_services_status()
        result["unchanged"] = True
        return result
    mutable = runtime(args).google_services_configuration_mutable()
    if mutable.get("ok") is not True:
        return mutable
    cfg = merge_config(
        args.context,
        {
            "google_services_provider": PROVIDER_NONE,
            "google_services_release": PROVIDER_NONE,
        },
    )
    save_config(args.context, cfg)
    args.config = cfg
    manager = RuntimeManager(args.context, cfg, args.lease)
    manager.operation_lock_held = bool(
        getattr(args, "_operation_lock_held", False)
    )
    result = manager.google_services_status()
    result["changed"] = True
    return result


def cmd_google_services_disable(args: argparse.Namespace) -> int:
    result = _google_services_disable_result(args)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_google_services_registry(args: argparse.Namespace) -> int:
    print_json({"ok": True, "releases": registry_public()})
    return 0



def cmd_runtime_build_image(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    if args.dry_run:
        try:
            record = mgr.runtime_image_input_record(args.image)
            result = {"ok": True, "dryRun": True, **record}
        except (InstanceError, OSError, RuntimeError, ValueError) as exc:
            result = {
                "ok": False,
                "dryRun": True,
                "error": getattr(exc, "code", "runtime_image_input_invalid"),
                "message": str(exc),
            }
    else:
        result = mgr.ensure_runtime_image(args.image)
    print_json(result)
    return 0 if result.get("ok") else 1




def cmd_start(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    with cli_operation_lock(args):
        result = mgr.start(dry_run=args.dry_run, wait=not args.no_wait, install_daemon_apk=args.install_daemon, start_colima=args.start_colima, adb_root=not args.no_adb_root, skip_preflight=args.skip_preflight, recreate=args.recreate, defer_proxy=False)
    print_json(result)
    return 0 if result.get("ok") or args.dry_run else 1


def cmd_stop(args: argparse.Namespace) -> int:
    with cli_operation_lock(args):
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


def _status_recommended_action(result: Mapping[str, Any]) -> str:
    current = result.get("recommendedAction")
    allowed = {
        "no-op",
        "resume",
        "start",
        "create",
        "recreate",
        "image-required",
        "daemon-only",
        "daemon-incompatible",
        "helper-only",
        "proxy-recovery",
        "protection-maintenance",
        "legacy-regeneration-recovery",
        "resource-conflict",
    }
    if isinstance(current, str) and current in allowed:
        return current
    if result.get("pendingJournalPhase") or result.get("pendingJournal"):
        return "resume"
    error = result.get("error")
    if error in {"resource_conflict", "ownership_mismatch", "runtime_identity_mismatch"}:
        return "resource-conflict"
    if error == "device_regeneration_legacy_pending":
        return "legacy-regeneration-recovery"
    if error == "daemon_seed_contract_incompatible":
        return "daemon-incompatible"
    if error == "shared_protection_reload_requires_maintenance":
        return "protection-maintenance"
    if isinstance(error, str) and error.startswith("proxy_"):
        return "proxy-recovery"
    runtime_image = result.get("runtimeImage")
    if isinstance(runtime_image, Mapping) and runtime_image.get("ok") is not True:
        return "image-required"
    if result.get("running") is True:
        return (
            "no-op"
            if result.get("containerContractMatches", True) is True
            else "recreate"
        )
    if "containerContractMatches" in result:
        return (
            "start"
            if result.get("containerContractMatches") is True
            else "recreate"
        )
    return "create"


def cmd_status(args: argparse.Namespace) -> int:
    result = runtime(args).status()
    result["recommendedAction"] = _status_recommended_action(result)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_adb(args: argparse.Namespace) -> int:
    result = runtime(args).adb(args.adb_args)
    print_json(result)
    return 0 if result.get("ok") else 1


def _bootstrap_error(result: Any, fallback: str = "daemon_unreachable") -> str:
    if isinstance(result, dict):
        code = result.get("code")
        if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
            return code
        components = result.get("components")
        root = components.get("root") if isinstance(components, dict) else None
        root_error = root.get("errorCode") if isinstance(root, dict) else None
        if (
            isinstance(root_error, str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", root_error)
        ):
            return root_error
    return fallback


def bootstrap_client(args: argparse.Namespace) -> DaemonClient:
    manager = runtime(args)
    reconciled = manager.reconcile_bootstrap()
    if (
        not isinstance(reconciled, dict)
        or reconciled.get("transportReady") is not True
        or reconciled.get("controlReady") is not True
    ):
        code = _bootstrap_error(reconciled)
        raise InstanceError(code, code)
    return daemon(args, manager)


def cmd_daemon_ensure(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    bootstrap = mgr.reconcile_bootstrap()
    proxy = (
        mgr.reconcile_proxy_desired()
        if bootstrap.get("controlReady") is True
        else {"ok": False, "skipped": True}
    )
    result = {
        "ok": bool(bootstrap.get("ok") and proxy.get("ok")),
        "bootstrap": bootstrap,
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
    result = {
        "ok": all(bool(step.get("ok")) for step in (install, bootstrap, proxy)),
        "install": install,
        "bootstrap": bootstrap,
        "proxyConverged": proxy,
    }
    print_json(result)
    return 0 if result["ok"] else 1


def cmd_daemon_start(args: argparse.Namespace) -> int:
    mgr = runtime(args)
    bootstrap = mgr.reconcile_bootstrap()
    proxy = (
        mgr.reconcile_proxy_desired()
        if bootstrap.get("controlReady") is True
        else {"ok": False, "skipped": True}
    )
    result = {
        "ok": bool(bootstrap.get("ok") and proxy.get("ok")),
        "bootstrap": bootstrap,
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
        client = bootstrap_client(args)
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
    require_bootstrap: bool = True,
) -> dict[str, Any]:
    try:
        manager = runtime(args)
        if require_bootstrap:
            reconciled = manager.reconcile_bootstrap()
            if (
                not isinstance(reconciled, dict)
                or reconciled.get("transportReady") is not True
                or reconciled.get("controlReady") is not True
            ):
                return _proxy_failure(_bootstrap_error(reconciled))
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
        _call_proxy_controller(
            args,
            lambda controller: controller.clear(
                discard_unreadable_state=args.discard_unreadable_state
            ),
        )
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
            require_bootstrap=False,
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
) -> tuple[Optional[RuntimeManager], Optional[DaemonClient], Optional[str]]:
    try:
        manager = runtime(args)
        reconciled = manager.reconcile_bootstrap()
        if (
            not isinstance(reconciled, dict)
            or reconciled.get("transportReady") is not True
            or reconciled.get("controlReady") is not True
        ):
            return None, None, _bootstrap_error(reconciled, "camera_unavailable")
        return manager, daemon(args, manager), None
    except InstanceError as exc:
        return None, None, exc.code
    except Exception:
        return None, None, "camera_unavailable"

def _camera_request(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = call()
    except Exception:
        return {"ok": False, "error": "camera request failed"}
    if not isinstance(result, dict):
        return {"ok": False, "error": "invalid camera response"}
    return result


def cmd_camera_status(args: argparse.Namespace) -> int:
    manager, client, bootstrap_error = _camera_ready(args)
    if manager is None or client is None:
        return _emit_camera_result(
            {"ok": False, "error": bootstrap_error or "camera_unavailable"}
        )
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

    manager, client, bootstrap_error = _camera_ready(args)
    if manager is None or client is None:
        return _emit_camera_result(
            {"ok": False, "error": bootstrap_error or "camera_unavailable"}
        )

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
    _, client, bootstrap_error = _camera_ready(args)
    if client is None:
        return _emit_camera_result(
            {"ok": False, "error": bootstrap_error or "camera_unavailable"}
        )
    return _emit_camera_result(_camera_request(lambda: client.camera_settings(args.mode)))


def cmd_camera_clear(args: argparse.Namespace) -> int:
    _, client, bootstrap_error = _camera_ready(args)
    if client is None:
        return _emit_camera_result(
            {"ok": False, "error": bootstrap_error or "camera_unavailable"}
        )
    return _emit_camera_result(_camera_request(lambda: client.camera_clear(args.kind)))


def cmd_camera_apply(args: argparse.Namespace) -> int:
    _, client, bootstrap_error = _camera_ready(args)
    if client is None:
        return _emit_camera_result(
            {"ok": False, "error": bootstrap_error or "camera_unavailable"}
        )
    return _emit_camera_result(_camera_request(client.camera_apply))


def _location_failure(code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "error": code}


# Bounded control-plane failures may trigger one retry through the same
# listener/root/bootstrap coordinator path.
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
        if repairs >= 1:
            return False
        repairs += 1
        reconciled = manager.reconcile_bootstrap()
        return bool(
            isinstance(reconciled, dict)
            and reconciled.get("transportReady") is True
            and reconciled.get("controlReady") is True
        )

    for _ in range(12):
        state = store.load()
        if state is None:
            raise LocationError("location_state_missing")
        epoch = _location_epoch(manager)
        client: Optional[DaemonClient] = None
        android: Optional[dict[str, Any]] = None
        if epoch:
            reconciled = manager.reconcile_bootstrap()
            if (
                isinstance(reconciled, dict)
                and reconciled.get("transportReady") is True
                and reconciled.get("controlReady") is True
            ):
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
    proxy_ok = proxy_rebind.get("ok") is True
    result: dict[str, Any] = {
        "ok": proxy_ok,
        "recreated": recreated,
        "identity": public_summary(state),
        "android": masked_android_status(verified_payload),
        "proxyRebind": proxy_rebind,
    }
    if not proxy_ok:
        result["error"] = _location_error_code(
            proxy_rebind,
            "proxy_reconcile_failed",
        )
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
                reconciled = manager.reconcile_bootstrap()
                if (
                    reconciled.get("transportReady") is not True
                    or reconciled.get("controlReady") is not True
                ):
                    android = {
                        "ok": False,
                        "error": _bootstrap_error(reconciled),
                    }
                else:
                    android = masked_android_status(
                        daemon(args, manager).location_status()
                    )
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
        if manager.location_runtime_container_id() is None:
            state = store.load()
            result = {
                "ok": True,
                "pending": True,
                "host": public_summary(state),
                "nextActions": [
                    f"./xenoid --instance {args.context.instance_name} up",
                ],
            }
        else:
            result = _location_converge(args, manager, store, rebind_proxy=True)
    except (CellularError, LocationError, InstanceError) as exc:
        result = _location_failure(exc.code)
    except Exception:
        result = _location_failure("location_convergence_failed")
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_location_apply(args: argparse.Namespace) -> int:
    """Explicitly converge the persisted Location state."""
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
        client = bootstrap_client(args)
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
    result = bootstrap_client(args).root_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_root_exec(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).root_exec(" ".join(args.command))
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
    result = bootstrap_client(args).frida_start(port=args.port)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_stop(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).frida_stop()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_frida_status(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).frida_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1



def cmd_profile_deploy_helper(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_profile_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_profile_helper_status(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).profile_helper_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_env(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).profile_helper_env()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_profile_helper_dump(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).profile_helper_dump()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_collect(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).collect_fingerprint()
    if args.out and result.get("ok", True):
        write_json_file(args.out, result)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_device_apply(args: argparse.Namespace) -> int:
    profile = read_json_file(args.profile)
    manager = runtime(args)
    bootstrap = manager.reconcile_bootstrap()
    if (
        not isinstance(bootstrap, dict)
        or bootstrap.get("transportReady") is not True
        or bootstrap.get("controlReady") is not True
    ):
        code = _bootstrap_error(bootstrap)
        result: dict[str, Any] = {
            "ok": False,
            "error": code,
            "bootstrap": bootstrap,
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
    result = bootstrap_client(args).set_fingerprint_field(args.field, value)
    if key is not None and result.get("ok") is True:
        state = DeviceIdentityStore(args.context).update_field(args.field, value)
        result = {
            "ok": True,
            "daemon": result,
            "identity": public_identity_state(state),
        }
    print_json(result)
    return 0 if result.get("ok", False) else 1


_KEYBOX_SAFE_PUBLIC_ERRORS = frozenset({
    "attestation_self_test_failed",
    "clear_failed",
    "daemon_response_invalid",
    "daemon_unauthorized",
    "daemon_unreachable",
    "daemon_token_unavailable",
    "daemon_transport_timeout",
    "daemon_transport_unavailable",
    "bootstrap_timeout",
    "rootd_unauthorized",
    "rootd_unavailable",
    "rootd_resource_conflict",
    "invalid_keybox",
    "invalid_request",
    "invalid_stage",
    "key_migration_unavailable",
    "keybox_daemon_unavailable",
    "keybox_file_changed",
    "keybox_file_invalid",
    "keybox_request_failed",
    "keybox_set_failed",
    "keybox_upload_failed",
    "method_not_allowed",
    "native_rejected",
    "native_unavailable",
    "response_too_large",
    "state_persist_failed",
    "unsupported_keybox",
})


def _public_keybox_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        return {"ok": False, "error": "daemon_response_invalid"}
    if value["ok"] is not True:
        error = value.get("error")
        return {
            "ok": False,
            "error": (
                error
                if isinstance(error, str) and error in _KEYBOX_SAFE_PUBLIC_ERRORS
                else "keybox_request_failed"
            ),
        }

    algorithms = value.get("algorithms")
    valid_algorithms = (
        isinstance(algorithms, dict)
        and set(algorithms)
        == {"rsa", "ecdsa", "rsaChainCount", "ecdsaChainCount"}
        and isinstance(algorithms.get("rsa"), bool)
        and isinstance(algorithms.get("ecdsa"), bool)
        and isinstance(algorithms.get("rsaChainCount"), int)
        and not isinstance(algorithms.get("rsaChainCount"), bool)
        and isinstance(algorithms.get("ecdsaChainCount"), int)
        and not isinstance(algorithms.get("ecdsaChainCount"), bool)
        and 0 <= algorithms["rsaChainCount"] <= 64
        and 0 <= algorithms["ecdsaChainCount"] <= 64
    )
    if (
        not isinstance(value.get("configured"), bool)
        or not isinstance(value.get("ready"), bool)
        or not isinstance(value.get("active"), bool)
        or not valid_algorithms
    ):
        return {"ok": False, "error": "daemon_response_invalid"}
    result = {
        "ok": True,
        "configured": value["configured"],
        "ready": value["ready"],
        "active": value["active"],
        "algorithms": {
            "rsa": algorithms["rsa"],
            "ecdsa": algorithms["ecdsa"],
            "rsaChainCount": algorithms["rsaChainCount"],
            "ecdsaChainCount": algorithms["ecdsaChainCount"],
        },
    }
    error = value.get("error")
    if isinstance(error, str) and error in _KEYBOX_SAFE_PUBLIC_ERRORS:
        result["error"] = error
    return result


def _emit_keybox_result(value: Any) -> int:
    result = _public_keybox_result(value)
    print_json(result)
    return 0 if result["ok"] is True else 1


def _keybox_mutation_client(
    args: argparse.Namespace,
) -> tuple[Optional[RuntimeManager], Optional[DaemonClient], Optional[str]]:
    try:
        manager = runtime(args)
        reconciled = manager.reconcile_bootstrap()
        if (
            not isinstance(reconciled, dict)
            or reconciled.get("transportReady") is not True
            or reconciled.get("controlReady") is not True
        ):
            return None, None, _bootstrap_error(
                reconciled,
                "keybox_daemon_unavailable",
            )
        return manager, daemon(args, manager), None
    except InstanceError as exc:
        return None, None, exc.code
    except Exception:
        return None, None, "keybox_daemon_unavailable"


def cmd_device_keybox_set(args: argparse.Namespace) -> int:
    try:
        with _validated_keybox_source(args.file) as validated:
            stream, size, digest, validated_state = validated
            manager, client, bootstrap_error = _keybox_mutation_client(args)
            if manager is None or client is None:
                return _emit_keybox_result(
                    {
                        "ok": False,
                        "error": bootstrap_error or "keybox_daemon_unavailable",
                    }
                )

            try:
                current = os.fstat(stream.fileno())
            except OSError as exc:
                raise _KeyboxFileError("keybox_file_changed") from exc
            if (
                not _private_keybox_file(current)
                or not _same_keybox_file(validated_state, current)
            ):
                raise _KeyboxFileError("keybox_file_changed")

            staging_path: Optional[str] = None
            try:
                try:
                    staged = manager.stage_keybox_source(stream, size)
                except Exception:
                    staged = {"ok": False}
                if not isinstance(staged, dict) or staged.get("ok") is not True:
                    return _emit_keybox_result(
                        {"ok": False, "error": "keybox_upload_failed"}
                    )
                candidate = staged.get("stagingPath")
                if not isinstance(candidate, str):
                    return _emit_keybox_result(
                        {"ok": False, "error": "keybox_upload_failed"}
                    )
                staging_path = candidate
                try:
                    result = client.keybox_source(staging_path, size, digest)
                except Exception:
                    result = {"ok": False, "error": "keybox_set_failed"}
                return _emit_keybox_result(result)
            finally:
                if staging_path is not None:
                    try:
                        manager.cleanup_keybox_staging(staging_path)
                    except Exception:
                        pass
    except _KeyboxFileError as exc:
        return _emit_keybox_result({"ok": False, "error": exc.code})


def cmd_device_keybox_status(args: argparse.Namespace) -> int:
    _, client, bootstrap_error = _keybox_mutation_client(args)
    if client is None:
        result = {
            "ok": False,
            "error": bootstrap_error or "keybox_daemon_unavailable",
        }
    else:
        try:
            result = client.keybox_status()
        except Exception:
            result = {"ok": False, "error": "keybox_daemon_unavailable"}
    return _emit_keybox_result(result)


def cmd_device_keybox_clear(args: argparse.Namespace) -> int:
    _, client, bootstrap_error = _keybox_mutation_client(args)
    if client is None:
        return _emit_keybox_result(
            {
                "ok": False,
                "error": bootstrap_error or "keybox_daemon_unavailable",
            }
        )
    try:
        result = client.keybox_clear()
    except Exception:
        result = {"ok": False, "error": "keybox_request_failed"}
    return _emit_keybox_result(result)


def _regeneration_phase_at_least(
    state: Mapping[str, Any],
    phase: str,
) -> bool:
    return REGENERATION_PHASES.index(str(state["phase"])) >= REGENERATION_PHASES.index(phase)


def _regeneration_result(
    state: Mapping[str, Any],
    *,
    ok: bool,
    error: Optional[str] = None,
    **details: Any,
) -> dict[str, Any]:
    return {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": ok,
        "transactionId": state.get("transactionId"),
        "phase": state.get("phase"),
        **({} if error is None else {"error": error}),
        **details,
    }


def _regeneration_shell_read(manager: RuntimeManager, command: str) -> str:
    result = manager.docker_exec(["sh", "-c", command], timeout=10)
    if result.get("ok") is not True:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "runtime identity surface is unreadable for regeneration verification",
        )
    return str(result.get("stdout", "")).strip()


def _generate_bluetooth_address(before: str) -> str:
    while True:
        candidate = "F4:F5:E8:" + ":".join(f"{octet:02X}" for octet in secrets.token_bytes(3))
        if candidate != before:
            return candidate

def _generate_device_name(before: str) -> str:
    while True:
        candidate = "Pixel 6 Pro " + secrets.token_hex(3).upper()
        if candidate != before:
            return candidate


def _generate_hostname(before: str) -> str:
    while True:
        candidate = "android-" + secrets.token_hex(6)
        if candidate != before:
            return candidate


def _verify_regeneration_target_state(
    manager: RuntimeManager,
    identity_store: DeviceIdentityStore,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail-closed live read-back of every regenerated factor."""
    before = state["before"]
    target = state["target"]
    identity = identity_store.load()
    if (
        identity is None
        or stable_identity_digest(identity["stable"]) != target["stableDigest"]
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "stable identity does not match the regeneration target",
        )
    stable = identity["stable"]
    live = {
        "android_id": _regeneration_shell_read(manager, "settings get secure android_id"),
        "serial": _regeneration_shell_read(manager, "getprop ro.serialno"),
        "boot_serial": _regeneration_shell_read(manager, "getprop ro.boot.serialno"),
        "imei": _regeneration_shell_read(manager, "getprop persist.xenoid.radio.imei"),
        "imeisv": _regeneration_shell_read(manager, "getprop persist.xenoid.radio.imeisv"),
        "boot_id": _regeneration_shell_read(
            manager, "cat /proc/sys/kernel/random/boot_id"
        ),
        "device_name": _regeneration_shell_read(manager, "settings get global device_name"),
        "bluetooth": _regeneration_shell_read(manager, "settings get secure bluetooth_address"),
        "hostname": _regeneration_shell_read(manager, "getprop net.hostname"),
        "statfs_fsid": _regeneration_shell_read(
            manager, "cat /data/local/tmp/xenoid-profile/statfs_fsid 2>/dev/null || true"
        ),
        "drm_device_unique_id": _regeneration_shell_read(
            manager, "cat /data/local/tmp/xenoid-profile/drm_device_unique_id 2>/dev/null || true"
        ),
        "ssaid_present": _regeneration_shell_read(
            manager, "test -f /data/system/users/0/settings_ssaid.xml && echo 1 || echo 0"
        ),
    }
    statfs_status = manager.shared_protection_status().get("statfsFsid")
    if (
        not isinstance(statfs_status, Mapping)
        or statfs_status.get("ok") is not True
        or statfs_status.get("running") is not True
        or statfs_status.get("published") is not True
        or statfs_status.get("staged") != target["statfsFsid"]
        or statfs_status.get("kernel") != target["statfsFsid"]
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "kernel statfs FSID diverges from the regeneration target",
        )
    expected = {
        "android_id": stable["androidId"],
        "serial": stable["serial"],
        "boot_serial": stable["serial"],
        "imei": stable["imei"],
        "imeisv": stable["imeisv"],
        "boot_id": target["bootId"],
        "device_name": target["deviceName"],
        "bluetooth": target["bluetoothAddress"],
        "hostname": target["hostname"],
        "statfs_fsid": target["statfsFsid"],
        "drm_device_unique_id": target["drmDeviceUniqueId"],
    }
    diverged = [key for key, value in expected.items() if live[key] != value]
    if diverged:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "regenerated identity diverges from its fixed target: " + ", ".join(sorted(diverged)),
        )
    if live["ssaid_present"] not in {"0", "1"}:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "per-app SSAID state is unreadable after regeneration",
        )
    snapshot = manager.regeneration_snapshot()
    if (
        snapshot.get("containerId") != state["before"]["containerId"]
        or snapshot.get("containerEpoch") != state["before"]["containerEpoch"]
        or snapshot.get("imageId") != state["before"]["imageId"]
        or snapshot.get("imageInputSha256")
        != state["before"]["imageInputSha256"]
        or snapshot.get("imageBootInputSha256")
        != state["before"]["imageBootInputSha256"]
    ):
        raise IdentityError(
            "device_regeneration_container_changed",
            "regeneration runtime no longer matches its journal",
        )
    if snapshot["runtimeEpoch"] == before["runtimeEpoch"]:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "runtime epoch did not change across the soft reboot",
        )
    if (
        snapshot["simEpoch"] != target["simEpoch"]
        or snapshot["locationDigest"] != target["locationProfileDigest"]
        or snapshot["googleBindingDigest"] != target["googleBindingDigest"]
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "SIM, location, or Google binding state diverges from the fixed target",
        )
    google_identity = _regeneration_google_identity(
        manager,
        state,
        activate=False,
    )
    if google_identity.get("ok") is not True:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "app-visible Google identity diverges from the regenerated target",
        )
    return {"snapshot": snapshot, "googleIdentity": google_identity}


def _regeneration_base_profile(
    manager: RuntimeManager,
    client: Any,
) -> dict[str, Any]:
    """Load the instance's fingerprint profile exactly as identity convergence does."""
    dumped = client.profile_helper_dump()
    raw = dumped.get("stdout") if isinstance(dumped, dict) else None
    profile: Any = None
    if isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= 256 * 1024:
        try:
            profile = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            profile = None
    if not isinstance(profile, dict) or profile.get("schema") != "dev.xenoid.fingerprint/v1":
        canonical = (
            manager.context.project_root
            / "examples"
            / "fingerprints"
            / "pixel-raven-android13.json"
        )
        try:
            info = canonical.lstat()
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 256 * 1024:
                raise OSError("canonical device profile is unsafe")
            profile = json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IdentityError(
                "device_profile_required",
                "identity regeneration requires the canonical Raven profile",
            ) from exc
    if not isinstance(profile, dict) or profile.get("schema") != "dev.xenoid.fingerprint/v1":
        raise IdentityError(
            "device_profile_required",
            "identity regeneration requires the canonical Raven profile",
        )
    return profile

def _stage_regeneration_drm(
    manager: RuntimeManager,
    device_unique_id: str,
) -> dict[str, Any]:
    return manager.stage_drm_identity(device_unique_id)


def _rehydrate_regeneration_target(
    manager: RuntimeManager,
    client: Any,
    identity_store: DeviceIdentityStore,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    target = state["target"]
    if _regeneration_phase_at_least(state, "props_committed"):
        identity = identity_store.load()
        if not isinstance(identity, Mapping):
            return {"ok": False, "error": "device_regeneration_state_invalid"}
        boot = identity.get("pending") or identity.get("active")
        if not isinstance(boot, Mapping):
            return {"ok": False, "error": "device_regeneration_state_invalid"}
        profile = _regeneration_base_profile(manager, client)
        effective = materialize_profile(profile, identity, boot)
        applied = client.apply_fingerprint(effective, regenerate_unique=False)
        if not isinstance(applied, Mapping) or applied.get("ok") is not True:
            return {"ok": False, "error": "device_identity_apply_failed"}
        drm = _stage_regeneration_drm(manager, str(target["drmDeviceUniqueId"]))
        if drm.get("ok") is not True:
            return {"ok": False, "error": "drm_identity_stage_failed"}
        hostname = client.set_fingerprint_field("net.hostname", target["hostname"])
        if not isinstance(hostname, Mapping) or hostname.get("ok") is not True:
            return {"ok": False, "error": "profile_field_apply_failed", "field": "net.hostname"}
        hidden = client.hide_apply()
        if not isinstance(hidden, Mapping) or hidden.get("ok") is not True:
            return {"ok": False, "error": "hide_apply_failed"}
    if _regeneration_phase_at_least(state, "settings_committed"):
        for field, value in (
            ("device_name", target["deviceName"]),
            ("bluetooth_address", target["bluetoothAddress"]),
        ):
            applied = client.set_fingerprint_field(field, value)
            if not isinstance(applied, Mapping) or applied.get("ok") is not True:
                return {"ok": False, "error": "profile_field_apply_failed", "field": field}
    if _regeneration_phase_at_least(state, "storage_identity_committed"):
        fsid = manager.shared_protection_manager().set_statfs_fsid(
            str(target["statfsFsid"])
        )
        if fsid.get("ok") is not True:
            return {
                "ok": False,
                "error": str(fsid.get("error") or "statfs_fsid_param_failed"),
            }
    return {"ok": True}



def _regeneration_google_preflight(
    manager: RuntimeManager,
    transaction_id: str,
) -> dict[str, Any]:
    """Deterministic host-only Google gate, safe to run before journaling.

    Only local state is consulted: the configured provider, the committed
    runtime binding's compatibility with the current spec, and the derived
    GSF target. Runtime health is proven separately by the verified no-op
    convergence plan and by the post-journal ``reconcile_google`` pass, so
    this preflight never calls a runtime status path that could repair or
    rekey Google identity before the journal owns the fixed targets.
    """
    provider = manager.cfg.google_services_provider
    if provider == PROVIDER_NONE:
        return {"ok": True, "skipped": True}
    if provider != PROVIDER_MICROG:
        return {"ok": False, "error": "google_identity_rotation_unsupported"}
    binding_store = GoogleBindingStore(manager.context, manager.lease)
    try:
        binding = binding_store.load()
        if binding is None or binding.get("state") != "committed":
            raise GoogleServicesError(
                "google_services_runtime_not_ready",
                "Google runtime binding is not committed",
            )
        spec = resolve_google_runtime_spec(
            manager.context,
            manager.cfg,
            "device-regeneration-preflight",
            require_assets=False,
        )
        if not binding_matches(binding, spec):
            raise GoogleServicesError(
                "google_services_new_instance_required",
                "Google runtime binding does not match the configured spec",
            )
        binding_store.regeneration_gsf_android_id(transaction_id)
    except GoogleServicesError as exc:
        return {"ok": False, "error": exc.code}
    return {"ok": True}


def _regeneration_google_identity(
    manager: RuntimeManager,
    state: Mapping[str, Any],
    *,
    activate: bool,
) -> dict[str, Any]:
    provider = manager.cfg.google_services_provider
    if provider == PROVIDER_NONE:
        return {
            "ok": True,
            "skipped": True,
            "reason": "google_services_disabled",
        }
    if provider != PROVIDER_MICROG:
        return {
            "ok": False,
            "error": "google_identity_rotation_unsupported",
        }
    try:
        gsf_android_id = GoogleBindingStore(
            manager.context,
            manager.lease,
        ).regeneration_gsf_android_id(str(state["transactionId"]))
    except GoogleServicesError as exc:
        return {"ok": False, "error": exc.code}
    expected_gsf_digest = hashlib.sha256(
        gsf_android_id.encode("ascii")
    ).hexdigest()
    empty_advertising_digest = hashlib.sha256(
        b"00000000-0000-0000-0000-000000000000"
    ).hexdigest()
    client = manager.daemon_client(timeout=30.0)
    before = state["before"]

    def verified(value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict) or value.get("ok") is not True:
            return None
        advertising_digest = value.get("advertisingIdSha256")
        gsf_digest = value.get("gsfAndroidIdSha256")
        if (
            not isinstance(advertising_digest, str)
            or not isinstance(gsf_digest, str)
            or gsf_digest != expected_gsf_digest
            or advertising_digest == empty_advertising_digest
            or advertising_digest == before["advertisingIdDigest"]
            or gsf_digest == before["gsfAndroidIdDigest"]
        ):
            return None
        return {
            "ok": True,
            "provider": PROVIDER_MICROG,
            "rotated": True,
            "advertisingIdSha256": advertising_digest,
            "gsfAndroidIdSha256": gsf_digest,
        }

    def accepted(value: Any) -> Optional[dict[str, Any]]:
        candidate = verified(value)
        if candidate is None:
            return None
        # Digests alone do not prove durability: a seed that crashed between
        # the provider write and the marker publication reads back matching
        # but is one GMS restart away from reverting, and a stale nonempty
        # marker passes a bare existence check. Accept only on the daemon's
        # strict offlineSeeded proof (marker file hygiene plus marker GSF ==
        # provider GSF); otherwise the caller runs the idempotent activate,
        # which always republishes the marker.
        if value.get("offlineSeeded") is not True:
            return None
        return candidate

    if activate:
        current = client.google_identity_inspect(timeout=60.0)
        current_accepted = accepted(current)
        if current_accepted is not None:
            result = client.google_identity_status(timeout=60.0)
        else:
            result = client.google_identity_activate(gsf_android_id, timeout=60.0)
    else:
        result = client.google_identity_inspect(timeout=60.0)
    final = accepted(result)
    if final is not None:
        return final
    if not isinstance(result, dict) or result.get("ok") is not True:
        return {
            "ok": False,
            "error": str(
                result.get("error") if isinstance(result, dict) else None
                or "google_identity_rotation_failed"
            ),
        }
    return {
        "ok": False,
        "error": "google_identity_rotation_unverified",
    }



def _regeneration_plan_is_runtime_only(plan: ConvergencePlan) -> bool:
    """A fresh regeneration may inspect/accept, but must not converge state."""
    return (
        plan.resolution == "complete"
        and plan.image_action == "reuse-selected"
        and plan.runtime_action == "reuse"
        and plan.boot_seed_action == "none"
        and plan.daemon_action == "reuse"
        and not plan.deploy_components
        and plan.identity_action == "reuse"
        and plan.location_action == "reuse"
        and plan.proxy_action == "reuse"
        and plan.keybox_action == "reuse"
        and plan.camera_action == "reuse"
        and plan.google_action == "reuse"
        and plan.protection_action == "reuse"
    )


def _regeneration_runtime_preflight(manager: RuntimeManager) -> dict[str, Any]:
    """Prove the checkout and live runtime are converged before journaling.

    Strictly observational: the only executor call is a dry-run inspection,
    and acceptance is the verified runtime-only no-op plan itself. The plan
    is never executed — there is no accept run and no auto follow-up, so a
    fresh regeneration cannot mutate runtime, journal, or identity state
    before ``RegenerationJournal.prepare`` owns the fixed targets.
    """
    executor = ConvergenceExecutor(manager)
    inspected = executor.run(skip_build=True, dry_run=True)
    raw_plan = inspected.get("plan") if isinstance(inspected, Mapping) else None
    try:
        plan = (
            ConvergencePlan.from_dict(raw_plan)
            if isinstance(raw_plan, Mapping)
            else None
        )
    except Exception:
        plan = None
    if (
        not isinstance(inspected, dict)
        or inspected.get("ok") is not True
        or inspected.get("dryRun") is not True
        or plan is None
        or inspected.get("initialPlanDigest") != plan.plan_digest
        or not _regeneration_plan_is_runtime_only(plan)
    ):
        return {
            "ok": False,
            "error": "device_regeneration_runtime_not_converged",
            "convergence": inspected,
        }
    return {"ok": True, "convergence": inspected}


def _regeneration_preflight_failure(
    error: str,
    **details: Any,
) -> dict[str, Any]:
    """Canonical v3 failure before any journal exists.

    ``phase`` is the external ``preflight`` marker, never a journal phase:
    no transaction was prepared, so nothing can be resumed.
    """
    return {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": False,
        "resumed": False,
        "phase": "preflight",
        "runtimeOnly": True,
        "containerRecreated": False,
        "error": error,
        **details,
    }


def _regeneration_exception_result(context: Any, exc: Exception) -> dict[str, Any]:
    """Canonical v3 failure envelope for an interrupted execution.

    When a journal exists its transaction and live phase identify the
    resumable attempt; before journaling the failure is a preflight-class
    result with ``resumed`` false. Raw target values stay journal-private
    either way.
    """
    result: dict[str, Any] = {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": False,
        "runtimeOnly": True,
        "containerRecreated": False,
        "error": getattr(exc, "code", "device_regeneration_state_invalid"),
    }
    try:
        state = RegenerationJournal(context).load()
    except IdentityError:
        state = None
    if state is None:
        result["resumed"] = False
        result["phase"] = "preflight"
    else:
        result["resumed"] = True
        result["transactionId"] = state["transactionId"]
        result["phase"] = state["phase"]
    return result


def _regeneration_google_runtime_postcondition(
    manager: RuntimeManager,
) -> dict[str, Any]:
    """Require a ready Google runtime with a durable offline-seeded identity.

    ``reconcile_google("reuse")`` proves readiness; the mode check proves the
    seeded-identity marker survived, which ``ok`` alone does not cover.
    """
    google_runtime = manager.reconcile_google("reuse")
    if not isinstance(google_runtime, dict) or google_runtime.get("ok") is not True:
        return {
            "ok": False,
            "error": str(
                google_runtime.get("error")
                if isinstance(google_runtime, Mapping)
                else None
            )
            or "google_services_runtime_not_ready",
            "googleRuntime": google_runtime,
        }
    if (
        manager.cfg.google_services_provider == PROVIDER_MICROG
        and google_runtime.get("googleIdentityMode") != "offline-seeded"
    ):
        return {
            "ok": False,
            "error": "google_identity_not_offline_seeded",
            "googleRuntime": google_runtime,
        }
    return {"ok": True, "googleRuntime": google_runtime}

def _regeneration_dry_run_result(
    state: Optional[Mapping[str, Any]],
) -> dict[str, Any]:
    phase = str(state["phase"]) if state is not None else None
    completed = REGENERATION_PHASES.index(phase) if phase is not None else -1
    return {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": True,
        "dryRun": True,
        "resumed": state is not None,
        "phase": phase,
        "runtimeOnly": True,
        "containerRecreated": False,
        "actions": list(REGENERATION_PHASES[completed + 1 :]),
    }


def _regeneration_success_result(
    state: Mapping[str, Any],
    *,
    resumed: bool,
    cleaned: bool = False,
    google_identity: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    regeneration = {
        "schema": "dev.xenoid.device-regenerate/v3",
        "transactionId": state["transactionId"],
        "resumed": resumed,
        "phase": "committed",
        "runtimeOnly": True,
        "containerRecreated": False,
        **({"cleaned": True} if cleaned else {}),
        **(
            {"googleIdentity": dict(google_identity)}
            if isinstance(google_identity, Mapping)
            else {}
        ),
    }
    return {**regeneration, "ok": True, "regeneration": regeneration}


def _execute_device_regeneration(args: argparse.Namespace) -> dict[str, Any]:
    context = args.context
    identity_store = DeviceIdentityStore(context)
    journal = RegenerationJournal(context)
    manager = runtime(args)
    state = journal.load()
    resumed = state is not None
    if state is not None:
        engine = manager.ensure_engine_started()
        if engine.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(engine.get("error") or "engine_unavailable"),
                engine=engine,
            )
        pinned = state["before"]
        # An engine/VM reboot unloads the kmod and eBPF; restore the exact
        # journal-pinned protection deployment while no runtime is active,
        # before starting the pinned container. A checkout change during the
        # pending transaction fails closed as inputs-changed.
        protection = manager.maintain_shared_protection(
            expected_digest=str(pinned["protectionExpectedDigest"])
        )
        if protection.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    protection.get("error") or "shared_protection_not_ready"
                ),
                protection=protection,
            )
        resumed_runtime = manager.ensure_regeneration_runtime(
            str(pinned["containerId"]),
            str(pinned["containerEpoch"]),
            str(pinned["imageId"]),
            str(pinned["imageInputSha256"]),
            str(pinned["imageBootInputSha256"]),
        )
        if resumed_runtime.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    resumed_runtime.get("error")
                    or "device_regeneration_runtime_unavailable"
                ),
                runtime=resumed_runtime,
            )
        # A stopped container restarts without rootd or any reconciled
        # control-plane component; re-provision before rehydration calls
        # reach them, then re-run the single-user guard before mutating.
        bootstrap = manager.reconcile_bootstrap()
        if bootstrap.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    bootstrap.get("error") or "bootstrap_reconcile_failed"
                ),
                bootstrap=bootstrap,
            )
        manager.assert_regeneration_single_user()
    if state is None:
        identity = identity_store.load()
        transaction_id = secrets.token_hex(16)
        # Deterministic host-only gates run before anything can mutate: the
        # Google provider/binding preflight reads only local state, and the
        # runtime preflight accepts only a verified no-op dry-run plan.
        google_preflight = _regeneration_google_preflight(manager, transaction_id)
        if google_preflight.get("ok") is not True:
            return _regeneration_preflight_failure(
                str(
                    google_preflight.get("error")
                    or "google_identity_rotation_unsupported"
                ),
            )
        runtime_preflight = _regeneration_runtime_preflight(manager)
        if runtime_preflight.get("ok") is not True:
            return _regeneration_preflight_failure(
                str(
                    runtime_preflight.get("error")
                    or "device_regeneration_runtime_not_converged"
                ),
                convergence=runtime_preflight.get("convergence"),
            )
        if identity is None:
            # Structural invariant: a verified no-op preflight means the
            # identity component is converged, hence initialized. Never
            # create identity state outside the journal transaction.
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device identity must be initialized before regeneration",
            )
        before = manager.regeneration_snapshot()
        sim_epoch = secrets.token_hex(16)
        while sim_epoch == before["simEpoch"]:
            sim_epoch = secrets.token_hex(16)
        statfs_fsid = secrets.token_hex(8)
        while statfs_fsid == before["statfsFsid"] or int(statfs_fsid, 16) == 0:
            statfs_fsid = secrets.token_hex(8)
        drm_id = secrets.token_hex(16)
        while drm_id == before["drmDeviceUniqueId"]:
            drm_id = secrets.token_hex(16)
        location_target = LocationStateStore(
            context.state_root
        ).regeneration_target(sim_epoch)
        stable_target = generate_stable_target(identity["stable"])
        target = {
            "stableDigest": stable_identity_digest(stable_target),
            "stable": stable_target,
            "simEpoch": sim_epoch,
            "locationProfileDigest": location_target["profileDigest"],
            "bootId": generate_boot_id(),
            "statfsFsid": statfs_fsid,
            "bluetoothAddress": _generate_bluetooth_address(before["bluetoothAddress"]),
            "deviceName": _generate_device_name(before["deviceName"]),
            "hostname": _generate_hostname(before["hostname"]),
            "googleBindingDigest": before["googleBindingDigest"],
            "drmDeviceUniqueId": drm_id,
        }
        # The journal owns every fixed target before any identity store
        state = journal.prepare(transaction_id, before, target)
    else:
        pending = identity_store.load()
        pending_stable = (
            pending.get("pendingStable") if isinstance(pending, Mapping) else None
        )
        mismatch = (
            isinstance(pending_stable, Mapping)
            and (
                pending_stable.get("transactionId") != state["transactionId"]
                or pending_stable.get("digest") != state["target"]["stableDigest"]
            )
        )
        if (
            mismatch and state["phase"] != "prepared"
            or not isinstance(pending_stable, Mapping)
            and state["phase"] not in {"prepared", "committed"}
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "regeneration journal and stable target disagree",
            )
    client = manager.daemon_client(timeout=30.0)
    if resumed:
        rehydrated = _rehydrate_regeneration_target(
            manager,
            client,
            identity_store,
            state,
        )
        if rehydrated.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    rehydrated.get("error")
                    or "device_regeneration_rehydrate_failed"
                ),
                rehydrate=rehydrated,
            )

    if state["phase"] == "committed":
        current_identity = identity_store.load()
        if (
            current_identity is None
            or stable_identity_digest(current_identity["stable"])
            != state["target"]["stableDigest"]
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "committed regeneration stable identity does not match target",
            )
        # The committed marker is only a crash-resume hint: re-prove the live
        # surfaces and the Google postconditions before clearing anything.
        google_identity = _regeneration_google_identity(
            manager,
            state,
            activate=False,
        )
        if google_identity.get("ok") is not True:
            # A seed that crashed before marker publication reads back
            # matching but unseeded; one idempotent activate completes it.
            google_identity = _regeneration_google_identity(
                manager,
                state,
                activate=True,
            )
        if google_identity.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    google_identity.get("error")
                    or "google_identity_rotation_unverified"
                ),
                googleIdentity=google_identity,
            )
        verified_committed = _verify_regeneration_target_state(
            manager,
            identity_store,
            state,
        )
        google_identity = verified_committed["googleIdentity"]
        google_runtime = _regeneration_google_runtime_postcondition(manager)
        if google_runtime.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    google_runtime.get("error")
                    or "google_services_runtime_not_ready"
                ),
                googleIdentity=google_identity,
                googleRuntime=google_runtime.get("googleRuntime"),
            )
        if isinstance(pending_stable, Mapping):
            identity_store.clear_regeneration_stable(state["transactionId"])
        manager.clear_regeneration_restart_receipt(str(state["transactionId"]))
        journal.clear()
        return _regeneration_success_result(
            state,
            resumed=True,
            cleaned=True,
            google_identity=google_identity,
        )
    if not _regeneration_phase_at_least(state, "staged"):
        staged_identity = identity_store.load()
        if not isinstance(staged_identity, Mapping):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device identity disappeared during regeneration",
            )
        staged_pending = staged_identity.get("pendingStable")
        if (
            isinstance(staged_pending, Mapping)
            and staged_pending.get("transactionId") != state["transactionId"]
        ):
            # Legacy v1/v2 delete-and-rerun recovery is now journal-owned:
            # the new transaction's fixed targets exist before the orphan
            # marker is cleared. The live stable must still equal the
            # journal's observed before digest, binding cleanup to this attempt.
            if (
                stable_identity_digest(staged_identity["stable"])
                != state["before"]["stableDigest"]
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "orphaned stable target does not match regeneration before-state",
                )
            identity_store.recover_orphaned_regeneration_stable()
            staged_identity = identity_store.load()
            staged_pending = (
                staged_identity.get("pendingStable")
                if isinstance(staged_identity, Mapping)
                else None
            )
        if not isinstance(staged_pending, Mapping):
            # Crash between journal prepare and store staging: re-stage the
            # exact journal-fixed target; the call is idempotent.
            staged_identity = identity_store.prepare_regeneration_stable(
                str(state["transactionId"]),
                state["target"]["stable"],
            )
            staged_pending = staged_identity.get("pendingStable")
        if (
            not isinstance(staged_pending, Mapping)
            or staged_pending.get("transactionId") != state["transactionId"]
            or staged_pending.get("digest") != state["target"]["stableDigest"]
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable regeneration target was not persisted",
            )
        identity_store.stage_regeneration_boot(str(state["target"]["bootId"]))
        committed_identity = identity_store.commit_regeneration_stable(
            str(state["transactionId"])
        )
        if stable_identity_digest(committed_identity["stable"]) != state["target"]["stableDigest"]:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable identity did not reach its fixed target",
            )
        state = journal.advance("staged")
    identity = identity_store.load()
    stable = identity.get("stable") if isinstance(identity, Mapping) else None
    pending_boot = identity.get("pending") if isinstance(identity, Mapping) else None
    active_boot = identity.get("active") if isinstance(identity, Mapping) else None
    active_boot_matches = (
        isinstance(active_boot, Mapping)
        and active_boot.get("bootId") == state["target"]["bootId"]
    )
    pending_boot_matches = (
        isinstance(pending_boot, Mapping)
        and pending_boot.get("bootId") == state["target"]["bootId"]
    )
    boot_matches = (
        active_boot_matches
        if _regeneration_phase_at_least(state, "soft_rebooted")
        else pending_boot_matches or active_boot_matches
    )
    if (
        not isinstance(stable, Mapping)
        or stable_identity_digest(stable) != state["target"]["stableDigest"]
        or not boot_matches
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "staged identity does not match the fixed target",
        )
    if not _regeneration_phase_at_least(state, "props_committed"):
        profile = _regeneration_base_profile(manager, client)
        effective = materialize_profile(profile, identity, pending_boot)
        applied = client.apply_fingerprint(effective, regenerate_unique=False)
        if not isinstance(applied, dict) or applied.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    applied.get("error") if isinstance(applied, dict) else None
                    or "device_identity_apply_failed"
                ),
            )
        staged_drm = _stage_regeneration_drm(
            manager,
            str(state["target"]["drmDeviceUniqueId"]),
        )
        if staged_drm.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error="drm_identity_stage_failed",
            )
        hostname = client.set_fingerprint_field(
            "net.hostname", state["target"]["hostname"]
        )
        if not isinstance(hostname, dict) or hostname.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error="profile_field_apply_failed",
                field="net.hostname",
            )
        hidden = client.hide_apply()
        if not isinstance(hidden, dict) or hidden.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(hidden.get("error") if isinstance(hidden, dict) else None
                          or "hide_apply_failed"),
            )
        state = journal.advance("props_committed")
    if not _regeneration_phase_at_least(state, "settings_committed"):
        for field, value in (
            ("device_name", state["target"]["deviceName"]),
            ("bluetooth_address", state["target"]["bluetoothAddress"]),
        ):
            applied = client.set_fingerprint_field(field, value)
            if not isinstance(applied, dict) or applied.get("ok") is not True:
                return _regeneration_result(
                    state,
                    ok=False,
                    error="profile_field_apply_failed",
                    field=field,
                )
        state = journal.advance("settings_committed")
    if not _regeneration_phase_at_least(state, "radio_committed"):
        location_store = LocationStateStore(context.state_root)
        location_state = location_store.rotate_sim_identity(
            sim_epoch=str(state["target"]["simEpoch"]),
            expected_epoch=str(state["before"]["simEpoch"]),
            expected_profile_digest=str(
                state["target"]["locationProfileDigest"]
            ),
        )
        epoch = manager._daemon_runtime_epoch()
        if epoch is None:
            return _regeneration_result(state, ok=False, error="device_runtime_not_running")
        pending_location = location_state.get("pending")
        if (
            isinstance(pending_location, Mapping)
            and pending_location.get("phase") == "armed"
            and pending_location.get("stagedRuntimeEpoch") != epoch
        ):
            # Retry after a crash between arm_restart and the journal advance
            # where the daemon also restarted (START_STICKY): the arm proof is
            # stale, so rewind and re-stage against the live daemon.
            location_state = location_store.restage(epoch)
        _location_stage(location_store, client, location_state, epoch, mark=True)
        location_store.arm_restart()
        state = journal.advance("radio_committed")
    if not _regeneration_phase_at_least(state, "storage_identity_committed"):
        fsid = manager.shared_protection_manager().set_statfs_fsid(
            str(state["target"]["statfsFsid"])
        )
        if fsid.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(fsid.get("error") or "statfs_fsid_param_failed"),
            )
        state = journal.advance("storage_identity_committed")
    if not _regeneration_phase_at_least(state, "soft_rebooted"):
        location_store = LocationStateStore(context.state_root)
        location_state = location_store.load()
        if not isinstance(location_state, Mapping):
            raise LocationError("location_state_missing")
        active = location_state.get("active")
        pending_location = location_state.get("pending")
        already_promoted = (
            isinstance(active, Mapping)
            and str(active.get("profileDigest"))
            == str(state["target"]["locationProfileDigest"])
            and str(active.get("simEpoch")) == str(state["target"]["simEpoch"])
        )
        restart_observed = already_promoted
        if not already_promoted:
            if not isinstance(pending_location, Mapping):
                raise LocationError("location_pending_missing")
            location_phase = pending_location.get("phase")
            if location_phase not in {"armed", "restarted"}:
                raise LocationError("location_phase_invalid")
            completed_userspace = state["restartCompletedUserspaceEpoch"]
            requested_userspace = state["restartRequestedUserspaceEpoch"]
            if completed_userspace or requested_userspace:
                current_userspace_epoch = manager._userspace_runtime_epoch()
                if current_userspace_epoch is None:
                    return _regeneration_result(
                        state, ok=False, error="device_runtime_not_running"
                    )
                receipt = manager.regeneration_restart_receipt(
                    str(state["transactionId"])
                )
                if receipt.get("ok") is True and completed_userspace:
                    # A journaled completion epoch plus the rootd receipt
                    # prove the restart already ran exactly once. A later
                    # userspace epoch drift (spontaneous zygote restart) is
                    # still that same completed restart: never restart a
                    # second time, never re-wipe SSAIDs.
                    restart_observed = True
                elif (
                    receipt.get("ok") is True
                    and not completed_userspace
                    and requested_userspace
                    and requested_userspace != current_userspace_epoch
                ):
                    # The rootd receipt proves the delete+RIL+zygote command
                    # reached its final instruction; the changed epoch proves
                    # the requested restart took effect.
                    state = journal.advance(
                        "storage_identity_committed",
                        restartCompletedUserspaceEpoch=current_userspace_epoch,
                    )
                    restart_observed = True
        if not restart_observed and not state["restartRequestedUserspaceEpoch"]:
            # Persist the pre-restart userspace epoch before the reboot so a
            # crash between the reboot and the completion record stays
            # provable and never triggers a second restart.
            requested_userspace_epoch = manager._userspace_runtime_epoch()
            if requested_userspace_epoch is None:
                return _regeneration_result(
                    state, ok=False, error="device_runtime_not_running"
                )
            state = journal.advance(
                "storage_identity_committed",
                restartRequestedUserspaceEpoch=requested_userspace_epoch,
            )

        rebooted = manager.soft_reboot(
            require_health=False,
            reset_ssaid=not restart_observed,
            userspace_restart_observed=restart_observed,
            restart_receipt=str(state["transactionId"]),
        )
        if rebooted.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(rebooted.get("error") or "soft_reboot_timeout"),
                softReboot=rebooted,
            )
        new_epoch = manager._daemon_runtime_epoch()
        if new_epoch is None:
            return _regeneration_result(
                state, ok=False, error="device_runtime_not_running"
            )
        new_userspace_epoch = manager._userspace_runtime_epoch()
        if new_userspace_epoch is None:
            return _regeneration_result(
                state, ok=False, error="device_runtime_not_running"
            )
        if manager.regeneration_restart_receipt(
            str(state["transactionId"])
        ).get("ok") is not True:
            return _regeneration_result(
                state, ok=False, error="soft_reboot_receipt_missing"
            )
        state = journal.advance(
            "storage_identity_committed",
            restartCompletedUserspaceEpoch=new_userspace_epoch,
        )
        if not already_promoted:
            if location_phase == "armed":
                location_store.mark_restarted(new_epoch)
            location_state = location_store.load()
            if not isinstance(location_state, Mapping):
                raise LocationError("location_state_missing")
            digest = location_store.target_profile(location_state)["identityDigest"]
            verified = client.location_verify(digest, new_epoch)
            if (
                not isinstance(verified, dict)
                or verified.get("ok") is not True
                or verified.get("verified") is not True
            ):
                return _regeneration_result(
                    state, ok=False, error="location_verify_failed"
                )
            location_store.promote(new_epoch)
        healthy = client.health(timeout=60.0)
        if not isinstance(healthy, dict) or healthy.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error="soft_reboot_daemon_timeout",
            )
        identity = identity_store.load()
        pending_boot = (
            identity.get("pending") if isinstance(identity, Mapping) else None
        )
        active_boot = (
            identity.get("active") if isinstance(identity, Mapping) else None
        )
        active_boot_matches = (
            isinstance(active_boot, Mapping)
            and active_boot.get("bootId") == state["target"]["bootId"]
        )
        pending_boot_matches = (
            isinstance(pending_boot, Mapping)
            and pending_boot.get("bootId") == state["target"]["bootId"]
        )
        if pending_boot_matches:
            identity_store.mark_applied(str(pending_boot["containerEpoch"]))
        elif not active_boot_matches:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "boot identity target is missing after the soft reboot",
            )
        location_converged = manager.reconcile_location("converge")
        if location_converged.get("ok") is not True:
            return _regeneration_result(
                state,
                ok=False,
                error=str(
                    location_converged.get("error")
                    or "location_convergence_failed"
                ),
                location=location_converged,
            )
        state = journal.advance("soft_rebooted")
    google_reset_pending = not _regeneration_phase_at_least(
        state, "google_reset"
    )
    if google_reset_pending:
        google_identity = _regeneration_google_identity(
            manager,
            state,
            activate=True,
        )
    else:
        google_identity = _regeneration_google_identity(
            manager,
            state,
            activate=False,
        )
        if google_identity.get("ok") is not True:
            google_identity = _regeneration_google_identity(
                manager,
                state,
                activate=True,
            )
    if google_identity.get("ok") is not True:
        return _regeneration_result(
            state,
            ok=False,
            error=str(
                google_identity.get("error")
                or (
                    "google_identity_rotation_failed"
                    if google_reset_pending
                    else "google_identity_rotation_unverified"
                )
            ),
            googleIdentity=google_identity,
        )
    google_runtime = _regeneration_google_runtime_postcondition(manager)
    if google_runtime.get("ok") is not True:
        return _regeneration_result(
            state,
            ok=False,
            error=str(
                google_runtime.get("error")
                or "google_services_runtime_not_ready"
            ),
            googleIdentity=google_identity,
            googleRuntime=google_runtime.get("googleRuntime"),
        )
    if google_reset_pending:
        state = journal.advance("google_reset")
    if not _regeneration_phase_at_least(state, "verified"):
        state = journal.advance("verified")
    # The verified marker cannot make volatile runtime evidence durable:
    # re-prove the identical live target and Google postconditions used by
    # committed-cleanup immediately before committing/clearing.
    verified_live = _verify_regeneration_target_state(manager, identity_store, state)
    google_identity = verified_live["googleIdentity"]
    final_google_runtime = _regeneration_google_runtime_postcondition(manager)
    if final_google_runtime.get("ok") is not True:
        return _regeneration_result(
            state,
            ok=False,
            error=str(
                final_google_runtime.get("error")
                or "google_services_runtime_not_ready"
            ),
            googleIdentity=google_identity,
            googleRuntime=final_google_runtime.get("googleRuntime"),
        )
    state = journal.advance("committed")
    identity_store.clear_regeneration_stable(str(state["transactionId"]))
    manager.clear_regeneration_restart_receipt(str(state["transactionId"]))
    journal.clear()
    return _regeneration_success_result(
        state,
        resumed=resumed,
        google_identity=google_identity,
    )


def cmd_device_regenerate(args: argparse.Namespace) -> int:
    try:
        if args.dry_run:
            result = _regeneration_dry_run_result(
                RegenerationJournal(args.context).load()
            )
        else:
            result = _execute_device_regeneration(args)
    except (IdentityError, InstanceError, LocationError, StorageError) as exc:
        result = _regeneration_exception_result(args.context, exc)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_plan(args: argparse.Namespace) -> int:
    result = runtime(args).automation_plan(args.script)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run_host(args: argparse.Namespace) -> int:
    manager = runtime(args)
    if args.execute:
        reconciled = manager.reconcile_bootstrap()
        if (
            reconciled.get("transportReady") is not True
            or reconciled.get("controlReady") is not True
        ):
            result = {
                "ok": False,
                "error": _bootstrap_error(reconciled),
                "bootstrap": reconciled,
            }
            print_json(result)
            return 1
    result = manager.automation_run_host(
        args.script,
        execute=args.execute,
        endpoint=daemon(args, manager).base,
    )
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_automation_run(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).run_automation(args.script)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_deploy(args: argparse.Namespace) -> int:
    result = runtime(args).deploy_input_helper(args.path, args.remote_path)
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_input_tap(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).tap(args.x, args.y)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_input_swipe(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).swipe(args.x1, args.y1, args.x2, args.y2, args.duration_ms)
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
        result = bootstrap_client(args).app_install(remote)
        result["upload"] = upload
        result["cleanup"] = manager.adb(["shell", "rm", "-f", remote])
        result["source"] = str(source.resolve())
    else:
        result = bootstrap_client(args).app_install(args.path)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_uninstall(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).app_uninstall(args.package)
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_app_launch(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).app_launch(args.component)
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
    result = bootstrap_client(args).hide_status()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_hide_apply(args: argparse.Namespace) -> int:
    policy = read_json_file(args.policy) if args.policy else None
    result = bootstrap_client(args).hide_apply(policy)
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
    result = bootstrap_client(args).ota_check()
    print_json(result)
    return 0 if result.get("ok", False) else 1


def cmd_ota_apply(args: argparse.Namespace) -> int:
    result = bootstrap_client(args).ota_apply(args.channel)
    print_json(result)
    return 0 if result.get("ok", False) else 1







def cmd_ebpf_build(args: argparse.Namespace) -> int:
    result = runtime(args).build_shared_protection()
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_ebpf_action(args: argparse.Namespace) -> int:
    manager = runtime(args)
    action = args.ebpf_action
    if action == "load":
        result = manager.maintain_shared_protection()
    elif action == "status":
        result = manager.shared_protection_status()
    elif action == "smoke":
        result = manager.smoke_shared_protection()
    else:
        result = manager.unload_shared_ebpf(
            maintenance=bool(getattr(args, "maintenance", False)),
        )
    print_json(result)
    return 0 if result.get("ok") else 1


def cmd_mcp_config(args: argparse.Namespace) -> int:
    print_json({
        "mcpServers": {
            "xenoid": {
                "command": "xenoid-mcp",
                "args": [],
                "env": {
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
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="top_command", required=True)

    s = sub.add_parser("install-runtime", help="install macOS runtime dependencies via Homebrew and start Colima")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_install_runtime)

    s = sub.add_parser("doctor", help="check installation, host dependencies, and the live runtime")
    s.add_argument("--full", action="store_true", help="also build artifacts and run exhaustive runtime smoke checks")
    s.add_argument("--require-runtime", action="store_true", help="fail when Android is not running and ready")
    s.add_argument("--out", help="also write the JSON report to this path")
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("up", help="converge the complete Xenoid production runtime")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--skip-build", action="store_true", help="validate and use existing artifact records without compiling")
    s.set_defaults(func=cmd_up)


    s = sub.add_parser("linux-binderfs", help="setup Linux binderfs devices for redroid")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_linux_binderfs)



    s = sub.add_parser("runtime-build-image", help="build custom redroid Docker image with Xenoid payloads")
    s.add_argument("--image", help="base redroid image")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_runtime_build_image)

    s = sub.add_parser("runtime-context", help="create custom redroid Docker build context with Xenoid payloads")
    s.add_argument("--image", help="base redroid image")
    s.set_defaults(func=cmd_runtime_context)

    s = sub.add_parser("make-rootfs", help="build/refresh ext4 rootfs+data loop images for the pivot entrypoint")
    s.set_defaults(func=cmd_make_rootfs)

    s = sub.add_parser("build", help="build daemon APK and native helpers")
    bsub = s.add_subparsers(required=True)
    for command, target in (
        ("daemon", "daemon"),
        ("keymint", "keymint"),
        ("input", "input"),
        ("hide", "hide"),
        ("profile", "profile"),
        ("netctl", "netctl"),
        ("gralloc", "gralloc"),
        ("hwcomposer", "hwcomposer"),
        ("ril", "ril"),
        ("radio-config", "radioConfig"),
    ):
        build_target = bsub.add_parser(command)
        build_target.set_defaults(
            artifact_target=target,
            artifact_force=target == "keymint",
            func=cmd_build_target,
        )
    build_all = bsub.add_parser("all")
    build_all.add_argument(
        "--force",
        action="store_true",
        help="rebuild every artifact and verify deterministic output",
    )
    build_all.set_defaults(func=cmd_build_all)

    s = sub.add_parser("verify-release", help="verify a Xenoid release bundle manifest and required artifacts")
    s.add_argument("archive")
    s.set_defaults(func=cmd_verify_release)

    s = sub.add_parser("package-release", help="package transferable Xenoid release bundle")
    s.add_argument("--version", default=__version__)
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
    s = sub.add_parser(
        "google-services",
        help="manage the optional pinned Google Mobile Services runtime",
    )
    google = s.add_subparsers(required=True)
    google_import = google.add_parser(
        "import-mindthegapps",
        help="verify and import the pinned official MindTheGapps source release",
    )
    google_import.add_argument("archive")
    google_import.add_argument("certificate")
    google_import.set_defaults(func=cmd_google_services_import)
    google_import_microg = google.add_parser(
        "import-microg",
        help="verify and import the pinned official microG GmsCore and GsfProxy APKs",
    )
    google_import_microg.add_argument("gmscore")
    google_import_microg.add_argument("gsfproxy")
    google_import_microg.set_defaults(func=cmd_google_services_import_microg)
    google_releases = google.add_parser(
        "releases",
        help="list the pinned Google services release registry",
    )
    google_releases.set_defaults(func=cmd_google_services_registry)
    google_status = google.add_parser(
        "status",
        help="show configured, bound, image, rootfs, and live runtime state",
    )
    google_status.add_argument("--require-runtime", action="store_true")
    google_status.set_defaults(func=cmd_google_services_status)
    google_enable = google.add_parser(
        "enable",
        help="enable the pinned release before first Android data creation",
    )
    google_enable.add_argument(
        "--release",
        default=MICROG_PLAY_RELEASE,
        choices=list(registered_releases(selectable_only=True)),
    )
    google_enable.set_defaults(func=cmd_google_services_enable)
    google_disable = google.add_parser(
        "disable",
        help="disable Google services before first Android data creation",
    )
    google_disable.set_defaults(func=cmd_google_services_disable)


    s = sub.add_parser("init", help="initialize the selected immutable instance")
    s.add_argument("--image")
    s.add_argument("--backend")
    s.add_argument("--config", help="operational config template to merge (e.g. examples/config-macos-colima.json)")
    s.add_argument("--from", dest="from_instance", help="clone operational config from an existing instance")
    s.add_argument(
        "--no-google-services",
        action="store_true",
        help="create this instance with Google services disabled",
    )
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

    s = sub.add_parser("stop", help="stop and retain the owned Android runtime container")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("logs", help="collect Docker/ADB runtime logs")
    s.add_argument("--out-dir")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("view", help="open scrcpy for the Xenoid Android target")
    s.set_defaults(func=cmd_view)

    s = sub.add_parser("status", help="observe runtime state and report the recommended convergence action")
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
    proxy_clear.add_argument(
        "--discard-unreadable-state",
        action="store_true",
        help=(
            "explicitly quarantine and preserve evidence for unreadable daemon "
            "state before a source-less cryptographic clear"
        ),
    )
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

    s = sub.add_parser("device", help="fingerprint and trusted-local keybox operations")
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
    keybox = dev.add_parser(
        "keybox",
        help="manage the trusted-local KeyMint keybox",
    )
    keybox_sub = keybox.add_subparsers(required=True)
    keybox_set = keybox_sub.add_parser("set")
    keybox_set.add_argument("file", metavar="FILE")
    keybox_set.set_defaults(func=cmd_device_keybox_set)
    keybox_status = keybox_sub.add_parser("status")
    keybox_status.set_defaults(func=cmd_device_keybox_status)
    keybox_clear = keybox_sub.add_parser("clear")
    keybox_clear.set_defaults(func=cmd_device_keybox_clear)
    rg = dev.add_parser(
        "regenerate",
        help=(
            "rotate Android/SIM/boot/filesystem/Bluetooth/device-name/hostname/"
            "DRM/GAID/GSF/SSAID identity in one soft reboot; offline Google "
            "identity disables FCM"
        ),
    )
    rg.add_argument("--dry-run", action="store_true", help="show the rotation plan without changing anything")
    rg.set_defaults(func=cmd_device_regenerate)

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


    s = sub.add_parser("ebpf", help="engine-host shared kmod/eBPF protection")
    eb = s.add_subparsers(required=True)
    eb_build = eb.add_parser(
        "build",
        help="build and validate shared protection replacements without loading",
    )
    eb_build.set_defaults(func=cmd_ebpf_build)
    eb_load = eb.add_parser("load", help="converge shared engine-host protection")
    eb_load.set_defaults(func=cmd_ebpf_action, ebpf_action="load")
    eb_status = eb.add_parser("status", help="show safe shared protection status")
    eb_status.set_defaults(func=cmd_ebpf_action, ebpf_action="status")
    eb_smoke = eb.add_parser(
        "smoke",
        help="run fresh target-engine host and Android UID protection proofs",
    )
    eb_smoke.set_defaults(func=cmd_ebpf_action, ebpf_action="smoke")
    eb_unload = eb.add_parser(
        "unload",
        help="maintenance-only eBPF unload with no active Xenoid runtimes",
    )
    eb_unload.add_argument(
        "--maintenance",
        action="store_true",
        help="acknowledge engine-host maintenance",
    )
    eb_unload.set_defaults(func=cmd_ebpf_action, ebpf_action="unload")


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


_READ_ONLY_INSTANCE_COMMANDS = frozenset({
    "cmd_doctor",
    "cmd_config_show",
    "cmd_google_services_status",
    "cmd_google_services_registry",
    "cmd_logs",
    "cmd_view",
    "cmd_status",
    "cmd_daemon_health",
    "cmd_location_list",
    "cmd_location_status",
    "cmd_automation_plan",
    "cmd_hide_overlay_status",
    "cmd_device_keybox_status",
    "cmd_mcp_config",
})


def _command_mutates_instance(args: argparse.Namespace) -> bool:
    """Fail closed: every resolved command is serialized unless proven read-only."""

    if not hasattr(args, "context"):
        return False
    handler_name = getattr(getattr(args, "func", None), "__name__", "")
    if handler_name in _READ_ONLY_INSTANCE_COMMANDS:
        return False
    if handler_name == "cmd_up" and bool(getattr(args, "dry_run", False)):
        return False
    if handler_name == "cmd_proxy_status" and not bool(getattr(args, "check", False)):
        return False
    if (
        handler_name == "cmd_ebpf_action"
        and getattr(args, "ebpf_action", None) in {"status", "smoke"}
    ):
        return False
    return True


def _refresh_instance_under_lock(args: argparse.Namespace) -> None:
    initial_id = args.context.instance_id
    context, config, lease = resolve_instance(
        args.instance_name,
        project_root=args.project_root,
    )
    expected_id = os.environ.get(EXPECTED_INSTANCE_ID_ENV) or initial_id
    if context.instance_id != initial_id or context.instance_id != expected_id:
        raise InstanceError(
            "instance_identity_mismatch",
            "instance identity changed during an operation",
        )
    args.context, args.config, args.lease = context, config, lease




def _reject_unrelated_regeneration_mutation(args: argparse.Namespace) -> Optional[dict[str, Any]]:
    handler = getattr(getattr(args, "func", None), "__name__", "")
    if handler in {"cmd_up", "cmd_device_regenerate"}:
        return None
    try:
        state = RegenerationJournal(args.context).load()
    except IdentityError as exc:
        # Legacy/malformed journals still produce the canonical v3 envelope
        # for unrelated mutators, not a bare identity error.
        return _regeneration_exception_result(args.context, exc)
    if state is None:
        return None
    return {
        "schema": "dev.xenoid.device-regenerate/v3",
        "ok": False,
        "error": "device_regeneration_pending",
        "phase": state["phase"],
        "transactionId": state["transactionId"],
    }


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
        expected_instance_id = os.environ.get(EXPECTED_INSTANCE_ID_ENV)
        if expected_instance_id:
            expected_context = (
                args.context
                if hasattr(args, "context")
                else resolve_instance(
                    args.instance_name,
                    project_root=args.project_root,
                )[0]
            )
            if expected_context.instance_id != expected_instance_id:
                raise InstanceError(
                    "instance_identity_mismatch",
                    "instance identity changed during an operation",
                )
        if _command_mutates_instance(args):
            with cli_operation_lock(args):
                _refresh_instance_under_lock(args)
                args._operation_lock_held = True
                blocked = _reject_unrelated_regeneration_mutation(args)
                if blocked is not None:
                    print_json(blocked)
                    return 1
                if not bool(getattr(args, "dry_run", False)):
                    runtime(args).migrate_legacy_token_state()
                return int(args.func(args))
        return int(args.func(args))
    except InstanceError as exc:
        print_json(exc.as_dict())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
