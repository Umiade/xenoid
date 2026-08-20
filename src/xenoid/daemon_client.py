from __future__ import annotations

import json
import re
import selectors
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal, Optional, Sequence, Union

from .config import InstanceContext, InstanceError, InstanceLease
from .util import bounded_timeout

# A source import can spend up to five sequential 600-second rootd phases on
# copy, publication, rollback/cleanup, and staging cleanup. Keep the host
# socket alive beyond that daemon-side bound so callers never clean staging
# while the daemon can still be consuming it.
CAMERA_MUTATION_TIMEOUT_SECONDS = 3605.0
PROXY_MAX_REQUEST_BYTES = 6 * 1024 * 1024 + 4096
PROXY_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
PROXY_MAX_SOURCE_BYTES = 1024 * 1024
PROXY_CHECK_TIMEOUT_SECONDS = 300.0
KEYBOX_STATUS_TIMEOUT_SECONDS = 30.0
KEYBOX_MUTATION_TIMEOUT_SECONDS = 180.0

DAEMON_TRANSPORT_SCHEMA = "dev.xenoid.daemon-transport/v1"
DAEMON_BOOTSTRAP_SCHEMA = "dev.xenoid.daemon-bootstrap/v1"
DAEMON_TOKEN_PATH = "/data/data/dev.xenoid.daemon/files/daemon.token"
DAEMON_APP_DATA_PATH = "/data/data/dev.xenoid.daemon"
BOOTSTRAP_POLL_TIMEOUT_SECONDS = 240.0
BOOTSTRAP_WORKER_TIMEOUT_MS = 230_000
_TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}")
_RUNTIME_EPOCH_PATTERN = re.compile(r"[0-9a-f]{64}")
_SAFE_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_BOOTSTRAP_STATES = frozenset({
    "transport_ready",
    "accepted",
    "reconciling",
    "ready",
    "degraded",
    "failed",
})
_BOOTSTRAP_COMPONENTS = frozenset({
    "root",
    "keybox",
    "proxy",
    "location",
    "camera",
})
_COMPONENT_STATES = frozenset({
    "pending",
    "reconciling",
    "ready",
    "unconfigured",
    "quarantined",
    "deferred",
    "failed",
    "timed_out",
    "cancelled",
})
KEYBOX_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_KEYBOX_STAGING_PATH = re.compile(
    r"/data/local/tmp/\.keybox-upload-[0-9a-f]{32}"
)
_KEYBOX_SHA256 = re.compile(r"[0-9a-f]{64}")
_KEYBOX_SAFE_ERRORS = frozenset({
    "attestation_self_test_failed",
    "clear_failed",
    "daemon_response_invalid",
    "daemon_unauthorized",
    "daemon_unreachable",
    "invalid_keybox",
    "invalid_request",
    "invalid_stage",
    "key_migration_unavailable",
    "keybox_request_failed",
    "method_not_allowed",
    "native_rejected",
    "native_unavailable",
    "response_too_large",
    "state_persist_failed",
    "unsupported_keybox",
})

def _keybox_failure(error: str) -> dict[str, Any]:
    safe = error if error in _KEYBOX_SAFE_ERRORS else "keybox_request_failed"
    return {"ok": False, "error": safe}


def _keybox_algorithms(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "rsa",
        "ecdsa",
        "rsaChainCount",
        "ecdsaChainCount",
    }:
        return None
    rsa = value.get("rsa")
    ecdsa = value.get("ecdsa")
    rsa_count = value.get("rsaChainCount")
    ecdsa_count = value.get("ecdsaChainCount")
    if (
        not isinstance(rsa, bool)
        or not isinstance(ecdsa, bool)
        or not isinstance(rsa_count, int)
        or isinstance(rsa_count, bool)
        or not isinstance(ecdsa_count, int)
        or isinstance(ecdsa_count, bool)
        or not 0 <= rsa_count <= 64
        or not 0 <= ecdsa_count <= 64
    ):
        return None
    return {
        "rsa": rsa,
        "ecdsa": ecdsa,
        "rsaChainCount": rsa_count,
        "ecdsaChainCount": ecdsa_count,
    }


def _keybox_public_response(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
        return _keybox_failure("daemon_response_invalid")
    if value["ok"] is not True:
        error = value.get("error")
        return _keybox_failure(error if isinstance(error, str) else "")

    algorithms = _keybox_algorithms(value.get("algorithms"))
    if (
        not isinstance(value.get("configured"), bool)
        or not isinstance(value.get("ready"), bool)
        or not isinstance(value.get("active"), bool)
        or algorithms is None
    ):
        return _keybox_failure("daemon_response_invalid")
    result: dict[str, Any] = {
        "ok": True,
        "configured": value["configured"],
        "ready": value["ready"],
        "active": value["active"],
        "algorithms": algorithms,
    }
    error = value.get("error")
    if isinstance(error, str) and error in _KEYBOX_SAFE_ERRORS:
        result["error"] = error
    return result

_PROXY_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PROXY_CAPABILITY_KEYS = (
    "v4DnsProxy",
    "v4TcpProxy",
    "v4UdpProxy",
    "v6DnsProxy",
    "v6TcpProxy",
    "v6UdpProxy",
)
_PROXY_PROBE_TIMEOUT_MS = 45_000


def _proxy_capabilities_match(value: Any, udp_allowed: Any) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != set(_PROXY_CAPABILITY_KEYS)
        or not isinstance(udp_allowed, bool)
        or any(not isinstance(value[key], bool) for key in _PROXY_CAPABILITY_KEYS)
    ):
        return False
    return (
        value["v4DnsProxy"]
        and value["v4TcpProxy"]
        and value["v6DnsProxy"]
        and value["v6TcpProxy"]
        and value["v4UdpProxy"] is udp_allowed
        and value["v6UdpProxy"] is udp_allowed
    )



def _proxy_failure(code: str, http_status: Optional[int] = None) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "code": code, "error": code}
    if http_status is not None:
        result["httpStatus"] = http_status
    return result


def _proxy_error_from_response(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("code", "errorCode", "stateError", "error"):
            candidate = value.get(key)
            if isinstance(candidate, str) and _PROXY_ERROR_CODE.fullmatch(candidate):
                return candidate
    return "proxy_request_failed"


def _proxy_counter(value: Any, *, positive: bool = False) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value < (1 << 63)
    )


def _validated_proxy_mutation(
    value: Any,
    *,
    enabled: Optional[bool] = None,
    configured: Optional[bool] = None,
    recovery: bool = False,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "ok",
            "generation",
            "checkId",
            "enabled",
            "configured",
            "quarantined",
        }
        or value.get("ok") is not True
        or not _proxy_counter(value.get("generation"))
        or not _proxy_counter(value.get("checkId"))
        or not isinstance(value.get("enabled"), bool)
        or not isinstance(value.get("configured"), bool)
        or not isinstance(value.get("quarantined"), bool)
        or (enabled is not None and value["enabled"] is not enabled)
        or (configured is not None and value["configured"] is not configured)
        or (recovery and value["quarantined"] is not True)
    ):
        return _proxy_failure("daemon_response_invalid")
    return value


def _validated_proxy_status(value: Any, instance_id: str) -> dict[str, Any]:
    expected = {
        "ok",
        "schemaVersion",
        "stateReadable",
        "stateError",
        "instanceId",
        "generation",
        "enabled",
        "configured",
        "sourceKind",
        "selectedNode",
        "udpAllowed",
        "allowInsecureHttp",
        "quarantined",
        "checkId",
        "runtimeEpoch",
        "report",
        "probe",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schemaVersion") != 2
        or not isinstance(value.get("stateReadable"), bool)
        or value.get("instanceId") not in (None, "", instance_id)
        or not _proxy_counter(value.get("checkId"))
        or not isinstance(value.get("runtimeEpoch"), str)
        or len(value["runtimeEpoch"]) > 128
    ):
        return _proxy_failure("daemon_response_invalid")
    if value["stateReadable"] is False:
        if (
            value.get("ok") is not False
            or not isinstance(value.get("stateError"), str)
            or _PROXY_ERROR_CODE.fullmatch(value["stateError"]) is None
            or value.get("generation") is not None
            or value.get("enabled") is not None
            or value.get("configured") is not None
            or value.get("sourceKind") is not None
            or value.get("selectedNode") is not None
            or value.get("udpAllowed") is not None
            or value.get("allowInsecureHttp") is not None
            or value.get("quarantined") is not True
            or value.get("report") is not None
            or value.get("probe") is not None
        ):
            return _proxy_failure("daemon_response_invalid")
        return value
    if (
        value.get("ok") is not True
        or value.get("stateError") is not None
        or not isinstance(value.get("instanceId"), str)
        or not _proxy_counter(value.get("generation"))
        or not isinstance(value.get("enabled"), bool)
        or not isinstance(value.get("configured"), bool)
        or not isinstance(value.get("udpAllowed"), bool)
        or not isinstance(value.get("allowInsecureHttp"), bool)
        or not isinstance(value.get("quarantined"), bool)
        or not isinstance(value.get("selectedNode"), str)
        or len(value["selectedNode"]) > 128
        or value.get("report") is not None
        and not isinstance(value.get("report"), dict)
        or value.get("probe") is not None
        and not isinstance(value.get("probe"), dict)
    ):
        return _proxy_failure("daemon_response_invalid")
    source_kind = value.get("sourceKind")
    if value["configured"]:
        if source_kind not in {"endpoint", "uri_list", "clash", "subscription"}:
            return _proxy_failure("daemon_response_invalid")
    elif (
        source_kind is not None
        or value["enabled"]
        or value["selectedNode"]
        or value["udpAllowed"]
        or value["allowInsecureHttp"]
    ):
        return _proxy_failure("daemon_response_invalid")
    return value


def _validated_proxy_export(value: Any, instance_id: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "ok",
            "schemaVersion",
            "instanceId",
            "generation",
            "enabled",
            "checkId",
            "source",
        }
        or value.get("ok") is not True
        or value.get("schemaVersion") != 2
        or value.get("instanceId") not in ("", instance_id)
        or not _proxy_counter(value.get("generation"))
        or not _proxy_counter(value.get("checkId"))
        or not isinstance(value.get("enabled"), bool)
    ):
        return _proxy_failure("daemon_response_invalid")
    source = value.get("source")
    if source is None:
        if value["enabled"]:
            return _proxy_failure("daemon_response_invalid")
        return value
    if (
        not isinstance(source, dict)
        or set(source)
        != {
            "kind",
            "value",
            "selectedNode",
            "udpAllowed",
            "allowInsecureHttp",
        }
        or source.get("kind")
        not in {"endpoint", "uri_list", "clash", "subscription"}
        or not isinstance(source.get("value"), str)
        or not isinstance(source.get("selectedNode"), str)
        or not isinstance(source.get("udpAllowed"), bool)
        or not isinstance(source.get("allowInsecureHttp"), bool)
    ):
        return _proxy_failure("daemon_response_invalid")
    try:
        if not source["value"] or len(source["value"].encode("utf-8")) > PROXY_MAX_SOURCE_BYTES:
            return _proxy_failure("daemon_response_invalid")
    except UnicodeError:
        return _proxy_failure("daemon_response_invalid")
    return value



def _bootstrap_failure(
    code: str,
    http_status: Optional[int] = None,
) -> dict[str, Any]:
    safe = code if _SAFE_CODE_PATTERN.fullmatch(code) else "daemon_response_invalid"
    result: dict[str, Any] = {"ok": False, "code": safe, "error": safe}
    if http_status is not None:
        result["httpStatus"] = http_status
    return result


def _bounded_nonnegative_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value < (1 << 63)
    )


def _valid_component(
    name: str,
    value: Any,
) -> bool:
    allowed: dict[str, frozenset[str]] = {
        "root": frozenset({"ok", "state", "errorCode"}),
        "keybox": frozenset({
            "ok",
            "state",
            "errorCode",
            "configured",
            "active",
            "algorithms",
        }),
        "proxy": frozenset({
            "ok",
            "state",
            "errorCode",
            "configured",
            "enabled",
            "generation",
            "quarantined",
        }),
        "location": frozenset({
            "ok",
            "state",
            "errorCode",
            "configured",
            "locationEpoch",
        }),
        "camera": frozenset({
            "ok",
            "state",
            "errorCode",
            "configured",
            "generation",
            "active",
            "publicationReady",
        }),
    }
    if (
        not isinstance(value, dict)
        or not {"ok", "state"}.issubset(value)
        or not set(value).issubset(allowed[name])
        or not isinstance(value.get("ok"), bool)
        or value.get("state") not in _COMPONENT_STATES
    ):
        return False
    error_code = value.get("errorCode")
    if error_code is not None and (
        not isinstance(error_code, str)
        or _SAFE_CODE_PATTERN.fullmatch(error_code) is None
    ):
        return False
    proxy_unreadable = (
        name == "proxy"
        and value["state"] == "failed"
        and error_code == "proxy_state_invalid"
    )
    if proxy_unreadable and (
        value["ok"] is not False
        or not {"configured", "enabled", "generation", "quarantined"}.issubset(value)
        or value["configured"] is not None
        or value["enabled"] is not None
        or value["generation"] is not None
        or value["quarantined"] is not True
    ):
        return False
    for key in (
        "configured",
        "active",
        "enabled",
        "quarantined",
        "publicationReady",
    ):
        if key in value and not (
            isinstance(value[key], bool)
            or (
                proxy_unreadable
                and key in {"configured", "enabled"}
                and value[key] is None
            )
        ):
            return False
    if "generation" in value and not (
        _bounded_nonnegative_integer(value["generation"])
        or (proxy_unreadable and value["generation"] is None)
    ):
        return False
    if "locationEpoch" in value and (
        not isinstance(value["locationEpoch"], str)
        or _RUNTIME_EPOCH_PATTERN.fullmatch(value["locationEpoch"]) is None
    ):
        return False
    if "algorithms" in value and _keybox_algorithms(value["algorithms"]) is None:
        return False
    return True


def _bootstrap_public_response(
    value: Any,
    context: InstanceContext,
) -> dict[str, Any]:
    required = {
        "ok",
        "schema",
        "state",
        "generation",
        "instanceId",
        "runtimeEpoch",
        "components",
    }
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | {"errorCode"})
        or value.get("schema") != DAEMON_BOOTSTRAP_SCHEMA
        or value.get("state") not in _BOOTSTRAP_STATES
        or not isinstance(value.get("ok"), bool)
        or value["ok"] is not (value["state"] == "ready")
        or not _bounded_nonnegative_integer(value.get("generation"))
    ):
        return _bootstrap_failure("daemon_response_invalid")
    instance_id = value.get("instanceId")
    runtime_epoch = value.get("runtimeEpoch")
    if not isinstance(instance_id, str) or not isinstance(runtime_epoch, str):
        return _bootstrap_failure("daemon_response_invalid")
    if value["generation"] == 0:
        if instance_id or runtime_epoch:
            return _bootstrap_failure("daemon_response_invalid")
    elif (
        instance_id != context.instance_id
        or _RUNTIME_EPOCH_PATTERN.fullmatch(runtime_epoch) is None
    ):
        return _bootstrap_failure("instance_identity_mismatch")
    error_code = value.get("errorCode")
    if error_code is not None and (
        not isinstance(error_code, str)
        or _SAFE_CODE_PATTERN.fullmatch(error_code) is None
    ):
        return _bootstrap_failure("daemon_response_invalid")
    components = value.get("components")
    if (
        not isinstance(components, dict)
        or set(components) != _BOOTSTRAP_COMPONENTS
        or any(not _valid_component(name, components[name]) for name in components)
    ):
        return _bootstrap_failure("daemon_response_invalid")
    return value

def wait_for_proxy_check(
    client: "DaemonClient",
    timeout: float = PROXY_CHECK_TIMEOUT_SECONDS,
    poll_interval: float = 0.25,
    *,
    expected_check_id: Optional[int] = None,
    expected_generation: Optional[int] = None,
    expected_runtime_epoch: Optional[str] = None,
) -> dict[str, Any]:
    """Wait for one exact generation/check without accepting stale evidence."""
    baseline = client.proxy_status()
    if not baseline.get("ok"):
        return baseline
    if baseline.get("enabled") is not True:
        return _proxy_failure("proxy_disabled")

    if expected_check_id is None:
        if expected_generation is not None or expected_runtime_epoch is not None:
            return _proxy_failure("daemon_response_invalid")
        check = client.proxy_check()
        if not check.get("ok"):
            return check
        check_id = check.get("checkId")
        generation = check.get("generation")
        runtime_epoch = baseline.get("runtimeEpoch")
        baseline = client.proxy_status()
        if not baseline.get("ok"):
            return baseline
    else:
        check_id = expected_check_id
        generation = expected_generation
        runtime_epoch = expected_runtime_epoch

    if (
        not isinstance(check_id, int)
        or isinstance(check_id, bool)
        or check_id < 1
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 0
        or not isinstance(runtime_epoch, str)
        or not runtime_epoch
    ):
        return _proxy_failure("daemon_response_invalid")
    if (
        baseline.get("generation") != generation
        or baseline.get("runtimeEpoch") != runtime_epoch
        or baseline.get("checkId") != check_id
    ):
        return _proxy_failure("agent_stale")

    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        status = client.proxy_status()
        if not status.get("ok"):
            return status
        if status.get("enabled") is not True:
            return _proxy_failure("proxy_disabled")
        if status.get("runtimeEpoch") != runtime_epoch:
            return _proxy_failure("runtime_epoch_mismatch")
        if status.get("generation") != generation or status.get("checkId") != check_id:
            return _proxy_failure("agent_stale")

        probe = status.get("probe")
        report = status.get("report")
        matching_report = (
            isinstance(report, dict)
            and report.get("checkId") == check_id
            and report.get("generation") == generation
        )
        if matching_report:
            report_error = report.get("errorCode")
            if isinstance(report_error, str) and report_error:
                return _proxy_failure(
                    report_error if _PROXY_ERROR_CODE.fullmatch(report_error)
                    else "data_plane_unverified"
                )

        matching_probe = isinstance(probe, dict) and probe.get("checkId") == check_id
        if matching_probe:
            probe_error = probe.get("errorCode")
            if isinstance(probe_error, str) and probe_error:
                return _proxy_failure(
                    probe_error if _PROXY_ERROR_CODE.fullmatch(probe_error)
                    else "data_plane_unverified"
                )
            elapsed_ms = probe.get("elapsedMs")
            if (
                not isinstance(elapsed_ms, int)
                or isinstance(elapsed_ms, bool)
                or not 0 <= elapsed_ms <= _PROXY_PROBE_TIMEOUT_MS
                or not _proxy_capabilities_match(
                    probe.get("capabilities"), status.get("udpAllowed")
                )
            ):
                return _proxy_failure("data_plane_unverified")

        core_ready = (
            matching_report
            and matching_probe
            and report.get("phase") == "active"
            and report.get("structuralApplied") is True
            and report.get("dataPlaneVerified") is True
            and _proxy_capabilities_match(
                report.get("capabilities"), status.get("udpAllowed")
            )
        )
        if core_ready:
            result = dict(status)
            result["checkCompleted"] = True
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result = _proxy_failure("proxy_check_timeout")
            result["checkId"] = check_id
            return result
        time.sleep(min(max(0.01, poll_interval), remaining))


class DaemonClient:
    def __init__(
        self,
        context: InstanceContext,
        lease: InstanceLease,
        docker_argv: Sequence[str],
        timeout: float = 10.0,
    ):
        if (
            lease.instance_id != context.instance_id
            or lease.instance_name != context.instance_name
            or lease.resource_tag != context.resource_tag
        ):
            raise InstanceError(
                "instance_identity_mismatch",
                "daemon client instance identity mismatch",
            )
        if not docker_argv or isinstance(docker_argv, (str, bytes)):
            raise ValueError("docker argv is required")
        self.base = f"http://127.0.0.1:{lease.host_daemon_port}"
        self.timeout = timeout
        self._context = context
        self._lease = lease
        self._docker_argv = tuple(str(part) for part in docker_argv)
        self._token: Optional[bytearray] = None
        self._token_container_id: Optional[str] = None

    def __del__(self) -> None:
        self._clear_token()

    def _clear_token(self) -> None:
        token = getattr(self, "_token", None)
        if token is not None:
            for index in range(len(token)):
                token[index] = 0
        self._token = None
        self._token_container_id = None

    def _engine_metadata(
        self,
        args: Sequence[str],
        *,
        timeout: float = 5.0,
        limit: int = 512,
    ) -> Optional[str]:
        """Capture only bounded, non-secret engine metadata."""
        process: Optional[subprocess.Popen[bytes]] = None
        try:
            process = subprocess.Popen(
                [*self._docker_argv, *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=False,
                close_fds=True,
            )
            output, _ = process.communicate(timeout=bounded_timeout(timeout))
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    pass
            return None
        if process.returncode != 0 or len(output) > limit:
            return None
        try:
            return output.decode("ascii").strip()
        except UnicodeError:
            return None

    def _container_id(self, timeout: float = 5.0) -> Optional[str]:
        value = self._engine_metadata(
            (
                "inspect",
                "--format",
                "{{.Id}}",
                self._lease.container_name,
            ),
            timeout=timeout,
        )
        if value is None or _RUNTIME_EPOCH_PATTERN.fullmatch(value) is None:
            return None
        return value

    def _token_metadata(
        self,
        container_id: str,
        path: str,
        *,
        timeout: float = 5.0,
    ) -> Optional[tuple[int, int, int, int, int, int]]:
        value = self._engine_metadata(
            (
                "exec",
                container_id,
                "stat",
                "-c",
                "%d:%i:%u:%f:%h:%s",
                path,
            ),
            timeout=timeout,
        )
        if value is None:
            return None
        fields = value.split(":")
        if len(fields) != 6:
            return None
        try:
            device, inode, uid, raw_mode, links, size = (
                int(fields[0]),
                int(fields[1]),
                int(fields[2]),
                int(fields[3], 16),
                int(fields[4]),
                int(fields[5]),
            )
        except ValueError:
            return None
        return device, inode, uid, raw_mode, links, size

    def _read_token_secret(
        self,
        container_id: str,
        *,
        timeout: float = 5.0,
    ) -> Optional[bytearray]:
        """Read only the fixed private token path into a bounded secret buffer."""
        process: Optional[subprocess.Popen[bytes]] = None
        selector: Optional[selectors.BaseSelector] = None
        secret = bytearray(32)
        extra = bytearray(1)
        valid = False
        try:
            process = subprocess.Popen(
                [
                    *self._docker_argv,
                    "exec",
                    container_id,
                    "cat",
                    DAEMON_TOKEN_PATH,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                bufsize=0,
            )
            if process.stdout is None:
                return None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + bounded_timeout(timeout)
            offset = 0
            while offset < len(secret):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(process.args, timeout)
                count = process.stdout.readinto(memoryview(secret)[offset:])
                if count is None:
                    continue
                if count == 0:
                    break
                offset += count
            eof = False
            if offset == len(secret):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(process.args, timeout)
                count = process.stdout.readinto(extra)
                eof = count == 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            process.wait(timeout=remaining)
            valid = (
                process.returncode == 0
                and offset == len(secret)
                and eof
                and re.fullmatch(rb"[0-9a-f]{32}", secret) is not None
            )
            return secret if valid else None
        except (OSError, subprocess.SubprocessError):
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.SubprocessError):
                    pass
            return None
        finally:
            if selector is not None:
                selector.close()
            if process is not None and process.stdout is not None:
                process.stdout.close()
            extra[0] = 0
            if not valid:
                for index in range(len(secret)):
                    secret[index] = 0

    def read_private_token(
        self,
        force: bool = False,
        timeout: float = 5.0,
    ) -> Optional[str]:
        """Read and cache the app-private token only for the observed container."""
        deadline = time.monotonic() + max(0.0, timeout)

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        initial_timeout = remaining()
        if initial_timeout <= 0:
            return None
        container_id = self._container_id(initial_timeout)
        if container_id is None:
            self._clear_token()
            return None
        if (
            not force
            and self._token is not None
            and self._token_container_id == container_id
        ):
            return self._token.decode("ascii")
        self._clear_token()

        metadata_timeout = remaining()
        if metadata_timeout <= 0:
            return None
        app_metadata = self._token_metadata(
            container_id,
            DAEMON_APP_DATA_PATH,
            timeout=metadata_timeout,
        )
        metadata_timeout = remaining()
        if metadata_timeout <= 0:
            return None
        before = self._token_metadata(
            container_id,
            DAEMON_TOKEN_PATH,
            timeout=metadata_timeout,
        )
        if app_metadata is None or before is None:
            return None
        _, _, app_uid, app_mode, _, _ = app_metadata
        _, _, token_uid, token_mode, token_links, token_size = before
        if (
            not stat.S_ISDIR(app_mode)
            or not stat.S_ISREG(token_mode)
            or token_uid != app_uid
            or stat.S_IMODE(token_mode) != 0o600
            or token_links != 1
            or token_size != 32
        ):
            return None

        secret_timeout = remaining()
        if secret_timeout <= 0:
            return None
        secret = self._read_token_secret(
            container_id,
            timeout=secret_timeout,
        )
        metadata_timeout = remaining()
        after = (
            self._token_metadata(
                container_id,
                DAEMON_TOKEN_PATH,
                timeout=metadata_timeout,
            )
            if metadata_timeout > 0
            else None
        )
        metadata_timeout = remaining()
        app_after = (
            self._token_metadata(
                container_id,
                DAEMON_APP_DATA_PATH,
                timeout=metadata_timeout,
            )
            if metadata_timeout > 0
            else None
        )
        identity_timeout = remaining()
        if (
            secret is None
            or after != before
            or app_after != app_metadata
            or identity_timeout <= 0
            or self._container_id(identity_timeout) != container_id
        ):
            if secret is not None:
                for index in range(len(secret)):
                    secret[index] = 0
            return None
        self._token = secret
        self._token_container_id = container_id
        return secret.decode("ascii")

    def _get_token(
        self,
        force: bool = False,
        timeout: float = 5.0,
    ) -> Optional[str]:
        return self.read_private_token(force=force, timeout=timeout)

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        request_timeout = self.timeout if timeout is None else timeout
        deadline = time.monotonic() + max(0.0, request_timeout)
        for attempt in range(2):
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _proxy_failure("daemon_unreachable")
            token = self._get_token(force=attempt > 0, timeout=remaining)
            if token:
                headers["X-Xenoid-Token"] = token
            request = urllib.request.Request(
                self.base + path,
                data=data,
                method=method,
                headers=headers,
            )
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return _proxy_failure("daemon_unreachable")
                with urllib.request.urlopen(
                    request,
                    timeout=bounded_timeout(remaining),
                ) as response:
                    raw = response.read().decode()
                    result = json.loads(raw) if raw else {"ok": True}
                    if response.status == 401 and attempt == 0:
                        self._clear_token()
                        continue
                    return result
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._clear_token()
                    exc.close()
                    continue
                if exc.code == 401:
                    exc.close()
                    return _proxy_failure("daemon_unauthorized", 401)
                raw = exc.read(PROXY_MAX_RESPONSE_BYTES + 1)
                if len(raw) > PROXY_MAX_RESPONSE_BYTES:
                    return _proxy_failure("response_too_large", exc.code)
                try:
                    result = json.loads(raw.decode("utf-8")) if raw else None
                except (UnicodeError, json.JSONDecodeError):
                    result = None
                return _proxy_failure(
                    _proxy_error_from_response(result),
                    exc.code,
                )
            except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                return _proxy_failure("daemon_unreachable")
        return _proxy_failure("daemon_unauthorized")


    def _public_json_request(
        self,
        method: str,
        path: str,
        *,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            self.base + path,
            method=method,
            headers={"Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=bounded_timeout(
                    self.timeout if timeout is None else timeout
                ),
            ) as response:
                raw = response.read(4097)
                if len(raw) > 4096:
                    return _bootstrap_failure("response_too_large")
                value = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            return _bootstrap_failure("daemon_unreachable", status)
        except (
            urllib.error.URLError,
            TimeoutError,
            ValueError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return _bootstrap_failure("daemon_unreachable")
        if not isinstance(value, dict):
            return _bootstrap_failure("daemon_response_invalid")
        return value

    def transport(self, timeout: Optional[float] = None) -> dict[str, Any]:
        value = self._public_json_request(
            "GET",
            "/bootstrap/transport",
            timeout=timeout,
        )
        expected = {
            "ok": True,
            "schema": DAEMON_TRANSPORT_SCHEMA,
            "service": "xenoid-daemon",
            "transportReady": True,
        }
        if value != expected:
            return _bootstrap_failure(
                "daemon_transport_unavailable"
                if value.get("code") == "daemon_unreachable"
                else "daemon_response_invalid",
                value.get("httpStatus")
                if isinstance(value.get("httpStatus"), int)
                else None,
            )
        return value

    def _validated_bootstrap_result(
        self,
        value: Any,
    ) -> dict[str, Any]:
        if isinstance(value, dict) and value.get("schema") == DAEMON_BOOTSTRAP_SCHEMA:
            return _bootstrap_public_response(value, self._context)
        if isinstance(value, dict):
            status = value.get("httpStatus")
            if status == 401:
                return _bootstrap_failure("daemon_unauthorized", 401)
            code = value.get("code")
            if isinstance(code, str) and _SAFE_CODE_PATTERN.fullmatch(code):
                return _bootstrap_failure(
                    code,
                    status if isinstance(status, int) else None,
                )
        return _bootstrap_failure("daemon_response_invalid")

    def bootstrap_reconcile(
        self,
        instance_id: str,
        runtime_epoch: str,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if (
            instance_id != self._context.instance_id
            or _RUNTIME_EPOCH_PATTERN.fullmatch(runtime_epoch) is None
            or not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or not 1000 <= timeout_ms <= BOOTSTRAP_WORKER_TIMEOUT_MS
        ):
            return _bootstrap_failure("invalid_request")
        value = self.request(
            "POST",
            "/bootstrap/reconcile",
            {
                "schema": DAEMON_BOOTSTRAP_SCHEMA,
                "instanceId": instance_id,
                "runtimeEpoch": runtime_epoch,
                "timeoutMs": timeout_ms,
            },
            timeout=min(self.timeout, max(1.0, timeout_ms / 1000.0)),
        )
        return self._validated_bootstrap_result(value)

    def bootstrap_status(
        self,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        return self._validated_bootstrap_result(
            self.request("GET", "/bootstrap/status", timeout=timeout)
        )

    def bootstrap_cancel(
        self,
        generation: int,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation <= 0
        ):
            return _bootstrap_failure("invalid_request")
        return self._validated_bootstrap_result(
            self.request(
                "POST",
                "/bootstrap/cancel",
                {
                    "schema": DAEMON_BOOTSTRAP_SCHEMA,
                    "generation": generation,
                },
                timeout=timeout,
            )
        )
    def _proxy_request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        body: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        try:
            data = (
                None
                if body is None
                else json.dumps(
                    body,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        except (TypeError, ValueError, UnicodeError):
            return _proxy_failure("invalid_request_schema")
        if data is not None and len(data) > PROXY_MAX_REQUEST_BYTES:
            return _proxy_failure("request_too_large")
        request_deadline = time.monotonic() + max(
            0.0,
            self.timeout if timeout is None else timeout,
        )

        for attempt in range(2):
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            remaining = request_deadline - time.monotonic()
            if remaining <= 0:
                return _proxy_failure("daemon_unreachable")
            token = self._get_token(force=attempt > 0, timeout=remaining)
            if token:
                headers["X-Xenoid-Token"] = token
            request = urllib.request.Request(
                self.base + path,
                data=data,
                method=method,
                headers=headers,
            )
            try:
                remaining = request_deadline - time.monotonic()
                if remaining <= 0:
                    return _proxy_failure("daemon_unreachable")
                with urllib.request.urlopen(
                    request,
                    timeout=bounded_timeout(remaining),
                ) as response:
                    raw = response.read(PROXY_MAX_RESPONSE_BYTES + 1)
                    if len(raw) > PROXY_MAX_RESPONSE_BYTES:
                        return _proxy_failure("response_too_large")
                    try:
                        parsed = json.loads(raw.decode("utf-8")) if raw else {"ok": True}
                    except (UnicodeError, json.JSONDecodeError):
                        return _proxy_failure("daemon_response_invalid")
                    if not isinstance(parsed, dict):
                        return _proxy_failure("daemon_response_invalid")
                    if (
                        parsed.get("ok") is not True
                        and parsed.get("error") == "not found"
                        and parsed.get("path") == path
                    ):
                        return _proxy_failure("proxy_api_unavailable", 404)
                    if path == "/proxy/status" and parsed.get("stateReadable") is False:
                        return parsed
                    if parsed.get("ok") is not True:
                        return _proxy_failure(_proxy_error_from_response(parsed))
                    return parsed
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._clear_token()
                    exc.close()
                    continue
                if exc.code == 401:
                    exc.close()
                    return _proxy_failure("daemon_unauthorized", 401)
                try:
                    raw = exc.read(PROXY_MAX_RESPONSE_BYTES + 1)
                finally:
                    exc.close()
                if len(raw) > PROXY_MAX_RESPONSE_BYTES:
                    return _proxy_failure("response_too_large", exc.code)
                try:
                    parsed = json.loads(raw.decode("utf-8")) if raw else None
                except (UnicodeError, json.JSONDecodeError):
                    parsed = None
                return _proxy_failure(
                    _proxy_error_from_response(parsed),
                    exc.code,
                )
            except (urllib.error.URLError, TimeoutError, ValueError, OSError):
                return _proxy_failure("daemon_unreachable")
        return _proxy_failure("daemon_unauthorized")

    def proxy_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        result = self._proxy_request("GET", "/proxy/status", timeout=timeout)
        if result.get("ok") is not True and "stateReadable" not in result:
            return result
        response_instance = result.get("instanceId")
        if (
            isinstance(response_instance, str)
            and response_instance not in ("", self._context.instance_id)
        ):
            return _proxy_failure("instance_identity_mismatch")
        return _validated_proxy_status(result, self._context.instance_id)

    def proxy_source(
        self,
        kind: Literal["endpoint", "uri_list", "clash", "subscription"],
        value: str,
        enable: bool,
        selected_node: str = "",
        udp_allowed: bool = True,
        allow_insecure_http: bool = False,
    ) -> dict[str, Any]:
        if (
            kind not in ("endpoint", "uri_list", "clash", "subscription")
            or not isinstance(value, str)
            or not isinstance(selected_node, str)
            or len(selected_node) > 128
            or not isinstance(enable, bool)
            or not isinstance(udp_allowed, bool)
            or not isinstance(allow_insecure_http, bool)
        ):
            return _proxy_failure("invalid_request_schema")
        try:
            source_size = len(value.encode("utf-8"))
        except UnicodeError:
            return _proxy_failure("source_invalid")
        if not 0 < source_size <= PROXY_MAX_SOURCE_BYTES:
            return _proxy_failure(
                "source_too_large"
                if source_size > PROXY_MAX_SOURCE_BYTES
                else "source_invalid"
            )
        result = self._proxy_request(
            "POST",
            "/proxy/source",
            {
                "kind": kind,
                "value": value,
                "enable": enable,
                "selectedNode": selected_node,
                "udpAllowed": udp_allowed,
                "allowInsecureHttp": allow_insecure_http,
            },
        )
        if result.get("ok") is not True:
            return result
        return _validated_proxy_mutation(
            result,
            enabled=enable,
            configured=True,
        )

    def proxy_enabled(self, enabled: bool) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            return _proxy_failure("invalid_request_schema")
        result = self._proxy_request(
            "POST",
            "/proxy/enabled",
            {"enabled": enabled},
        )
        if result.get("ok") is not True:
            return result
        return _validated_proxy_mutation(result, enabled=enabled)

    def proxy_select(self, name: str) -> dict[str, Any]:
        if not isinstance(name, str) or not name or len(name) > 128 or "\0" in name:
            return _proxy_failure("invalid_request_schema")
        result = self._proxy_request("POST", "/proxy/select", {"name": name})
        if result.get("ok") is not True:
            return result
        return _validated_proxy_mutation(result, configured=True)

    def proxy_clear(self, discard_unreadable_state: bool = False) -> dict[str, Any]:
        if not isinstance(discard_unreadable_state, bool):
            return _proxy_failure("invalid_request_schema")
        result = self._proxy_request(
            "POST",
            "/proxy/clear",
            {"discardUnreadableState": discard_unreadable_state},
        )
        if result.get("ok") is not True:
            return result
        return _validated_proxy_mutation(
            result,
            enabled=False,
            configured=False,
            recovery=discard_unreadable_state,
        )

    def proxy_check(self) -> dict[str, Any]:
        result = self._proxy_request("POST", "/proxy/check", {})
        if result.get("ok") is not True:
            return result
        if (
            set(result) != {"ok", "generation", "checkId"}
            or not _proxy_counter(result.get("generation"))
            or not _proxy_counter(result.get("checkId"), positive=True)
        ):
            return _proxy_failure("daemon_response_invalid")
        return result

    def proxy_export(self) -> dict[str, Any]:
        result = self._proxy_request("GET", "/proxy/export")
        if result.get("ok") is not True:
            return result
        response_instance = result.get("instanceId")
        if (
            isinstance(response_instance, str)
            and response_instance not in ("", self._context.instance_id)
        ):
            return _proxy_failure("instance_identity_mismatch")
        return _validated_proxy_export(result, self._context.instance_id)

    def proxy_agent_bootstrap(
        self,
        instance_id: str,
        runtime_epoch: str,
    ) -> dict[str, Any]:
        if (
            instance_id != self._context.instance_id
            or not isinstance(runtime_epoch, str)
            or not runtime_epoch
        ):
            return _proxy_failure("instance_identity_mismatch")
        return self._proxy_request(
            "POST",
            "/proxy/agent-bootstrap",
            {
                "instanceId": instance_id,
                "runtimeEpoch": runtime_epoch,
            },
        )

    def health(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("GET", "/health", timeout=timeout)

    def location_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("GET", "/location/status", timeout=timeout)

    def location_stage(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", "/location/stage", request, timeout=120)

    def location_verify(self, profile_digest: str, runtime_epoch: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/location/verify",
            {"profileDigest": profile_digest, "runtimeEpoch": runtime_epoch},
            timeout=150,
        )

    def keybox_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return _keybox_public_response(
            self.request(
                "GET",
                "/keybox/status",
                timeout=(
                    KEYBOX_STATUS_TIMEOUT_SECONDS
                    if timeout is None
                    else timeout
                ),
            )
        )

    def keybox_source(
        self,
        staging_path: str,
        size: int,
        sha256: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(staging_path, str)
            or _KEYBOX_STAGING_PATH.fullmatch(staging_path) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= KEYBOX_MAX_SOURCE_BYTES
            or not isinstance(sha256, str)
            or _KEYBOX_SHA256.fullmatch(sha256) is None
        ):
            return _keybox_failure("invalid_request")
        return _keybox_public_response(
            self.request(
                "POST",
                "/keybox/source",
                {
                    "stagingPath": staging_path,
                    "size": size,
                    "sha256": sha256,
                },
                timeout=KEYBOX_MUTATION_TIMEOUT_SECONDS,
            )
        )

    def keybox_clear(self) -> dict[str, Any]:
        return _keybox_public_response(
            self.request(
                "POST",
                "/keybox/clear",
                {},
                timeout=KEYBOX_MUTATION_TIMEOUT_SECONDS,
            )
        )

    def camera_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request(
            "GET",
            "/camera/status",
            timeout=(
                CAMERA_MUTATION_TIMEOUT_SECONDS
                if timeout is None
                else timeout
            ),
        )

    def camera_source(self, kind: str, staging_path: str, size: int, sha256: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/source",
            {
                "kind": kind,
                "stagingPath": staging_path,
                "size": size,
                "sha256": sha256,
            },
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_settings(self, mode: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/settings",
            {"mode": mode},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_clear(self, kind: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/clear",
            {"kind": kind},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_apply(self) -> dict[str, Any]:
        return self.request(
            "POST",
            "/camera/apply",
            {},
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
        )

    def camera_self_test_start(self, run_id: str) -> dict[str, Any]:
        return self.request("POST", "/camera/self-test/start", {"runId": run_id})

    def camera_self_test_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("GET", "/camera/self-test/status", timeout=timeout)

    def root_status(self, timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("GET", "/root/status", timeout=timeout)

    def root_exec(self, command: str) -> dict[str, Any]:
        return self.request("POST", "/root/exec", {"command": command})

    def frida_start(self, port: int = 27042) -> dict[str, Any]:
        return self.request("POST", "/frida/start", {"port": port}, timeout=90)

    def frida_stop(self) -> dict[str, Any]:
        return self.request("POST", "/frida/stop", timeout=30)

    def frida_status(self) -> dict[str, Any]:
        return self.request("GET", "/frida/status")

    def profile_helper_status(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/status")

    def profile_helper_env(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/env")

    def profile_helper_dump(self) -> dict[str, Any]:
        return self.request("GET", "/profile/helper/dump")

    def collect_fingerprint(self) -> dict[str, Any]:
        return self.request("GET", "/fingerprint/collect")

    def apply_fingerprint(self, profile: dict[str, Any], regenerate_unique: bool = True) -> dict[str, Any]:
        # Full apply fans out to dozens of rootd exec calls (props, overlay re-mount,
        # ssaid, netctl) — far beyond the 10s default. Give it the same headroom as ota_apply.
        return self.request("POST", "/fingerprint/apply", {"profile": profile, "regenerateUnique": regenerate_unique}, timeout=120)

    def set_fingerprint_field(self, field: str, value: Any) -> dict[str, Any]:
        return self.request("POST", "/fingerprint/set", {"field": field, "value": value}, timeout=30)

    def run_automation(self, script_path: Union[str, Path]) -> dict[str, Any]:
        script = Path(script_path).read_text()
        return self.request("POST", "/automation/run", {"language": "js", "script": script, "name": Path(script_path).name})

    def tap(self, x: int, y: int) -> dict[str, Any]:
        return self.request("POST", "/input/tap", {"x": x, "y": y})

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, Any]:
        return self.request("POST", "/input/swipe", {"x1": x1, "y1": y1, "x2": x2, "y2": y2, "durationMs": duration_ms})

    def app_install(self, path: str) -> dict[str, Any]:
        return self.request("POST", "/app/install", {"path": path}, timeout=120)

    def app_uninstall(self, package: str) -> dict[str, Any]:
        return self.request("POST", "/app/uninstall", {"package": package})

    def app_launch(self, component: str) -> dict[str, Any]:
        return self.request("POST", "/app/launch", {"component": component})

    def hide_status(self) -> dict[str, Any]:
        return self.request("GET", "/hide/status")

    def hide_apply(self, policy: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        # hide apply re-runs the overlay helper + prop-area as root; allow for slow mounts.
        return self.request("POST", "/hide/apply", {"policy": policy or {}}, timeout=90)

    def ota_check(self) -> dict[str, Any]:
        return self.request("GET", "/ota/check")

    def ota_apply(self, channel: str = "stable") -> dict[str, Any]:
        return self.request("POST", "/ota/apply", {"channel": channel}, timeout=120)
