from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal, Optional, Sequence, Union

from .config import InstanceContext, InstanceError, InstanceLease

# A source import can spend up to five sequential 600-second rootd phases on
# copy, publication, rollback/cleanup, and staging cleanup. Keep the host
# socket alive beyond that daemon-side bound so callers never clean staging
# while the daemon can still be consuming it.
CAMERA_MUTATION_TIMEOUT_SECONDS = 3605.0
PROXY_MAX_REQUEST_BYTES = 6 * 1024 * 1024 + 4096
PROXY_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
PROXY_MAX_SOURCE_BYTES = 1024 * 1024
PROXY_CHECK_TIMEOUT_SECONDS = 120.0
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
        for key in ("code", "error"):
            candidate = value.get(key)
            if isinstance(candidate, str) and _PROXY_ERROR_CODE.fullmatch(candidate):
                return candidate
    return "proxy_request_failed"


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
        if (
            status.get("generation") != generation
            or status.get("checkId") != check_id
        ):
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
                    report_error
                    if _PROXY_ERROR_CODE.fullmatch(report_error)
                    else "data_plane_unverified"
                )

        matching_probe = isinstance(probe, dict) and probe.get("checkId") == check_id
        if matching_probe:
            probe_error = probe.get("errorCode")
            if isinstance(probe_error, str) and probe_error:
                return _proxy_failure(
                    probe_error
                    if _PROXY_ERROR_CODE.fullmatch(probe_error)
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

        if (
            matching_report
            and matching_probe
            and report.get("phase") == "active"
            and report.get("structuralApplied") is True
            and report.get("dataPlaneVerified") is True
            and _proxy_capabilities_match(
                report.get("capabilities"), status.get("udpAllowed")
            )
        ):
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
        self._token_cache = context.state_root / "daemon.token"
        self._token: Optional[str] = None

    def _get_token(self, force: bool = False) -> Optional[str]:
        """Read the selected instance token from device and cache it mode 0600."""
        if self._token is not None and not force:
            return self._token
        if not force:
            try:
                if self._token_cache.is_file():
                    self._token = self._token_cache.read_text().strip() or None
                    if self._token:
                        self._token_cache.chmod(0o600)
                        return self._token
            except OSError:
                pass
        try:
            result = subprocess.run(
                [
                    *self._docker_argv,
                    "exec",
                    self._lease.container_name,
                    "cat",
                    "/data/data/dev.xenoid.daemon/files/daemon.token",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            token = result.stdout.strip()
            if result.returncode == 0 and token:
                self._token = token
                self._token_cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                self._token_cache.write_text(token + "\n")
                self._token_cache.chmod(0o600)
                return self._token
        except (OSError, subprocess.SubprocessError):
            pass
        self._token = None
        return None

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        for attempt in range(2):
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            token = self._get_token(force=attempt > 0)
            if token:
                headers["X-Xenoid-Token"] = token
            request = urllib.request.Request(
                self.base + path,
                data=data,
                method=method,
                headers=headers,
            )
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.timeout if timeout is None else timeout,
                ) as response:
                    raw = response.read().decode()
                    result = json.loads(raw) if raw else {"ok": True}
                    if response.status == 401 and attempt == 0:
                        self._token = None
                        continue
                    return result
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._token = None
                    exc.close()
                    continue
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

        for attempt in range(2):
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            token = self._get_token(force=attempt > 0)
            if token:
                headers["X-Xenoid-Token"] = token
            request = urllib.request.Request(
                self.base + path,
                data=data,
                method=method,
                headers=headers,
            )
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.timeout if timeout is None else timeout,
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
                    if parsed.get("ok") is not True:
                        return _proxy_failure(_proxy_error_from_response(parsed))
                    return parsed
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._token = None
                    exc.close()
                    continue
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

    def proxy_status(self) -> dict[str, Any]:
        result = self._proxy_request("GET", "/proxy/status")
        if result.get("ok"):
            instance_id = result.get("instanceId")
            if not isinstance(instance_id, str):
                return _proxy_failure("daemon_response_invalid")
            if instance_id and instance_id != self._context.instance_id:
                return _proxy_failure("instance_identity_mismatch")
        return result

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
            or not isinstance(enable, bool)
            or not isinstance(udp_allowed, bool)
            or not isinstance(allow_insecure_http, bool)
        ):
            return _proxy_failure("invalid_request_schema")
        try:
            source_size = len(value.encode("utf-8"))
        except UnicodeError:
            return _proxy_failure("source_invalid")
        if source_size > PROXY_MAX_SOURCE_BYTES:
            return _proxy_failure("source_too_large")
        return self._proxy_request(
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

    def proxy_enabled(self, enabled: bool) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            return _proxy_failure("invalid_request_schema")
        return self._proxy_request(
            "POST",
            "/proxy/enabled",
            {"enabled": enabled},
        )

    def proxy_select(self, name: str) -> dict[str, Any]:
        if not isinstance(name, str):
            return _proxy_failure("invalid_request_schema")
        return self._proxy_request("POST", "/proxy/select", {"name": name})

    def proxy_clear(self) -> dict[str, Any]:
        return self._proxy_request("POST", "/proxy/clear", {})

    def proxy_check(self) -> dict[str, Any]:
        return self._proxy_request("POST", "/proxy/check", {})

    def proxy_export(self) -> dict[str, Any]:
        return self._proxy_request("GET", "/proxy/export")

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

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health")

    def camera_status(self) -> dict[str, Any]:
        return self.request(
            "GET",
            "/camera/status",
            timeout=CAMERA_MUTATION_TIMEOUT_SECONDS,
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

    def root_status(self) -> dict[str, Any]:
        return self.request("GET", "/root/status")

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
