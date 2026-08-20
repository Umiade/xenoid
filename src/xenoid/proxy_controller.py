from __future__ import annotations

import base64
import binascii
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from .backend import RuntimeManager
from .config import InstanceContext, InstanceError, InstanceLease, XenoidConfig
from .daemon_client import PROXY_CHECK_TIMEOUT_SECONDS, DaemonClient, wait_for_proxy_check
from .operation_lock import instance_operation_lock, operation_lock_is_held

_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ACTIVE_PHASES = {
    "starting",
    "quarantine",
    "quarantined",
    "prepared",
    "configured",
    "applying",
    "applied",
    "ready",
    "active",
    "disabled",
    "off",
    "error",
}


def _failure(code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "error": code}


def _error_code(value: Any, fallback: str) -> str:
    if isinstance(value, dict):
        for name in ("code", "error", "errorCode", "stateError"):
            candidate = value.get(name)
            if isinstance(candidate, str) and _SAFE_CODE.fullmatch(candidate):
                return candidate
    return fallback


def _valid_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    decoded: Optional[bytearray] = None
    try:
        decoded = bytearray(base64.b64decode(value, validate=True))
        return len(decoded) == 32
    except (binascii.Error, ValueError):
        return False
    finally:
        if decoded is not None:
            for index in range(len(decoded)):
                decoded[index] = 0

def _completed_check(status: dict[str, Any]) -> bool:
    generation = status.get("generation")
    check_id = status.get("checkId")
    runtime_epoch = status.get("runtimeEpoch")
    instance_id = status.get("instanceId")
    report = status.get("report")
    probe = status.get("probe")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not isinstance(check_id, int)
        or isinstance(check_id, bool)
        or check_id <= 0
        or not isinstance(runtime_epoch, str)
        or not runtime_epoch
        or not isinstance(instance_id, str)
        or not instance_id
        or not isinstance(report, dict)
        or not isinstance(probe, dict)
    ):
        return False
    return (
        report.get("generation") == generation
        and report.get("checkId") == check_id
        and report.get("phase") == "active"
        and report.get("structuralApplied") is True
        and report.get("dataPlaneVerified") is True
        and probe.get("checkId") == check_id
        and probe.get("errorCode") == ""
    )


class ProxyController:
    """Coordinates daemon desired state with one explicitly bound engine agent."""

    def __init__(
        self,
        context: InstanceContext,
        config: XenoidConfig,
        lease: InstanceLease,
        manager: RuntimeManager,
        daemon: DaemonClient,
    ):
        if (
            manager.context != context
            or manager.cfg != config
            or manager.lease != lease
            or lease.instance_id != context.instance_id
            or lease.resource_tag != context.resource_tag
        ):
            raise InstanceError("instance_identity_mismatch", "proxy controller instance identity mismatch")
        manager.ensure_instance_lease()
        self._context = context
        self._lease = lease
        self._manager = manager
        self._daemon = daemon

    def _manager_call(self, name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            result = getattr(self._manager, name)(*args, **kwargs)
        except InstanceError as exc:
            return _failure(exc.code)
        except Exception:
            return _failure("engine_unavailable")
        if not isinstance(result, dict):
            return _failure("engine_response_invalid")
        if result.get("ok") is not True:
            return _failure(_error_code(result, "engine_unavailable"))
        return result

    @contextmanager
    def _mutation_scope(self) -> Iterator[None]:
        if operation_lock_is_held(self._context.instance_id):
            yield
            return
        with instance_operation_lock(self._context.state_root):
            yield

    def _quarantine_for_mutation(self) -> dict[str, Any]:
        prerequisite = self._manager_call("proxy_prerequisite")
        if prerequisite.get("ok") is not True:
            return prerequisite
        guarded = self._manager_call("proxy_quarantine")
        if guarded.get("ok") is not True:
            return guarded
        return {"ok": True, "quarantined": True}

    def _release_direct(
        self,
        mutation: dict[str, Any],
        *,
        configured: bool,
    ) -> dict[str, Any]:
        generation = mutation.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            self._manager_call("proxy_quarantine")
            return _failure("daemon_response_invalid")
        current = self._daemon.proxy_status()
        runtime_epoch = self._runtime_epoch()
        if (
            current.get("ok") is not True
            or current.get("generation") != generation
            or current.get("enabled") is not False
            or current.get("configured") is not configured
            or not isinstance(runtime_epoch, str)
            or not runtime_epoch
        ):
            self._manager_call("proxy_quarantine", generation)
            return _failure(_error_code(current, "daemon_response_invalid"))
        released = self._manager_call(
            "proxy_off",
            generation,
            runtime_epoch=runtime_epoch,
        )
        released_epoch = released.get("runtimeEpoch")
        if (
            released.get("ok") is not True
            or released.get("generation") != generation
            or not isinstance(released_epoch, str)
            or not released_epoch
            or released.get("phase") != "off"
            or released.get("structuralApplied") is not True
            or released.get("dataPlaneVerified") is not True
            or released.get("agentAbsent") is not True
            or released.get("routingAbsent") is not True
        ):
            self._manager_call("proxy_quarantine", generation)
            return (
                released
                if released.get("ok") is not True
                else _failure("off_unverified")
            )
        return {
            "ok": True,
            "generation": generation,
            "enabled": False,
            "configured": configured,
            "runtimeEpoch": released_epoch,
            "phase": "off",
            "structuralApplied": True,
            "dataPlaneVerified": True,
            "agentAbsent": True,
            "routingAbsent": True,
        }

    def _runtime_epoch(self) -> str:
        status = self._daemon.bootstrap_status()
        runtime_epoch = (
            status.get("runtimeEpoch")
            if isinstance(status, dict)
            else None
        )
        return (
            runtime_epoch
            if isinstance(runtime_epoch, str)
            and re.fullmatch(r"[0-9a-f]{64}", runtime_epoch) is not None
            else ""
        )

    def _ensure_agent(self, status: dict[str, Any]) -> dict[str, Any]:
        generation = status.get("generation")
        runtime_epoch = self._runtime_epoch()
        enabled = status.get("enabled")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            return _failure("daemon_response_invalid")
        if enabled is not True:
            return _failure("proxy_disabled")
        prerequisite = self._manager_call("proxy_prerequisite")
        if prerequisite.get("ok") is not True:
            return prerequisite
        engine_status = self._manager_call("proxy_engine_status")
        same_agent = (
            engine_status.get("ok") is True
            and engine_status.get("instanceId") == self._context.instance_id
            and engine_status.get("resourceTag") == self._context.resource_tag
            and bool(runtime_epoch)
            and engine_status.get("runtimeEpoch") == runtime_epoch
            and engine_status.get("phase") in _ACTIVE_PHASES
        )
        if same_agent and engine_status.get("phase") != "off":
            prepared = self._manager_call("proxy_prepare_asset", None)
            if prepared.get("ok") is not True:
                self._manager_call("proxy_quarantine", generation)
                return prepared
            return engine_status

        if engine_status.get("ok") is True:
            quarantined = self._manager_call("proxy_quarantine", generation)
            if quarantined.get("ok") is not True:
                return quarantined

        bootstrap = self._daemon.proxy_agent_bootstrap(self._context.instance_id, runtime_epoch)
        if (
            not isinstance(bootstrap, dict)
            or set(bootstrap) != {
                "ok", "version", "instanceId", "runtimeEpoch", "masterKey", "agentToken"
            }
            or bootstrap.get("ok") is not True
            or type(bootstrap.get("version")) is not int
            or bootstrap.get("version") != 1
            or bootstrap.get("instanceId") != self._context.instance_id
            or bootstrap.get("runtimeEpoch") != runtime_epoch
            or not _valid_secret(bootstrap.get("masterKey"))
            or not _valid_secret(bootstrap.get("agentToken"))
        ):
            return _failure(_error_code(bootstrap, "agent_bootstrap_failed"))
        master_key = bootstrap.pop("masterKey")
        agent_token = bootstrap.pop("agentToken")
        try:
            started = self._manager_call(
                "proxy_start_agent",
                runtime_epoch=runtime_epoch,
                generation=generation,
                master_key=master_key,
                agent_token=agent_token,
                enabled=True,
            )
        finally:
            bootstrap.clear()
            del master_key
            del agent_token
        if started.get("ok") is not True:
            self._manager_call("proxy_quarantine", generation)
            return started
        prepared = self._manager_call("proxy_prepare_asset", None)
        if prepared.get("ok") is not True:
            self._manager_call("proxy_quarantine", generation)
            return prepared
        return started

    def _wait_generation(
        self,
        generation: int,
        runtime_epoch: str,
        timeout: float = PROXY_CHECK_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            status = self._daemon.proxy_status()
            if status.get("ok") is not True:
                return status
            if status.get("runtimeEpoch") != runtime_epoch:
                return _failure("runtime_epoch_mismatch")
            report = status.get("report")
            if isinstance(report, dict) and report.get("generation") == generation:
                code = report.get("errorCode")
                if isinstance(code, str) and code:
                    return _failure(code if _SAFE_CODE.fullmatch(code) else "proxy_reconcile_failed")
                if (
                    report.get("phase") == "active"
                    and report.get("structuralApplied") is True
                    and report.get("dataPlaneVerified") is True
                ):
                    return status if _completed_check(status) else _failure("data_plane_unverified")
                if (
                    report.get("phase") == "off"
                    and report.get("structuralApplied") is True
                    and report.get("dataPlaneVerified") is True
                ):
                    return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _failure("agent_stale")
            time.sleep(min(0.25, remaining))

    def _converge(self, mutation: dict[str, Any], *, fresh_check: bool) -> dict[str, Any]:
        if mutation.get("ok") is not True:
            return mutation
        generation = mutation.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool):
            return _failure("daemon_response_invalid")
        status = self._daemon.proxy_status()
        if status.get("ok") is not True or status.get("generation") != generation:
            self._manager_call("proxy_quarantine", generation)
            return _failure(_error_code(status, "daemon_response_invalid"))
        ensured = self._ensure_agent(status)
        if ensured.get("ok") is not True:
            self._manager_call("proxy_quarantine", generation)
            return ensured
        current = self._daemon.proxy_status()
        if current.get("ok") is not True or current.get("generation") != generation:
            self._manager_call("proxy_quarantine", generation)
            return _failure(_error_code(current, "daemon_response_invalid"))
        runtime_epoch = current.get("runtimeEpoch")
        if not isinstance(runtime_epoch, str) or not runtime_epoch:
            self._manager_call("proxy_quarantine", generation)
            return _failure("agent_stale")
        if fresh_check:
            check_id = current.get("checkId")
            report = current.get("report")
            probe = current.get("probe")
            terminal_evidence = (
                _completed_check(current)
                or isinstance(report, dict)
                and report.get("checkId") == check_id
                and (
                    bool(report.get("errorCode"))
                    or report.get("phase") in {"active", "off"}
                )
                or isinstance(probe, dict)
                and probe.get("checkId") == check_id
            )
            if (
                isinstance(check_id, int)
                and not isinstance(check_id, bool)
                and check_id > 0
                and not terminal_evidence
            ):
                # A mutation allocates its check before the agent starts. Reuse
                # only genuinely in-flight evidence; terminal success or failure
                # must allocate a fresh readiness check.
                checked = wait_for_proxy_check(
                    self._daemon,
                    expected_check_id=check_id,
                    expected_generation=generation,
                    expected_runtime_epoch=runtime_epoch,
                )
            else:
                checked = wait_for_proxy_check(self._daemon)
            if checked.get("ok") is not True:
                self._manager_call("proxy_quarantine", generation)
                checked.setdefault("generation", generation)
            return checked
        settled = self._wait_generation(generation, runtime_epoch)
        if settled.get("ok") is not True:
            self._manager_call("proxy_quarantine", generation)
        return settled

    def status(self, *, check: bool = False) -> dict[str, Any]:
        if not check:
            return self._daemon.proxy_status()
        with self._mutation_scope():
            status = self._daemon.proxy_status()
            if status.get("ok") is not True:
                return status
            if status.get("enabled") is not True:
                return _failure("proxy_disabled")
            return self._converge(
                {"ok": True, "generation": status.get("generation")},
                fresh_check=True,
            )

    def set_source(
        self,
        kind: str,
        value: str,
        enable: bool,
        *,
        selected_node: str = "",
        udp_allowed: bool = True,
        allow_insecure_http: bool = False,
    ) -> dict[str, Any]:
        with self._mutation_scope():
            guarded = self._quarantine_for_mutation()
            if guarded.get("ok") is not True:
                return guarded
            mutation = self._daemon.proxy_source(
                kind,
                value,
                enable,
                selected_node=selected_node,
                udp_allowed=udp_allowed,
                allow_insecure_http=allow_insecure_http,
            )
            if mutation.get("ok") is not True:
                return mutation
            if enable:
                return self._converge(mutation, fresh_check=True)
            return self._release_direct(mutation, configured=True)

    def set_enabled(self, enabled: bool) -> dict[str, Any]:
        with self._mutation_scope():
            guarded = self._quarantine_for_mutation()
            if guarded.get("ok") is not True:
                return guarded
            mutation = self._daemon.proxy_enabled(enabled)
            if mutation.get("ok") is not True:
                return mutation
            if enabled:
                return self._converge(mutation, fresh_check=True)
            configured = mutation.get("configured")
            if not isinstance(configured, bool):
                return _failure("daemon_response_invalid")
            return self._release_direct(mutation, configured=configured)

    def clear(self, *, discard_unreadable_state: bool = False) -> dict[str, Any]:
        with self._mutation_scope():
            guarded = self._quarantine_for_mutation()
            if guarded.get("ok") is not True:
                return guarded
            mutation = self._daemon.proxy_clear(discard_unreadable_state)
            if mutation.get("ok") is not True:
                return mutation
            return self._release_direct(mutation, configured=False)

    def select(self, name: str) -> dict[str, Any]:
        with self._mutation_scope():
            guarded = self._quarantine_for_mutation()
            if guarded.get("ok") is not True:
                return guarded
            mutation = self._daemon.proxy_select(name)
            if mutation.get("ok") is not True:
                return mutation
            enabled = mutation.get("enabled")
            if not isinstance(enabled, bool):
                return _failure("daemon_response_invalid")
            if enabled:
                return self._converge(mutation, fresh_check=True)
            return self._release_direct(mutation, configured=True)

    def reconcile_for_list(self) -> dict[str, Any]:
        with self._mutation_scope():
            status = self._daemon.proxy_status()
            if status.get("ok") is not True or status.get("configured") is not True:
                return status
            if status.get("enabled") is not True:
                return status
            return self._converge(
                {"ok": True, "generation": status.get("generation")},
                fresh_check=False,
            )

    def reconcile_desired(self) -> dict[str, Any]:
        with self._mutation_scope():
            status = self._daemon.proxy_status()
            if status.get("ok") is not True:
                return status
            enabled = status.get("enabled")
            if not isinstance(enabled, bool):
                return _failure("daemon_response_invalid")
            configured = status.get("configured")
            if not isinstance(configured, bool):
                return _failure("daemon_response_invalid")
            if not enabled:
                return self._release_direct(
                    {
                        "ok": True,
                        "generation": status.get("generation"),
                    },
                    configured=configured,
                )
            return self._converge(
                {
                    "ok": True,
                    "generation": status.get("generation"),
                    "checkId": status.get("checkId"),
                    "enabled": True,
                },
                fresh_check=True,
            )

    def prepare(self, asset_path: Optional[str] = None) -> dict[str, Any]:
        with self._mutation_scope():
            prerequisite = self._manager_call("proxy_prerequisite")
            if prerequisite.get("ok") is not True:
                return prerequisite
            asset = Path(asset_path).expanduser() if asset_path is not None else None
            return self._manager_call("proxy_prepare_asset", asset)
