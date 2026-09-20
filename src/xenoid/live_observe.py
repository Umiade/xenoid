from __future__ import annotations

import hashlib
import inspect
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Optional

from .device_identity import container_epoch


LIVE_ACCEPTANCE_SCHEMA = "dev.xenoid.live-acceptance/v1"
_PROGRESS_SCHEMA = "dev.xenoid.progress/v1"
_SAFE_MODE = re.compile(r"[a-z][a-z0-9-]{0,63}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}")
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}")


class _DeadlineExpired(RuntimeError):
    pass


class _Budget:
    def __init__(self, deadline: Optional[float]) -> None:
        if deadline is None:
            self.deadline: Optional[float] = None
        elif (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(float(deadline))
        ):
            raise ValueError("invalid deadline")
        else:
            self.deadline = float(deadline)

    def remaining(self, maximum: float = 10.0) -> float:
        if self.deadline is None:
            return maximum
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExpired
        return min(maximum, remaining)

    def check(self) -> None:
        self.remaining()


class _Checks:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}

    def add(
        self,
        name: str,
        ok: bool,
        failure: str,
        *,
        state: Optional[str] = None,
    ) -> None:
        item: dict[str, Any] = {
            "ok": bool(ok),
            "code": "accepted" if ok else _safe_code(failure, "acceptance_failed"),
        }
        if isinstance(state, str) and _SAFE_CODE.fullmatch(state):
            item["state"] = state
        self.values[name] = item

    def ok(self, *names: str) -> bool:
        return all(self.values.get(name, {}).get("ok") is True for name in names)

    def first_failure(self) -> Optional[str]:
        for item in self.values.values():
            if item.get("ok") is not True:
                return str(item["code"])
        return None


class LiveAcceptance:
    """Fresh, read-only acceptance of one already-running owned runtime.

    The observer deliberately depends on capabilities rather than RuntimeManager's
    concrete type. This keeps it usable by the convergence executor and by strict
    fakes while ensuring that every operation selected here is observational.
    """

    def __init__(self, manager: Any = None) -> None:
        self._manager = manager

    def observe(
        self,
        context: Any,
        expected: Mapping[str, Any],
        mode: str,
        deadline: Optional[float],
        progress: Optional[Callable[[Mapping[str, Any]], None]],
    ) -> dict[str, Any]:
        started = time.monotonic()
        if not isinstance(mode, str) or _SAFE_MODE.fullmatch(mode) is None:
            return _early_failure("acceptance_mode_invalid", started)
        if not isinstance(expected, Mapping):
            return _early_failure("acceptance_expected_invalid", started)
        try:
            budget = _Budget(deadline)
        except ValueError:
            return _early_failure("acceptance_deadline_invalid", started)

        self._emit(progress, started, "started", "observing")
        checks = _Checks()
        try:
            manager, context_values = self._resolve_manager(context)
            if manager is None:
                return _early_failure("acceptance_context_invalid", started)
            contextual_expected = _mapping_at(context_values, "expected")
            resolved_expected = dict(contextual_expected)
            resolved_expected.update(expected)
            resolved_expected["_acceptanceMode"] = mode

            snapshot = self._manager_snapshot(manager, budget)
            checks.add(
                "observation",
                isinstance(snapshot, Mapping) and bool(snapshot),
                "convergence_observation_unavailable",
            )
            self._emit(progress, started, "running", "runtime-observed")

            identifiers = self._host_checks(
                manager,
                context_values,
                snapshot,
                resolved_expected,
                budget,
                checks,
            )
            self._emit(progress, started, "running", "host-observed")

            daemon = self._daemon_checks(
                manager,
                snapshot,
                resolved_expected,
                identifiers,
                budget,
                checks,
            )
            self._emit(progress, started, "running", "control-observed")

            self._proxy_checks(
                manager,
                snapshot,
                resolved_expected,
                identifiers,
                daemon,
                budget,
                checks,
            )
            self._google_and_protection_checks(
                manager,
                snapshot,
                resolved_expected,
                budget,
                checks,
                identifiers,
            )
            if mode == "doctor-full":
                checks.add(
                    "cellular",
                    checks.ok("location"),
                    "cellular_not_ready",
                )
            budget.check()
        except _DeadlineExpired:
            checks.add("deadline", False, "live_acceptance_timeout")
            identifiers = locals().get("identifiers", {})
            snapshot = locals().get("snapshot", {})
        except Exception:
            checks.add("observer", False, "live_acceptance_observation_failed")
            identifiers = locals().get("identifiers", {})
            snapshot = locals().get("snapshot", {})

        observation = {
            "schema": LIVE_ACCEPTANCE_SCHEMA,
            "mode": mode,
            "containerId": _safe_identifier(identifiers.get("containerId")),
            "imageId": _safe_identifier(identifiers.get("imageId")),
            "selectedImageInputSha256": _safe_digest(
                identifiers.get("selectedImageInputSha256")
            ),
            "selectedImageBootInputSha256": _safe_digest(
                identifiers.get("selectedImageBootInputSha256")
            ),
            "runtimeInventoryDigest": _safe_digest(
                identifiers.get("runtimeInventoryDigest")
            ),
            "runtimeInventoryCount": _safe_counter(
                identifiers.get("runtimeInventoryCount")
            ),
            "dataUuid": _safe_uuid(identifiers.get("dataUuid")),
            "rootfsUuid": _safe_uuid(identifiers.get("rootfsUuid")),
            "runtimeEpoch": _safe_digest(identifiers.get("runtimeEpoch")),
            "proxyGeneration": _safe_counter(identifiers.get("proxyGeneration")),
            "protectionDigest": _safe_digest(identifiers.get("protectionDigest")),
            "checks": checks.values,
        }
        observation_sha = hashlib.sha256(_canonical(observation)).hexdigest()
        error_code = checks.first_failure()
        ok = error_code is None
        observation_valid = self._observation_valid(checks)
        component_actions = self._component_actions(snapshot, checks, resolved_expected)
        result: dict[str, Any] = {
            "ok": ok,
            "observationValid": observation_valid,
            "schema": LIVE_ACCEPTANCE_SCHEMA,
            "mode": mode,
            "observationSha256": observation_sha,
            "observation": observation,
            "acceptanceChecks": list(checks.values),
            "checks": checks.values,
            "componentActions": component_actions,
            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
        }
        if error_code is not None:
            result["errorCode"] = error_code
        self._emit(
            progress,
            started,
            "passed" if ok else "failed",
            "accepted" if ok else error_code or "acceptance-failed",
        )
        return result

    @staticmethod
    def _observation_valid(checks: _Checks) -> bool:
        structural = (
            "observation",
            "containerOwnership",
            "containerRunning",
            "containerContract",
            "networkContract",
            "volumeContract",
            "imageImmutableId",
            "imageIdentity",
            "storageIdentity",
            "bootSeed",
            "adbTransport",
            "androidBoot",
            "expectedContainer",
            "expectedDataUuid",
            "expectedRootfsUuid",
            "expectedImageInput",
            "expectedImageBootInput",
        )
        return (
            checks.ok(*structural)
            and checks.values.get("deadline") is None
            and checks.values.get("observer") is None
        )

    @staticmethod
    def _resolve_manager(context: Any) -> tuple[Any, Mapping[str, Any]]:
        if isinstance(context, Mapping):
            manager = context.get("manager") or context.get("runtimeManager")
            return manager, context
        if hasattr(context, "observe_convergence"):
            return context, {}
        manager = getattr(context, "manager", None)
        values = getattr(context, "acceptance", None)
        return manager, values if isinstance(values, Mapping) else {}

    @staticmethod
    def _manager_snapshot(manager: Any, budget: _Budget) -> Mapping[str, Any]:
        budget.check()
        method = getattr(manager, "observe_convergence", None)
        if not callable(method):
            return {}
        kwargs: dict[str, Any] = {}
        parameters = _parameters(method)
        if "skip_build" in parameters:
            kwargs["skip_build"] = True
        if "deadline" in parameters:
            kwargs["deadline"] = (
                budget.deadline
                if budget.deadline is not None
                else time.monotonic() + budget.remaining(30.0)
            )
        value = method(**kwargs)
        budget.check()
        return value if isinstance(value, Mapping) else {}

    def _host_checks(
        self,
        manager: Any,
        context: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        expected: Mapping[str, Any],
        budget: _Budget,
        checks: _Checks,
    ) -> dict[str, Any]:
        identifiers: dict[str, Any] = {}
        runtime = _mapping_at(snapshot, "runtime")
        container = _mapping_at(snapshot, "container", "runtime.container")
        if not container:
            container = runtime
        container_id = _first(
            _at(snapshot, "containerId", "runtime.containerId"),
            _at(container, "id", "containerId", "Id"),
            _at(context, "containerId"),
        )
        identifiers["containerId"] = container_id
        image_id = _first(
            _at(snapshot, "imageId", "runtime.imageId"),
            _at(container, "imageId", "Image"),
            _at(snapshot, "runtimeImageIdentity.imageId"),
        )
        identifiers["imageId"] = image_id
        checks.add(
            "imageImmutableId",
            _safe_identifier(image_id) is not None,
            "runtime_image_identity_unavailable",
        )
        owned = _first_bool(
            _at(snapshot, "containerOwned", "owned"),
            _at(container, "owned", "ownershipValid"),
            _at(runtime, "ownershipValid"),
        )
        running = _first_bool(
            _at(snapshot, "running", "containerRunning"),
            _at(container, "running", "state.running", "State.Running"),
        )
        if running is None:
            running = _at(runtime, "state") == "running"
        contract_match = _first_bool(
            _at(snapshot, "containerContractMatches", "createSpecMatches"),
            _at(container, "contractMatches", "createSpecMatches"),
            _at(runtime, "createSpecMatches"),
        )
        network_match = _first_bool(_at(runtime, "networkMatches"))
        volume_match = _first_bool(_at(runtime, "volumeMatches"))
        if owned is None:
            owned = bool(container_id and _at(snapshot, "error") != "resource_conflict")
        checks.add("containerOwnership", owned is True, "container_ownership_invalid")
        checks.add("containerRunning", running is True, "runtime_not_running")
        checks.add(
            "containerContract",
            contract_match is True,
            "container_contract_mismatch",
        )
        checks.add(
            "networkContract",
            network_match is True,
            "network_contract_mismatch",
        )
        checks.add(
            "volumeContract",
            volume_match is True,
            "volume_contract_mismatch",
        )

        image_identity = _mapping_at(
            snapshot,
            "runtimeImageIdentity",
            "container.imageIdentity",
            "imageIdentity",
        )
        image_ok = _first_bool(
            _at(image_identity, "ok", "compatible"),
            _at(snapshot, "imageIdentityMatches"),
            _at(runtime, "integrationIdentityValid"),
        )
        if image_ok is None:
            match = _at(image_identity, "match")
            image_ok = match in {"exact", "daemon-live-compatible", "boot-compatible"}
        identifiers["selectedImageInputSha256"] = _first(
            _at(
                image_identity,
                "containerInputSha256",
                "inputSha256",
                "selectedImageInputSha256",
            ),
            _at(
                snapshot,
                "selectedImageInputSha256",
                "image.inputSha256",
                "runtime.imageInputSha256",
            ),
        )
        identifiers["selectedImageBootInputSha256"] = _first(
            _at(
                image_identity,
                "containerBootInputSha256",
                "bootInputSha256",
                "selectedImageBootInputSha256",
            ),
            _at(
                snapshot,
                "selectedImageBootInputSha256",
                "image.bootInputSha256",
                "runtime.imageBootInputSha256",
            ),
        )
        checks.add("imageIdentity", image_ok is True, "runtime_image_identity_mismatch")

        deploy = _mapping_at(snapshot, "components.deploy", "deploy")
        deploy_states = [
            value.get("state")
            if isinstance(value, Mapping)
            else value
            for value in deploy.values()
        ]
        deploy_ok = (
            deploy.get("ok") is True
            or deploy.get("state") in {"ready", "reused"}
            or deploy.get("action") == "reuse"
            or bool(deploy_states)
            and all(
                state in {"matching", "ready", "reused", "reuse"}
                for state in deploy_states
            )
        )
        checks.add("deployment", deploy_ok, "runtime_components_stale")

        storage = _mapping_at(snapshot, "storage", "observations.storage")
        if not storage and "storageValid" in runtime:
            storage = runtime
        if not storage:
            storage = self._optional_call(manager, "storage_status", budget)
        data_uuid = _first(
            _at(storage, "filesystemUuid", "dataUuid", "dataFilesystemUuid"),
            _at(snapshot, "dataUuid", "runtime.dataUuid"),
            _at(context, "dataUuid"),
        )
        rootfs_uuid = _first(
            _at(storage, "rootfsFilesystemUuid", "rootfsUuid"),
            _at(snapshot, "rootfsUuid", "runtime.rootfsUuid"),
            _at(context, "rootfsUuid"),
        )
        identifiers["dataUuid"] = data_uuid
        identifiers["rootfsUuid"] = rootfs_uuid
        storage_ok = _first_bool(_at(storage, "ok"), _at(storage, "storageValid")) is True
        storage_state = _at(storage, "state")
        if isinstance(storage_state, str) and "storageValid" not in storage:
            storage_ok = storage_ok and storage_state == "committed"
        checks.add("storageIdentity", storage_ok, "storage_identity_mismatch")
        checks.add(
            "bootSeed",
            _at(runtime, "bootSeedRequired") is False,
            "boot_seed_incomplete",
        )

        sentinel_value = _at(
            snapshot,
            "storageSentinel",
            "sentinel",
            "observations.storageSentinel",
            "runtime.storageSentinel",
        )
        sentinel_error: Any = None
        if isinstance(sentinel_value, Mapping) and sentinel_value.get("skipped") is not True:
            sentinel_ok = sentinel_value.get("ok") is True
            sentinel_error = sentinel_value.get("errorCode") or sentinel_value.get("error")
        elif isinstance(sentinel_value, bool):
            sentinel_ok = sentinel_value
        else:
            sentinel = self._optional_call(
                manager,
                "data_sentinel",
                budget,
                fixed_kwargs={"create": False},
            )
            sentinel_ok = _at(sentinel, "ok") is True
            sentinel_error = _first(
                _at(sentinel, "errorCode"),
                _at(sentinel, "error"),
            )
        checks.add(
            "storageSentinel",
            sentinel_ok,
            _safe_code(sentinel_error, "storage_sentinel_mismatch"),
        )

        identity = _mapping_at(
            snapshot,
            "identity",
            "deviceIdentity",
            "components.identity",
        )
        identity_status = (
            identity.get("status")
            if isinstance(identity.get("status"), Mapping)
            else None
        )
        if identity_status is not None:
            identity = identity_status
        if not identity:
            identity = self._optional_call(manager, "device_identity_status", budget)
        identity_state = _at(identity, "state")
        identity_ok = (
            _at(identity, "ok") is True and _at(identity, "initialized") is True
        ) or identity_state in {"ready", "reused", "converged"} or (
            _at(identity, "action") == "reuse"
        )
        phase = _at(identity, "phase")
        if isinstance(phase, str):
            identity_ok = identity_ok and phase == "applied"
        identity_container_epoch = _at(identity, "containerEpoch")
        safe_container_id = _safe_digest(container_id)
        if identity_container_epoch is not None and safe_container_id is not None:
            try:
                identity_ok = identity_ok and identity_container_epoch == container_epoch(
                    safe_container_id
                )
            except Exception:
                identity_ok = False
        checks.add("identity", identity_ok, "identity_not_converged")

        adb_value = _at(snapshot, "adb", "androidBoot", "runtime.adb")
        adb = adb_value if isinstance(adb_value, Mapping) else {}
        connected = _first_bool(
            adb_value if isinstance(adb_value, bool) else None,
            _at(adb, "connected", "ok", "ready"),
        )
        boot_value = _at(snapshot, "runtime.boot")
        booted = _first_bool(
            boot_value if isinstance(boot_value, bool) else None,
            _at(adb, "bootCompleted", "booted"),
            _at(boot_value, "ok", "bootCompleted", "booted"),
        )
        adb_method = getattr(manager, "adb", None)
        if (connected is None or booted is None) and callable(adb_method):
            state = self._call(adb_method, budget, ["get-state"])
            boot = self._call(
                adb_method,
                budget,
                ["shell", "getprop", "sys.boot_completed"],
            )
            connected = bool(
                isinstance(state, Mapping)
                and state.get("ok") is True
                and str(state.get("stdout") or "").strip() == "device"
            )
            booted = bool(
                isinstance(boot, Mapping)
                and boot.get("ok") is True
                and str(boot.get("stdout") or "").strip() == "1"
            )
        checks.add("adbTransport", connected is True, "adb_transport_unavailable")
        checks.add("androidBoot", booted is True, "android_boot_incomplete")

        expected_container = expected.get("containerId")
        if expected_container is None:
            checks.add(
                "expectedContainer",
                _safe_identifier(container_id) is not None,
                "container_identity_mismatch",
            )
        else:
            self._bind_identifier(
                checks,
                "expectedContainer",
                expected_container,
                container_id,
                _safe_identifier,
                "container_identity_mismatch",
            )
        expected_data_uuid = expected.get("dataUuid")
        if expected_data_uuid is None:
            checks.add(
                "expectedDataUuid",
                _safe_uuid(data_uuid) is not None,
                "data_uuid_mismatch",
            )
        else:
            self._bind_identifier(
                checks,
                "expectedDataUuid",
                expected_data_uuid,
                data_uuid,
                _safe_uuid,
                "data_uuid_mismatch",
            )
        self._bind_optional_identifier(
            checks,
            "expectedRootfsUuid",
            expected.get("rootfsUuid"),
            rootfs_uuid,
            _safe_uuid,
            "rootfs_uuid_mismatch",
        )
        self._bind_optional_identifier(
            checks,
            "expectedImageInput",
            _first(
                expected.get("selectedImageInputSha256"),
                expected.get("imageInputSha256"),
            ),
            identifiers["selectedImageInputSha256"],
            _safe_digest,
            "runtime_image_input_mismatch",
        )
        self._bind_optional_identifier(
            checks,
            "expectedImageBootInput",
            _first(
                expected.get("selectedImageBootInputSha256"),
                expected.get("imageBootInputSha256"),
            ),
            identifiers["selectedImageBootInputSha256"],
            _safe_digest,
            "runtime_image_boot_input_mismatch",
        )
        return identifiers

    def _daemon_checks(
        self,
        manager: Any,
        snapshot: Mapping[str, Any],
        expected: Mapping[str, Any],
        identifiers: dict[str, Any],
        budget: _Budget,
        checks: _Checks,
    ) -> dict[str, Mapping[str, Any]]:
        factory = getattr(manager, "daemon_client", None)
        if not callable(factory):
            for name, code in (
                ("daemonTransport", "daemon_transport_unavailable"),
                ("daemonBootstrap", "daemon_bootstrap_not_ready"),
                ("daemonHealth", "daemon_health_not_ready"),
                ("rootd", "rootd_not_ready"),
                ("location", "location_not_ready"),
                ("keybox", "keybox_not_ready"),
                ("camera", "camera_not_ready"),
            ):
                checks.add(name, False, code)
            return {}
        client = self._call(factory, budget)
        statuses: dict[str, Mapping[str, Any]] = {}
        for name, method_name in (
            ("transport", "transport"),
            ("bootstrap", "bootstrap_status"),
            ("health", "health"),
            ("root", "root_status"),
            ("location", "location_status"),
            ("keybox", "keybox_status"),
            ("camera", "camera_status"),
            ("proxy", "proxy_status"),
        ):
            method = getattr(client, method_name, None)
            value = self._call(method, budget) if callable(method) else {}
            statuses[name] = value if isinstance(value, Mapping) else {}

        transport = statuses["transport"]
        bootstrap = statuses["bootstrap"]
        health = statuses["health"]
        checks.add(
            "daemonTransport",
            transport.get("ok") is True and transport.get("transportReady") is True,
            "daemon_transport_unavailable",
        )
        bootstrap_ok = (
            bootstrap.get("ok") is True
            and bootstrap.get("state") == "ready"
            and isinstance(bootstrap.get("components"), Mapping)
        )
        checks.add("daemonBootstrap", bootstrap_ok, "daemon_bootstrap_not_ready")
        checks.add(
            "daemonHealth",
            health.get("ok") is True,
            "daemon_health_not_ready",
        )
        runtime_epoch = bootstrap.get("runtimeEpoch")
        identifiers["runtimeEpoch"] = runtime_epoch
        expected_runtime_epoch = _first(
            expected.get("runtimeEpoch"),
            _at(snapshot, "runtimeEpoch"),
        )
        self._bind_optional_identifier(
            checks,
            "expectedRuntimeEpoch",
            expected_runtime_epoch,
            runtime_epoch,
            _safe_digest,
            "runtime_epoch_mismatch",
        )

        components = bootstrap.get("components")
        components = components if isinstance(components, Mapping) else {}
        for name, check_name, failure in (
            ("root", "rootd", "rootd_not_ready"),
            ("location", "location", "location_not_ready"),
            ("keybox", "keybox", "keybox_not_ready"),
            ("camera", "camera", "camera_not_ready"),
        ):
            component = components.get(name)
            component_ok = isinstance(component, Mapping) and component.get("ok") is True
            direct_ok = _component_ready(statuses[name])
            if name == "root":
                direct_ok = direct_ok and statuses[name].get("root") is True
            checks.add(check_name, component_ok and direct_ok, failure)
        return statuses

    def _proxy_checks(
        self,
        manager: Any,
        snapshot: Mapping[str, Any],
        expected: Mapping[str, Any],
        identifiers: dict[str, Any],
        daemon: Mapping[str, Mapping[str, Any]],
        budget: _Budget,
        checks: _Checks,
    ) -> None:
        status = daemon.get("proxy", {})
        bootstrap = daemon.get("bootstrap", {})
        components = bootstrap.get("components")
        proxy_component = (
            components.get("proxy") if isinstance(components, Mapping) else None
        )
        readable = status.get("stateReadable") is True
        generation = status.get("generation")
        runtime_epoch = status.get("runtimeEpoch")
        enabled = status.get("enabled")
        configured = status.get("configured")
        quarantined = status.get("quarantined")
        identifiers["proxyGeneration"] = generation
        checks.add(
            "proxyState",
            readable and status.get("ok") is True,
            (
                str(status["stateError"])
                if status.get("stateReadable") is False
                and isinstance(status.get("stateError"), str)
                else "proxy_state_unreadable"
            ),
        )
        checks.add(
            "proxyBootstrap",
            isinstance(proxy_component, Mapping) and proxy_component.get("ok") is True,
            "proxy_component_not_ready",
        )
        expected_generation = expected.get("proxyGeneration")
        if expected_generation is None:
            checks.add(
                "expectedProxyGeneration",
                _safe_counter(generation) is not None,
                "proxy_generation_unavailable",
            )
        else:
            checks.add(
                "expectedProxyGeneration",
                _safe_counter(expected_generation) is not None
                and generation == expected_generation,
                "proxy_generation_mismatch",
            )

        host = _mapping_at(
            snapshot,
            "proxyEngine",
            "proxyHost",
            "proxy.engine",
            "observations.proxyEngine",
            "components.proxy.engine",
        )
        if not host:
            host = self._optional_call(manager, "proxy_engine_status", budget)
        snapshot_quarantine = _first_bool(
            _at(snapshot, "proxyQuarantined"),
            _at(snapshot, "components.proxy.quarantineRequired"),
            _at(host, "quarantined"),
        )
        if snapshot_quarantine is True:
            checks.add("proxyHostQuarantine", False, "proxy_quarantined")
        else:
            checks.add("proxyHostQuarantine", True, "proxy_quarantined")

        disabled_proof = False
        if enabled is True:
            report = status.get("report")
            probe = status.get("probe")
            check_id = status.get("checkId")
            report_capabilities = (
                report.get("capabilities") if isinstance(report, Mapping) else None
            )
            probe_capabilities = (
                probe.get("capabilities") if isinstance(probe, Mapping) else None
            )
            expected_capabilities = {
                "v4DnsProxy": True,
                "v4TcpProxy": True,
                "v4UdpProxy": status.get("udpAllowed") is True,
                "v6DnsProxy": True,
                "v6TcpProxy": True,
                "v6UdpProxy": status.get("udpAllowed") is True,
            }
            capability_proof = (
                report_capabilities == expected_capabilities
                and probe_capabilities == expected_capabilities
            )
            daemon_proof = (
                isinstance(check_id, int)
                and not isinstance(check_id, bool)
                and check_id > 0
                and isinstance(report, Mapping)
                and isinstance(probe, Mapping)
                and report.get("checkId") == check_id
                and probe.get("checkId") == check_id
                and report.get("generation") == generation
                and report.get("phase") == "active"
                and report.get("structuralApplied") is True
                and report.get("dataPlaneVerified") is True
                and not report.get("errorCode")
                and not probe.get("errorCode")
                and capability_proof
            )
            report_counters = (
                report.get("counters") if isinstance(report, Mapping) else None
            )
            host_counters = host.get("counters")
            counter_proof = (
                isinstance(report_counters, Mapping)
                and isinstance(host_counters, Mapping)
                and set(report_counters) == set(host_counters)
                and all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    and isinstance(host_counters.get(name), int)
                    and not isinstance(host_counters.get(name), bool)
                    and host_counters[name] >= value
                    for name, value in report_counters.items()
                )
            )
            host_proof = (
                host.get("ok") is True
                and host.get("generation") == generation
                and host.get("runtimeEpoch") == runtime_epoch
                and host.get("phase") == "active"
                and host.get("structuralApplied") is True
                and counter_proof
            )
            checks.add(
                "proxyDataPlane",
                daemon_proof and host_proof,
                "proxy_data_plane_unverified",
            )
        elif enabled is False and configured in {False, True}:
            disabled_proof = (
                host.get("ok") is True
                and host.get("generation") == generation
                and host.get("runtimeEpoch") == runtime_epoch
                and host.get("phase") == "off"
                and host.get("structuralApplied") is True
                and host.get("dataPlaneVerified") is True
            )
            checks.add(
                "proxyDataPlane",
                disabled_proof,
                "proxy_disabled_state_unverified",
            )
        else:
            checks.add("proxyDataPlane", False, "proxy_state_unreadable")
        effective_epoch = (
            host.get("runtimeEpoch")
            if enabled is False
            else runtime_epoch
        )
        checks.add(
            "proxyQuarantine",
            quarantined is False
            if enabled is True
            else disabled_proof
            if enabled is False
            else False,
            "proxy_quarantined",
        )
        expected_epoch = _first(
            expected.get("runtimeEpoch"),
            identifiers.get("runtimeEpoch"),
        )
        if expected_epoch is not None:
            checks.add(
                "proxyRuntimeEpoch",
                _safe_digest(expected_epoch) is not None
                and effective_epoch == expected_epoch,
                "proxy_runtime_epoch_mismatch",
            )
        else:
            checks.add(
                "proxyRuntimeEpoch",
                _safe_digest(effective_epoch) is not None,
                "proxy_runtime_epoch_unavailable",
            )

    def _google_and_protection_checks(
        self,
        manager: Any,
        snapshot: Mapping[str, Any],
        expected: Mapping[str, Any],
        budget: _Budget,
        checks: _Checks,
        identifiers: dict[str, Any],
    ) -> None:
        google = _mapping_at(
            snapshot,
            "googleServices",
            "google",
            "observations.google",
            "components.google",
        )
        google_status = (
            google.get("status")
            if isinstance(google.get("status"), Mapping)
            else None
        )
        if google_status is not None:
            google = google_status
        if not google:
            google = self._optional_call(
                manager,
                "google_services_status",
                budget,
                fixed_kwargs={"require_runtime": True},
            )
        google_ok = google.get("ok") is True or google.get("state") in {
            "ready",
            "reused",
            "running-clean",
            "disabled",
        }
        google_ok = google_ok or google.get("action") == "reuse"
        if google.get("runtimeRequired") is True:
            google_ok = google_ok and google.get("ready") is True
        binding = google.get("binding")
        if isinstance(binding, Mapping) and binding:
            google_ok = google_ok and binding.get("state") == "committed"
        checks.add("googleBinding", google_ok, "google_binding_not_ready")

        protection = _mapping_at(
            snapshot,
            "sharedProtection",
            "protection",
            "observations.sharedProtection",
            "components.protection",
        )
        if not protection:
            for method_name in ("shared_protection_status", "protection_status"):
                protection = self._optional_call(manager, method_name, budget)
                if protection:
                    break
        observed_protection = protection.get("observed")
        backend_protection = (
            observed_protection
            if isinstance(observed_protection, Mapping)
            else protection
        )
        current_digest = _first(
            protection.get("currentDigest"),
            backend_protection.get("currentDigest"),
            _at(snapshot, "protectionDigest"),
        )
        identifiers["runtimeInventoryDigest"] = _first(
            protection.get("runtimeInventoryDigest"),
            backend_protection.get("runtimeInventoryDigest"),
        )
        identifiers["runtimeInventoryCount"] = _first(
            protection.get("runtimeInventoryCount"),
            backend_protection.get("runtimeInventoryCount"),
        )
        expected_digest = _first(
            protection.get("expectedDigest"),
            backend_protection.get("expectedDigest"),
        )
        engine_id = backend_protection.get("engineId")
        identifiers["protectionDigest"] = current_digest
        identifiers["protectionEngineId"] = engine_id
        protection_ok = (
            backend_protection.get("ok") is True
            and _safe_digest(current_digest) is not None
            and _safe_digest(expected_digest) is not None
            and current_digest == expected_digest
            and protection.get("replacementRequired") is not True
            and backend_protection.get("replacementRequired") is not True
        )
        checks.add(
            "sharedProtection",
            protection_ok,
            "shared_protection_not_ready",
        )
        self._bind_optional_identifier(
            checks,
            "expectedProtectionDigest",
            expected.get("protectionDigest"),
            current_digest,
            _safe_digest,
            "shared_protection_digest_mismatch",
        )
        self._bind_optional_identifier(
            checks,
            "expectedProtectionEngineId",
            expected.get("protectionEngineId"),
            engine_id,
            _safe_digest,
            "shared_protection_engine_mismatch",
        )

    @staticmethod
    def _bind_identifier(
        checks: _Checks,
        name: str,
        expected: Any,
        actual: Any,
        validator: Callable[[Any], Optional[Any]],
        failure: str,
    ) -> None:
        expected_value = validator(expected)
        actual_value = validator(actual)
        checks.add(
            name,
            expected_value is not None
            and actual_value is not None
            and expected_value == actual_value,
            failure,
        )

    @staticmethod
    def _bind_optional_identifier(
        checks: _Checks,
        name: str,
        expected: Any,
        actual: Any,
        validator: Callable[[Any], Optional[Any]],
        failure: str,
    ) -> None:
        if expected is None:
            checks.add(name, True, "accepted")
            return
        LiveAcceptance._bind_identifier(
            checks,
            name,
            expected,
            actual,
            validator,
            failure,
        )

    @staticmethod
    def _optional_call(
        target: Any,
        method_name: str,
        budget: _Budget,
        *,
        fixed_kwargs: Optional[Mapping[str, Any]] = None,
    ) -> Mapping[str, Any]:
        method = getattr(target, method_name, None)
        if not callable(method):
            return {}
        value = LiveAcceptance._call(
            method,
            budget,
            fixed_kwargs=dict(fixed_kwargs or {}),
        )
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _call(
        method: Callable[..., Any],
        budget: _Budget,
        *args: Any,
        fixed_kwargs: Optional[dict[str, Any]] = None,
    ) -> Any:
        budget.check()
        kwargs = dict(fixed_kwargs or {})
        parameters = _parameters(method)
        if "timeout" in parameters and "timeout" not in kwargs:
            kwargs["timeout"] = budget.remaining()
        value = method(*args, **kwargs)
        budget.check()
        return value

    @staticmethod
    def _component_actions(
        snapshot: Mapping[str, Any],
        checks: _Checks,
        expected: Mapping[str, Any],
    ) -> dict[str, Any]:
        supplied = expected.get("componentActions")
        if not isinstance(supplied, Mapping):
            supplied = _mapping_at(snapshot, "componentActions", "live.componentActions")
        result: dict[str, Any] = {}
        check_names = {
            "daemon": ("daemonTransport", "daemonBootstrap", "daemonHealth", "rootd"),
            "identity": ("identity",),
            "location": ("location",),
            "proxy": (
                "proxyState",
                "proxyBootstrap",
                "proxyQuarantine",
                "proxyHostQuarantine",
                "expectedProxyGeneration",
                "proxyRuntimeEpoch",
                "proxyDataPlane",
            ),
            "keybox": ("keybox",),
            "camera": ("camera",),
            "google": ("googleBinding",),
            "protection": ("sharedProtection", "expectedProtectionDigest"),
        }
        deploy_supplied = supplied.get("deploy")
        if isinstance(deploy_supplied, Mapping):
            result["deploy"] = {
                str(name): (
                    action
                    if isinstance(action, str) and action in {"reuse", "deploy"}
                    else "deploy"
                )
                for name, action in sorted(deploy_supplied.items())
            }
        else:
            deploy = _mapping_at(snapshot, "components.deploy", "deploy")
            result["deploy"] = {
                str(name): (
                    "reuse"
                    if (
                        value.get("state") if isinstance(value, Mapping) else value
                    )
                    in {"matching", "ready", "reused"}
                    else "deploy"
                )
                for name, value in sorted(deploy.items())
            }
        for component, names in check_names.items():
            action = supplied.get(component)
            if isinstance(action, str) and action != "inspect":
                result[component] = action
                continue
            if component == "daemon":
                daemon = _mapping_at(snapshot, "components.daemon", "daemon")
                result[component] = (
                    "install"
                    if daemon.get("state") in {"drift", "missing"}
                    else ("reuse" if checks.ok(*names) else "reconcile")
                )
            elif component in {"identity", "location"}:
                result[component] = "reuse" if checks.ok(*names) else "converge"
            elif component == "proxy":
                result[component] = (
                    "reuse"
                    if checks.ok(*names)
                    else "recovery"
                    if checks.values.get("proxyState", {}).get("code")
                    == "proxy_state_invalid"
                    else "reconcile"
                )
            else:
                result[component] = "reuse" if checks.ok(*names) else "reconcile"
        return result

    @staticmethod
    def _emit(
        progress: Optional[Callable[[Mapping[str, Any]], None]],
        started: float,
        state: str,
        detail: str,
    ) -> None:
        if not callable(progress):
            return
        safe_detail = (
            detail
            if isinstance(detail, str) and _SAFE_CODE.fullmatch(detail.replace("-", "_"))
            else "acceptance"
        )
        event = {
            "schema": _PROGRESS_SCHEMA,
            "command": "up",
            "phase": "live-acceptance",
            "state": state,
            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
            "detail": safe_detail,
        }
        try:
            progress(event)
        except Exception:
            pass


def _parameters(method: Callable[..., Any]) -> Mapping[str, inspect.Parameter]:
    try:
        return inspect.signature(method).parameters
    except (TypeError, ValueError):
        return {}


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _at(value: Any, *paths: str) -> Any:
    if not isinstance(value, Mapping):
        return None
    for path in paths:
        current: Any = value
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                current = None
                break
            current = current[part]
        if current is not None:
            return current
    return None


def _mapping_at(value: Any, *paths: str) -> Mapping[str, Any]:
    found = _at(value, *paths)
    return found if isinstance(found, Mapping) else {}


def _first(*values: Any) -> Any:
    return next((value for value in values if value is not None), None)


def _first_bool(*values: Any) -> Optional[bool]:
    return next((value for value in values if isinstance(value, bool)), None)


def _component_ready(value: Mapping[str, Any]) -> bool:
    if value.get("ok") is not True:
        return False
    if value.get("ready") is False or value.get("configured") is True and value.get("applied") is False:
        return False
    state = value.get("state")
    if isinstance(state, str) and state in {
        "degraded",
        "failed",
        "error",
        "pending",
        "stale",
        "quarantined",
    }:
        return False
    return True


def _safe_code(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and _SAFE_CODE.fullmatch(value) else fallback


def _safe_digest(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _HEX_64.fullmatch(value) else None


def _safe_uuid(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    return lowered if _UUID.fullmatch(lowered) else None


def _safe_identifier(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _SAFE_ID.fullmatch(value) else None


def _safe_counter(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < (1 << 63):
        return value
    return None


def _early_failure(code: str, started: float) -> dict[str, Any]:
    safe = _safe_code(code, "live_acceptance_observation_failed")
    checks = {"observer": {"ok": False, "code": safe}}
    observation = {
        "schema": LIVE_ACCEPTANCE_SCHEMA,
        "mode": "invalid",
        "containerId": None,
        "imageId": None,
        "selectedImageInputSha256": None,
        "selectedImageBootInputSha256": None,
        "dataUuid": None,
        "rootfsUuid": None,
        "runtimeEpoch": None,
        "proxyGeneration": None,
        "protectionDigest": None,
        "checks": checks,
    }
    return {
        "ok": False,
        "observationValid": False,
        "schema": LIVE_ACCEPTANCE_SCHEMA,
        "mode": "invalid",
        "observationSha256": hashlib.sha256(_canonical(observation)).hexdigest(),
        "observation": observation,
        "acceptanceChecks": list(checks),
        "checks": checks,
        "componentActions": {},
        "errorCode": safe,
        "durationMs": max(0, int((time.monotonic() - started) * 1000)),
    }
