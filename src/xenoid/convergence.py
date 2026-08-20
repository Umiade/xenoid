from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import inspect
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Optional

from .operation_lock import instance_operation_lock, operation_lock_is_held
from .storage import storage_rotation_target
from .util import bounded_timeout, command_timeout


PLAN_SCHEMA = "dev.xenoid.convergence-plan/v1"
JOURNAL_SCHEMA = "dev.xenoid.convergence-journal/v1"
RESULT_SCHEMA = "dev.xenoid.convergence/v1"
PROGRESS_SCHEMA = "dev.xenoid.progress/v1"
JOURNAL_FILENAME = "convergence-v1.json"
MAX_JOURNAL_BYTES = 256 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
HEARTBEAT_SECONDS = 5.0

_PHASES = (
    "planned",
    "quarantined",
    "image_ensured",
    "runtime_quiesced",
    "shared_protection_maintained",
    "seed_runtime_started",
    "seed_initialized",
    "container_removed",
    "storage_converged",
    "container_created",
    "runtime_started",
    "live_resolved",
    "components_deployed",
    "control_ready",
    "identity_converged",
    "location_converged",
    "keybox_converged",
    "camera_converged",
    "google_converged",
    "proxy_converged",
    "protection_converged",
    "accepted",
)
_PHASE_INDEX = {name: index for index, name in enumerate(_PHASES)}
_PLAN_KEYS = frozenset(
    {
        "schema",
        "resolution",
        "artifactTargets",
        "artifactRecords",
        "imageAction",
        "desiredImageInputSha256",
        "desiredImageBootInputSha256",
        "selectedImageRecord",
        "runtimeAction",
        "bootSeedAction",
        "recreateReasons",
        "liveObservationRequired",
        "daemonAction",
        "deployComponents",
        "identityAction",
        "locationAction",
        "proxyAction",
        "keyboxAction",
        "cameraAction",
        "googleAction",
        "protectionAction",
        "acceptanceChecks",
        "planDigest",
    }
)
_JOURNAL_KEYS = frozenset(
    {
        "schema",
        "instanceId",
        "operationId",
        "regenerationTransactionId",
        "plan",
        "planDigest",
        "phase",
        "selectedImageInputSha256",
        "selectedImageBootInputSha256",
        "protectionEngineId",
        "protectionExpectedDigest",
        "oldContainerId",
        "seedContainerId",
        "newContainerId",
        "observedDataUuid",
        "observedRootfsUuid",
        "bootSeedTarget",
        "proxyGeneration",
        "proxyEnabled",
        "proxyQuarantineRequired",
        "proxyQuarantined",
        "liveResolution",
        "completed",
        "createdAt",
        "updatedAt",
    }
)
_LIVE_RESOLUTION_KEYS = frozenset(
    {"observationSha256", "componentActions", "acceptanceChecks"}
)
_BOOT_SEED_KEYS = frozenset({"transactionId", "dataUuid", "rootfsUuid"})
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TARGET_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$")

_RESOLUTIONS = frozenset({"complete", "requires-artifacts"})
_IMAGE_ACTIONS = frozenset({"reuse-selected", "ensure-desired"})
_RUNTIME_ACTIONS = frozenset({"reuse", "start", "restart", "create", "recreate"})
_BOOT_SEED_ACTIONS = frozenset({"none", "initialize_replace"})
_DAEMON_ACTIONS = frozenset({"inspect", "reuse", "install", "reconcile"})
_DEPLOY_ACTIONS = frozenset({"inspect", "reuse", "deploy"})
_IDENTITY_ACTIONS = frozenset({"inspect", "reuse", "converge"})
_LOCATION_ACTIONS = frozenset({"inspect", "reuse", "converge", "resume", "verify"})
_PROXY_ACTIONS = frozenset({"inspect", "reuse", "reconcile", "recovery"})
_COMPONENT_ACTIONS = frozenset({"inspect", "reuse", "reconcile"})
_PROTECTION_ACTIONS = frozenset({"inspect", "reuse", "reconcile", "maintenance"})
_RECOMMENDED_ACTIONS = frozenset(
    {
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
)
_STATE_ACTION = {
    "matching": "reuse",
    "unknown": "inspect",
    "drift": "reconcile",
    "pending": "reconcile",
}
_PHASE_DEADLINES_SECONDS = {
    "runtime_started": 300.0,
    "seed_runtime_started": 300.0,
    "control_ready": 240.0,
    "proxy_converged": 300.0,
}


class ConvergenceError(RuntimeError):
    """Stable, redacted convergence failure."""

    def __init__(
        self,
        code: str,
        *,
        phase: str | None = None,
        recommended_action: str | None = None,
    ) -> None:
        self.code = _safe_code(code, "convergence_failed")
        self.phase = phase
        self.recommended_action = recommended_action or _error_recommendation(self.code)
        super().__init__(self.code)


def _error_recommendation(code: str) -> str:
    if code in {
        "daemon_seed_contract_incompatible",
        "daemon_integration_identity_drift",
        "convergence_daemon_incompatible",
    }:
        return "daemon-incompatible"
    if code in {
        "device_regeneration_legacy_pending",
        "legacy_regeneration_recovery_required",
    }:
        return "legacy-regeneration-recovery"
    if code.startswith("proxy_") or code in {
        "agent_stale",
        "data_plane_unverified",
        "engine_health_failed",
    }:
        return "proxy-recovery"
    if code in {
        "convergence_state_conflict",
        "convergence_resource_conflict",
        "resource_conflict",
        "instance_identity_mismatch",
        "storage_identity_mismatch",
        "runtime_image_cache_conflict",
    }:
        return "resource-conflict"
    return "resume"


def _safe_code(value: Any, fallback: str) -> str:
    if isinstance(value, str) and _SAFE_NAME.fullmatch(value):
        return value
    return fallback


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _thaw(value), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ConvergenceError("convergence_plan_invalid")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _require_sha256(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ConvergenceError("convergence_plan_invalid")
    return value


def _require_identifier(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ConvergenceError("convergence_state_invalid")
    return value


def _require_uuid(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ConvergenceError("convergence_state_invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ConvergenceError("convergence_state_invalid") from exc
    if str(parsed) != value.lower():
        raise ConvergenceError("convergence_state_invalid")
    return value


def _validate_action(value: Any, allowed: frozenset[str], *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or value not in allowed:
        raise ConvergenceError("convergence_plan_invalid")
    return value


def _sanitize_artifact_record(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ConvergenceError("convergence_plan_invalid")
    target = raw.get("target")
    if not isinstance(target, str) or _TARGET_NAME.fullmatch(target) is None:
        raise ConvergenceError("convergence_plan_invalid")
    record: dict[str, Any] = {"target": target}
    if "schema" in raw:
        schema = raw["schema"]
        if not isinstance(schema, str) or len(schema) > 128:
            raise ConvergenceError("convergence_plan_invalid")
        record["schema"] = schema
    record["inputSha256"] = _require_sha256(raw.get("inputSha256"))
    record["toolSha256"] = _require_sha256(raw.get("toolSha256"))
    outputs = raw.get("outputs")
    if not isinstance(outputs, Sequence) or isinstance(outputs, (str, bytes)):
        raise ConvergenceError("convergence_plan_invalid")
    clean_outputs: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for output in outputs:
        if not isinstance(output, Mapping) or set(output) != {"path", "mode", "size", "sha256"}:
            raise ConvergenceError("convergence_plan_invalid")
        path = output.get("path")
        mode = output.get("mode")
        size = output.get("size")
        valid_mode = (
            isinstance(mode, str)
            and re.fullmatch(r"0[0-7]{3,4}", mode) is not None
        ) or (
            isinstance(mode, int)
            and not isinstance(mode, bool)
            and 0 <= mode <= 0o7777
        )
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or path in seen_paths
            or not valid_mode
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise ConvergenceError("convergence_plan_invalid")
        seen_paths.add(path)
        clean_outputs.append(
            {
                "path": path,
                "mode": mode,
                "size": size,
                "sha256": _require_sha256(output.get("sha256")),
            }
        )
    record["outputs"] = sorted(clean_outputs, key=lambda item: item["path"])
    return MappingProxyType(record)


def _sanitize_selected_image_record(raw: Any) -> Mapping[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ConvergenceError("convergence_plan_invalid")
    permitted = {
        "schema",
        "inputSha256",
        "bootInputSha256",
        "imageId",
        "imageRef",
        "derivedTag",
        "architecture",
        "baseImageId",
        "artifactManifestSha256",
        "daemonSeedContractSha256",
    }
    clean: dict[str, Any] = {}
    for key in sorted(permitted.intersection(raw)):
        value = raw[key]
        if key.endswith("Sha256"):
            clean[key] = _require_sha256(value)
        elif not isinstance(value, str) or not value or len(value) > 255:
            raise ConvergenceError("convergence_plan_invalid")
        else:
            clean[key] = value
    if "inputSha256" not in clean or "bootInputSha256" not in clean:
        raise ConvergenceError("convergence_plan_invalid")
    return MappingProxyType(clean)


def _normalize_deploy_components(raw: Any) -> Mapping[str, str] | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ConvergenceError("convergence_plan_invalid")
    clean: dict[str, str] = {}
    for name, action in sorted(raw.items()):
        if not isinstance(name, str) or _TARGET_NAME.fullmatch(name) is None:
            raise ConvergenceError("convergence_plan_invalid")
        clean[name] = str(_validate_action(action, _DEPLOY_ACTIONS))
    return MappingProxyType(clean)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class ConvergencePlan:
    resolution: str
    artifact_targets: tuple[str, ...] = ()
    artifact_records: tuple[Mapping[str, Any], ...] = ()
    image_action: str = "reuse-selected"
    desired_image_input_sha256: str | None = None
    desired_image_boot_input_sha256: str | None = None
    selected_image_record: Mapping[str, Any] | None = None
    runtime_action: str = "reuse"
    boot_seed_action: str = "none"
    recreate_reasons: tuple[str, ...] = ()
    live_observation_required: bool = False
    daemon_action: str = "inspect"
    deploy_components: Mapping[str, str] | None = None
    identity_action: str | None = None
    location_action: str | None = None
    proxy_action: str | None = None
    keybox_action: str | None = None
    camera_action: str | None = None
    google_action: str | None = None
    protection_action: str | None = None
    acceptance_checks: tuple[str, ...] = ()
    plan_digest: str = ""

    @property
    def schema(self) -> str:
        return PLAN_SCHEMA

    def __post_init__(self) -> None:
        _validate_action(self.resolution, _RESOLUTIONS)
        targets: list[str] = []
        for target in self.artifact_targets:
            if not isinstance(target, str) or _TARGET_NAME.fullmatch(target) is None or target in targets:
                raise ConvergenceError("convergence_plan_invalid")
            targets.append(target)
        object.__setattr__(self, "artifact_targets", tuple(targets))
        records = tuple(_sanitize_artifact_record(record) for record in self.artifact_records)
        if len({record["target"] for record in records}) != len(records):
            raise ConvergenceError("convergence_plan_invalid")
        object.__setattr__(self, "artifact_records", records)
        object.__setattr__(
            self,
            "selected_image_record",
            _sanitize_selected_image_record(self.selected_image_record),
        )
        _validate_action(self.image_action, _IMAGE_ACTIONS)
        _require_sha256(self.desired_image_input_sha256, nullable=True)
        _require_sha256(self.desired_image_boot_input_sha256, nullable=True)
        _validate_action(self.runtime_action, _RUNTIME_ACTIONS)
        _validate_action(self.boot_seed_action, _BOOT_SEED_ACTIONS)
        reasons: list[str] = []
        for reason in self.recreate_reasons:
            safe = _safe_code(reason, "")
            if not safe or safe in reasons:
                raise ConvergenceError("convergence_plan_invalid")
            reasons.append(safe)
        object.__setattr__(self, "recreate_reasons", tuple(sorted(reasons)))
        if not isinstance(self.live_observation_required, bool):
            raise ConvergenceError("convergence_plan_invalid")
        _validate_action(self.daemon_action, _DAEMON_ACTIONS)
        object.__setattr__(
            self, "deploy_components", _normalize_deploy_components(self.deploy_components)
        )
        _validate_action(self.identity_action, _IDENTITY_ACTIONS, nullable=True)
        _validate_action(self.location_action, _LOCATION_ACTIONS, nullable=True)
        _validate_action(self.proxy_action, _PROXY_ACTIONS, nullable=True)
        _validate_action(self.keybox_action, _COMPONENT_ACTIONS, nullable=True)
        _validate_action(self.camera_action, _COMPONENT_ACTIONS, nullable=True)
        _validate_action(self.google_action, _COMPONENT_ACTIONS, nullable=True)
        _validate_action(self.protection_action, _PROTECTION_ACTIONS, nullable=True)
        checks: list[str] = []
        for check in self.acceptance_checks:
            safe = _safe_code(check, "")
            if not safe or safe in checks:
                raise ConvergenceError("convergence_plan_invalid")
            checks.append(safe)
        object.__setattr__(self, "acceptance_checks", tuple(sorted(checks)))
        calculated = _digest(self._payload())
        if self.plan_digest and self.plan_digest != calculated:
            raise ConvergenceError("convergence_plan_digest_invalid")
        object.__setattr__(self, "plan_digest", calculated)

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA,
            "resolution": self.resolution,
            "artifactTargets": list(self.artifact_targets),
            "artifactRecords": [_thaw(record) for record in self.artifact_records],
            "imageAction": self.image_action,
            "desiredImageInputSha256": self.desired_image_input_sha256,
            "desiredImageBootInputSha256": self.desired_image_boot_input_sha256,
            "selectedImageRecord": _thaw(self.selected_image_record),
            "runtimeAction": self.runtime_action,
            "bootSeedAction": self.boot_seed_action,
            "recreateReasons": list(self.recreate_reasons),
            "liveObservationRequired": self.live_observation_required,
            "daemonAction": self.daemon_action,
            "deployComponents": _thaw(self.deploy_components),
            "identityAction": self.identity_action,
            "locationAction": self.location_action,
            "proxyAction": self.proxy_action,
            "keyboxAction": self.keybox_action,
            "cameraAction": self.camera_action,
            "googleAction": self.google_action,
            "protectionAction": self.protection_action,
            "acceptanceChecks": list(self.acceptance_checks),
        }

    def to_dict(self) -> dict[str, Any]:
        return self._payload() | {"planDigest": self.plan_digest}

    as_dict = to_dict

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ConvergencePlan":
        if not isinstance(raw, Mapping) or set(raw) != _PLAN_KEYS:
            raise ConvergenceError("convergence_plan_invalid")
        return cls(
            resolution=raw["resolution"],
            artifact_targets=tuple(raw["artifactTargets"]),
            artifact_records=tuple(raw["artifactRecords"]),
            image_action=raw["imageAction"],
            desired_image_input_sha256=raw["desiredImageInputSha256"],
            desired_image_boot_input_sha256=raw["desiredImageBootInputSha256"],
            selected_image_record=raw["selectedImageRecord"],
            runtime_action=raw["runtimeAction"],
            boot_seed_action=raw["bootSeedAction"],
            recreate_reasons=tuple(raw["recreateReasons"]),
            live_observation_required=raw["liveObservationRequired"],
            daemon_action=raw["daemonAction"],
            deploy_components=raw["deployComponents"],
            identity_action=raw["identityAction"],
            location_action=raw["locationAction"],
            proxy_action=raw["proxyAction"],
            keybox_action=raw["keyboxAction"],
            camera_action=raw["cameraAction"],
            google_action=raw["googleAction"],
            protection_action=raw["protectionAction"],
            acceptance_checks=tuple(raw["acceptanceChecks"]),
            plan_digest=raw["planDigest"],
        )


def recommended_action(plan: ConvergencePlan, *, resumed: bool = False) -> str:
    if not isinstance(plan, ConvergencePlan):
        raise ConvergenceError("convergence_plan_invalid")
    if resumed:
        return "resume"
    if plan.protection_action == "maintenance":
        return "protection-maintenance"
    if plan.runtime_action == "create":
        return "create"
    if plan.runtime_action == "recreate":
        return "recreate"
    if plan.runtime_action in {"start", "restart"}:
        return "start"
    if plan.image_action == "ensure-desired":
        return "image-required"
    if plan.daemon_action == "install":
        return "daemon-only"
    if plan.deploy_components and any(
        action == "deploy" for action in plan.deploy_components.values()
    ):
        return "helper-only"
    if plan.proxy_action in {"reconcile", "recovery"}:
        return "proxy-recovery"
    return "no-op"


class ConvergenceJournal:
    """Strict, private and crash-resumable convergence mutation journal."""

    def __init__(self, owner: Any, instance_id: str | None = None) -> None:
        if isinstance(owner, (str, os.PathLike, Path)):
            state_root = Path(owner)
        else:
            context = getattr(owner, "context", None)
            state_root = getattr(context, "state_root", None) or getattr(owner, "state_root", None)
            if instance_id is None:
                instance_id = getattr(context, "instance_id", None) or getattr(owner, "instance_id", None)
            if state_root is None:
                raise ConvergenceError("convergence_state_invalid")
            state_root = Path(state_root)
        self.state_root = state_root
        self.path = state_root / JOURNAL_FILENAME
        self.instance_id = instance_id

    @classmethod
    def for_manager(cls, manager: Any) -> "ConvergenceJournal":
        return cls(manager)

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def _validate_root(self) -> None:
        try:
            info = self.state_root.lstat()
        except OSError as exc:
            raise ConvergenceError("convergence_state_invalid") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ConvergenceError("convergence_state_invalid")

    def load(self) -> dict[str, Any] | None:
        self._validate_root()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConvergenceError("convergence_state_invalid") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size <= 0
            or info.st_size > MAX_JOURNAL_BYTES
        ):
            raise ConvergenceError("convergence_state_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                payload = stream.read(MAX_JOURNAL_BYTES + 1)
        except OSError as exc:
            raise ConvergenceError("convergence_state_invalid") from exc
        if len(payload) > MAX_JOURNAL_BYTES:
            raise ConvergenceError("convergence_state_invalid")
        try:
            raw = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConvergenceError("convergence_state_invalid") from exc
        return self._validate(raw)

    def _validate(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != _JOURNAL_KEYS:
            raise ConvergenceError("convergence_state_invalid")
        if raw.get("schema") != JOURNAL_SCHEMA:
            raise ConvergenceError("convergence_state_invalid")
        instance_id = _require_uuid(raw.get("instanceId"))
        if self.instance_id is not None and instance_id != self.instance_id:
            raise ConvergenceError("convergence_state_conflict")
        operation_id = raw.get("operationId")
        regeneration_id = raw.get("regenerationTransactionId")
        if not isinstance(operation_id, str) or _HEX_32.fullmatch(operation_id) is None:
            raise ConvergenceError("convergence_state_invalid")
        if regeneration_id is not None and (
            not isinstance(regeneration_id, str) or _HEX_32.fullmatch(regeneration_id) is None
        ):
            raise ConvergenceError("convergence_state_invalid")
        plan = ConvergencePlan.from_dict(raw.get("plan"))
        if raw.get("planDigest") != plan.plan_digest:
            raise ConvergenceError("convergence_plan_digest_invalid")
        phase = raw.get("phase")
        completed = raw.get("completed")
        if phase not in _PHASE_INDEX or not isinstance(completed, list) or not completed:
            raise ConvergenceError("convergence_state_invalid")
        if any(item not in _PHASE_INDEX for item in completed) or len(set(completed)) != len(completed):
            raise ConvergenceError("convergence_state_invalid")
        indexes = [_PHASE_INDEX[item] for item in completed]
        if indexes != sorted(indexes) or completed[-1] != phase:
            raise ConvergenceError("convergence_state_invalid")
        selected_input = _require_sha256(raw.get("selectedImageInputSha256"), nullable=True)
        selected_boot = _require_sha256(raw.get("selectedImageBootInputSha256"), nullable=True)
        protection_engine_id = _require_sha256(
            raw.get("protectionEngineId"),
            nullable=False,
        )
        protection_expected = _require_sha256(
            raw.get("protectionExpectedDigest"),
            nullable=False,
        )
        old_container = _require_identifier(raw.get("oldContainerId"), nullable=True)
        seed_container = _require_identifier(raw.get("seedContainerId"), nullable=True)
        new_container = _require_identifier(raw.get("newContainerId"), nullable=True)
        if len({item for item in (old_container, seed_container, new_container) if item}) != len(
            [item for item in (old_container, seed_container, new_container) if item]
        ):
            raise ConvergenceError("convergence_state_invalid")
        observed_data = _require_uuid(raw.get("observedDataUuid"), nullable=True)
        observed_rootfs = _require_uuid(raw.get("observedRootfsUuid"), nullable=True)
        boot_seed = self._validate_boot_seed(raw.get("bootSeedTarget"))
        proxy_generation = raw.get("proxyGeneration")
        if proxy_generation is not None and (
            not isinstance(proxy_generation, int)
            or isinstance(proxy_generation, bool)
            or proxy_generation < 0
        ):
            raise ConvergenceError("convergence_state_invalid")
        proxy_enabled = raw.get("proxyEnabled")
        if proxy_enabled is not None and not isinstance(proxy_enabled, bool):
            raise ConvergenceError("convergence_state_invalid")
        if not isinstance(raw.get("proxyQuarantineRequired"), bool) or not isinstance(
            raw.get("proxyQuarantined"), bool
        ):
            raise ConvergenceError("convergence_state_invalid")
        live_resolution = self._validate_live_resolution(raw.get("liveResolution"))
        for field in ("createdAt", "updatedAt"):
            value = raw.get(field)
            if not isinstance(value, str) or not value.endswith("Z") or len(value) != 20:
                raise ConvergenceError("convergence_state_invalid")
            try:
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise ConvergenceError("convergence_state_invalid") from exc
        clean = dict(raw)
        clean["plan"] = plan.to_dict()
        clean["selectedImageInputSha256"] = selected_input
        clean["selectedImageBootInputSha256"] = selected_boot
        clean["protectionEngineId"] = protection_engine_id
        clean["protectionExpectedDigest"] = protection_expected
        clean["oldContainerId"] = old_container
        clean["seedContainerId"] = seed_container
        clean["newContainerId"] = new_container
        clean["observedDataUuid"] = observed_data
        clean["observedRootfsUuid"] = observed_rootfs
        clean["bootSeedTarget"] = boot_seed
        clean["liveResolution"] = live_resolution
        clean["completed"] = list(completed)
        return clean

    def _validate_boot_seed(self, raw: Any) -> dict[str, str] | None:
        if raw is None:
            return None
        if not isinstance(raw, Mapping) or set(raw) != _BOOT_SEED_KEYS:
            raise ConvergenceError("convergence_state_invalid")
        transaction_id = raw.get("transactionId")
        if not isinstance(transaction_id, str) or _HEX_32.fullmatch(transaction_id) is None:
            raise ConvergenceError("convergence_state_invalid")
        return {
            "transactionId": transaction_id,
            "dataUuid": str(_require_uuid(raw.get("dataUuid"))),
            "rootfsUuid": str(_require_uuid(raw.get("rootfsUuid"))),
        }

    def _validate_live_resolution(self, raw: Any) -> dict[str, Any] | None:
        if raw is None:
            return None
        if not isinstance(raw, Mapping) or set(raw) != _LIVE_RESOLUTION_KEYS:
            raise ConvergenceError("convergence_state_invalid")
        observation_sha = _require_sha256(raw.get("observationSha256"))
        actions = raw.get("componentActions")
        if not isinstance(actions, Mapping) or set(actions) != {
            "daemon",
            "deploy",
            "identity",
            "location",
            "proxy",
            "keybox",
            "camera",
            "google",
            "protection",
        }:
            raise ConvergenceError("convergence_state_invalid")
        checks = raw.get("acceptanceChecks")
        if not isinstance(checks, list) or any(
            not isinstance(check, str) or not _safe_code(check, "") for check in checks
        ):
            raise ConvergenceError("convergence_state_invalid")
        return {
            "observationSha256": observation_sha,
            "componentActions": _thaw(_freeze(actions)),
            "acceptanceChecks": list(checks),
        }

    def create(
        self,
        plan: ConvergencePlan,
        *,
        operation_id: str | None = None,
        regeneration_transaction_id: str | None = None,
        observation: Mapping[str, Any] | None = None,
        boot_seed_target: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.load() is not None:
            raise ConvergenceError("convergence_state_conflict")
        if not isinstance(plan, ConvergencePlan) or self.instance_id is None:
            raise ConvergenceError("convergence_state_invalid")
        if operation_id is None:
            operation_id = secrets.token_hex(16)
        if _HEX_32.fullmatch(operation_id) is None:
            raise ConvergenceError("convergence_state_invalid")
        if regeneration_transaction_id is not None and _HEX_32.fullmatch(
            regeneration_transaction_id
        ) is None:
            raise ConvergenceError("convergence_state_invalid")
        observation = {} if observation is None else observation
        runtime = observation.get("runtime") if isinstance(observation.get("runtime"), Mapping) else {}
        components = (
            observation.get("components") if isinstance(observation.get("components"), Mapping) else {}
        )
        proxy = components.get("proxy") if isinstance(components.get("proxy"), Mapping) else {}
        protection = (
            components.get("protection")
            if isinstance(components.get("protection"), Mapping)
            else {}
        )
        protection_observed = (
            protection.get("observed")
            if isinstance(protection.get("observed"), Mapping)
            else protection
        )
        protection_engine_id = _require_sha256(
            protection_observed.get("engineId"),
            nullable=False,
        )
        protection_expected = _require_sha256(
            protection.get("expectedDigest"),
            nullable=False,
        )
        selected_input, selected_boot = _selected_digests(plan)
        created = _now_timestamp()
        state = {
            "schema": JOURNAL_SCHEMA,
            "instanceId": self.instance_id,
            "operationId": operation_id,
            "regenerationTransactionId": regeneration_transaction_id,
            "plan": plan.to_dict(),
            "planDigest": plan.plan_digest,
            "phase": "planned",
            "selectedImageInputSha256": selected_input,
            "selectedImageBootInputSha256": selected_boot,
            "oldContainerId": runtime.get("containerId"),
            "seedContainerId": None,
            "protectionEngineId": protection_engine_id,
            "protectionExpectedDigest": protection_expected,
            "newContainerId": None,
            "observedDataUuid": runtime.get("dataUuid"),
            "observedRootfsUuid": runtime.get("rootfsUuid") or None,
            "bootSeedTarget": None if boot_seed_target is None else dict(boot_seed_target),
            "proxyGeneration": proxy.get("generation"),
            "proxyEnabled": proxy.get("enabled"),
            "proxyQuarantineRequired": proxy.get("quarantineRequired") is not False,
            "proxyQuarantined": False,
            "liveResolution": None,
            "completed": ["planned"],
            "createdAt": created,
            "updatedAt": created,
        }
        clean = self._validate(state)
        self._write(clean)
        return clean

    def advance(self, phase: str, **updates: Any) -> dict[str, Any]:
        state = self.load()
        if state is None:
            raise ConvergenceError("convergence_state_invalid")
        if phase not in _PHASE_INDEX:
            raise ConvergenceError("convergence_state_invalid")
        allowed_updates = _JOURNAL_KEYS - {
            "schema",
            "instanceId",
            "operationId",
            "regenerationTransactionId",
            "plan",
            "planDigest",
            "phase",
            "completed",
            "createdAt",
            "updatedAt",
        }
        if not set(updates).issubset(allowed_updates):
            raise ConvergenceError("convergence_state_invalid")
        if phase in state["completed"]:
            if phase != state["phase"] or any(state[key] != value for key, value in updates.items()):
                raise ConvergenceError("convergence_state_conflict")
            return state
        if _PHASE_INDEX[phase] <= _PHASE_INDEX[state["phase"]]:
            raise ConvergenceError("convergence_state_invalid")
        state.update(updates)
        state["phase"] = phase
        state["completed"] = list(state["completed"]) + [phase]
        state["updatedAt"] = _now_timestamp()
        clean = self._validate(state)
        self._write(clean)
        return clean

    def bind_runtime_id(self, field: str, container_id: str) -> dict[str, Any]:
        if field not in {"seedContainerId", "newContainerId"}:
            raise ConvergenceError("convergence_state_invalid")
        value = _require_identifier(container_id)
        state = self.load()
        if state is None:
            raise ConvergenceError("convergence_state_invalid")
        current = state.get(field)
        if current is not None:
            if current != value:
                raise ConvergenceError("convergence_state_conflict")
            return state
        state[field] = value
        state["updatedAt"] = _now_timestamp()
        clean = self._validate(state)
        self._write(clean)
        return clean

    def clear(self) -> None:
        if self.load() is None:
            return
        try:
            self.path.unlink()
            _fsync_directory(self.state_root)
        except OSError as exc:
            raise ConvergenceError("convergence_state_invalid") from exc

    def _write(self, state: Mapping[str, Any]) -> None:
        self._validate_root()
        if os.path.lexists(self.path):
            self.load()
        payload = _canonical_bytes(state) + b"\n"
        if len(payload) > MAX_JOURNAL_BYTES:
            raise ConvergenceError("convergence_state_too_large")
        descriptor = -1
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{JOURNAL_FILENAME}.", dir=self.state_root
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            temporary = None
            _fsync_directory(self.state_root)
        except OSError as exc:
            raise ConvergenceError("convergence_state_invalid") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _selected_digests(plan: ConvergencePlan) -> tuple[str | None, str | None]:
    if plan.image_action == "ensure-desired":
        return plan.desired_image_input_sha256, plan.desired_image_boot_input_sha256
    selected = plan.selected_image_record
    if selected is None:
        return plan.desired_image_input_sha256, plan.desired_image_boot_input_sha256
    return selected.get("inputSha256"), selected.get("bootInputSha256")


def _component_state(components: Mapping[str, Any], name: str) -> tuple[str, Mapping[str, Any]]:
    raw = components.get(name)
    if not isinstance(raw, Mapping):
        raise ConvergenceError("convergence_observation_invalid")
    state = raw.get("state")
    if state not in {"unknown", "matching", "drift", "pending", "incompatible", "maintenance", "recovery"}:
        raise ConvergenceError("convergence_observation_invalid")
    return str(state), raw


class ConvergencePlanner:
    def __init__(self, manager: Any, artifact_builder: Any = None) -> None:
        self.manager = manager
        self.artifact_builder = artifact_builder

    def inspect(
        self,
        skip_build: bool = False,
        *,
        observation: Mapping[str, Any] | None = None,
    ) -> ConvergencePlan:
        observation = (
            self._observe(skip_build=skip_build)
            if observation is None
            else observation
        )
        instance_id = observation.get("instanceId")
        expected_instance = getattr(getattr(self.manager, "context", None), "instance_id", None)
        if not isinstance(instance_id, str) or (expected_instance and instance_id != expected_instance):
            raise ConvergenceError("instance_identity_mismatch", recommended_action="resource-conflict")
        runtime = observation.get("runtime")
        components = observation.get("components")
        if not isinstance(runtime, Mapping) or not isinstance(components, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        runtime_state = runtime.get("state")
        if runtime_state not in {"absent", "stopped", "running"}:
            raise ConvergenceError("convergence_observation_invalid")
        for flag, code in (
            ("ownershipValid", "convergence_resource_conflict"),
            ("integrationIdentityValid", "daemon_integration_identity_drift"),
            ("storageValid", "storage_identity_mismatch"),
        ):
            if runtime.get(flag) is not True:
                recommendation = "daemon-incompatible" if flag == "integrationIdentityValid" else "resource-conflict"
                raise ConvergenceError(code, recommended_action=recommendation)

        artifact_targets = self._artifact_targets(observation)
        artifact_records = self._artifact_records(observation)
        if self.artifact_builder is not None and not artifact_targets and not artifact_records:
            try:
                snapshot = self.artifact_builder.snapshot("liveDeploy")
                artifact_records = tuple(snapshot.as_dict()["records"])
            except Exception:
                artifact_targets = ("liveDeploy",)
        resolution = "requires-artifacts" if artifact_targets else "complete"

        desired_input = observation.get("desiredImageInputSha256")
        desired_boot = observation.get("desiredImageBootInputSha256")
        if desired_input is not None:
            _require_sha256(desired_input)
        if desired_boot is not None:
            _require_sha256(desired_boot)
        selected_record = observation.get("selectedImageRecord")
        if selected_record is not None:
            selected_record = _sanitize_selected_image_record(selected_record)

        recreate_reasons: list[str] = []
        runtime_input_mismatch = False
        if runtime_state == "absent":
            runtime_action = "create"
        else:
            if runtime.get("storageMigrationRequired") is True:
                recreate_reasons.append("storage_v4_migration_required")
            for key, reason in (
                ("createSpecMatches", "runtime_create_spec_mismatch"),
                ("networkMatches", "runtime_network_mismatch"),
                ("volumeMatches", "runtime_volume_mismatch"),
            ):
                value = runtime.get(key)
                if value is False:
                    recreate_reasons.append(reason)
                elif value is not True:
                    raise ConvergenceError("convergence_observation_invalid")
            current_input = runtime.get("imageInputSha256")
            if current_input is not None:
                _require_sha256(current_input)
            runtime_input_mismatch = bool(
                desired_input is not None
                and current_input is not None
                and desired_input != current_input
            )
            current_boot = runtime.get("imageBootInputSha256")
            if current_boot is not None:
                _require_sha256(current_boot)
            if desired_boot is not None and current_boot is not None and desired_boot != current_boot:
                recreate_reasons.append("runtime_boot_image_mismatch")
            if recreate_reasons:
                runtime_action = "recreate"
            elif runtime_state == "stopped":
                runtime_action = "start"
            else:
                runtime_action = "reuse"

        daemon_state, _ = _component_state(components, "daemon")
        if daemon_state == "incompatible":
            raise ConvergenceError(
                "daemon_seed_contract_incompatible", recommended_action="daemon-incompatible"
            )
        if daemon_state == "matching":
            daemon_action = "reuse"
        elif daemon_state == "drift":
            daemon_action = "install"
        elif daemon_state == "pending":
            daemon_action = "reconcile"
        elif daemon_state == "unknown":
            daemon_action = "inspect"
        else:
            raise ConvergenceError("convergence_observation_invalid")
        if runtime_input_mismatch and runtime_state == "stopped":
            recreate_reasons.append("runtime_image_input_mismatch")
            runtime_action = "recreate"

        deploy_raw = components.get("deploy")
        if not isinstance(deploy_raw, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        deploy_components: dict[str, str] = {}
        for name, raw_state in sorted(deploy_raw.items()):
            state = raw_state.get("state") if isinstance(raw_state, Mapping) else raw_state
            if state == "incompatible":
                raise ConvergenceError("convergence_component_incompatible")
            if state == "drift" or state == "pending":
                deploy_components[str(name)] = "deploy"
            elif state == "unknown":
                deploy_components[str(name)] = "inspect"
            elif state != "matching":
                raise ConvergenceError("convergence_observation_invalid")

        identity_state, _ = _component_state(components, "identity")
        location_state, location_component = _component_state(components, "location")
        proxy_state, _ = _component_state(components, "proxy")
        keybox_state, _ = _component_state(components, "keybox")
        camera_state, _ = _component_state(components, "camera")
        google_state, _ = _component_state(components, "google")
        protection_state, protection = _component_state(components, "protection")
        for name, state in (
            ("identity", identity_state),
            ("location", location_state),
            ("proxy", proxy_state),
            ("keybox", keybox_state),
            ("camera", camera_state),
            ("google", google_state),
            ("protection", protection_state),
        ):
            if state == "incompatible":
                if name == "protection":
                    error = protection.get("error")
                    if (
                        isinstance(error, str)
                        and error.startswith("shared_protection_")
                    ):
                        raise ConvergenceError(
                            error,
                            recommended_action="protection-maintenance",
                        )
                raise ConvergenceError(f"convergence_{name}_incompatible")

        identity_action = self._simple_action(identity_state, converge="converge")
        location_action = self._simple_action(location_state, converge="converge")
        if proxy_state == "recovery":
            proxy_action = "recovery"
        else:
            proxy_action = self._simple_action(proxy_state, converge="reconcile")
        if daemon_action == "install":
            proxy_action = "reconcile"
        keybox_action = self._simple_action(keybox_state, converge="reconcile")
        camera_action = self._simple_action(camera_state, converge="reconcile")
        google_action = self._simple_action(google_state, converge="reconcile")
        protection_prestart = (
            protection_state == "maintenance"
            or protection_state == "drift"
            and runtime_state != "running"
        )
        if protection_prestart:
            if (
                protection_state == "maintenance"
                and protection.get("siblingRuntimeActive") is True
            ):
                raise ConvergenceError(
                    "shared_protection_reload_requires_maintenance",
                    recommended_action="protection-maintenance",
                )
            protection_action = "maintenance"
            if runtime_state == "running" and runtime_action == "reuse":
                runtime_action = "restart"
        else:
            protection_action = self._simple_action(
                protection_state,
                converge="reconcile",
            )

        if location_state == "pending" and runtime_state != "absent":
            if runtime_action not in {"recreate"}:
                runtime_action = "recreate"
                recreate_reasons.append("location_pending_recreate")

        location_host = location_component.get("host")
        location_pending = (
            location_host.get("pending")
            if isinstance(location_host, Mapping)
            and isinstance(location_host.get("pending"), Mapping)
            else {}
        )
        boot_seed_action = (
            "initialize_replace"
            if runtime.get("bootSeedRequired") is True
            or runtime_state == "absent"
            and location_state == "pending"
            and location_pending.get("phase") in {"new", "staged"}
            else "none"
        )
        if runtime.get("bootSeedRequired") not in {True, False}:
            raise ConvergenceError("convergence_observation_invalid")
        image_action = (
            "ensure-desired"
            if runtime_action in {"create", "recreate"} or boot_seed_action == "initialize_replace"
            else "reuse-selected"
        )
        if image_action == "ensure-desired" and resolution == "complete" and (
            desired_input is None or desired_boot is None
        ):
            raise ConvergenceError("convergence_image_input_unavailable")

        runtime_hides_live = runtime_action != "reuse"
        if runtime_hides_live:
            daemon_action = "inspect"
            deploy_value: Mapping[str, str] | None = None
            identity_action = "inspect"
            location_action = "inspect" if location_state == "unknown" else location_action
            proxy_action = "inspect"
            keybox_action = "inspect"
            camera_action = "inspect"
            google_action = "inspect"
        else:
            deploy_value = deploy_components
        if resolution == "requires-artifacts":
            daemon_action = "inspect"
            deploy_value = None
            desired_input = None
            desired_boot = None

        acceptance = observation.get("acceptanceChecks")
        if not isinstance(acceptance, Sequence) or isinstance(acceptance, (str, bytes)):
            raise ConvergenceError("convergence_observation_invalid")
        checks = tuple(str(check) for check in acceptance)
        inspect_actions = (
            daemon_action == "inspect"
            or deploy_value is None
            or any(
                action == "inspect"
                for action in (
                    identity_action,
                    location_action,
                    proxy_action,
                    keybox_action,
                    camera_action,
                    google_action,
                    protection_action,
                )
            )
        )
        return ConvergencePlan(
            resolution=resolution,
            artifact_targets=artifact_targets,
            artifact_records=artifact_records,
            image_action=image_action,
            desired_image_input_sha256=desired_input,
            desired_image_boot_input_sha256=desired_boot,
            selected_image_record=selected_record,
            runtime_action=runtime_action,
            boot_seed_action=boot_seed_action,
            recreate_reasons=tuple(recreate_reasons),
            live_observation_required=runtime_hides_live or inspect_actions,
            daemon_action=daemon_action,
            deploy_components=deploy_value,
            identity_action=identity_action,
            location_action=location_action,
            proxy_action=proxy_action,
            keybox_action=keybox_action,
            camera_action=camera_action,
            google_action=google_action,
            protection_action=protection_action,
            acceptance_checks=checks,
        )

    def input_identity_digest(self, skip_build: bool = False) -> str:
        method = getattr(
            self.manager,
            "observe_convergence_inputs",
            None,
        )
        if not callable(method):
            return _input_identity_digest(
                self.inspect(skip_build=skip_build)
            )
        observation = _call_supported(
            method,
            skip_build=skip_build,
        )
        if not isinstance(observation, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        artifact_targets = self._artifact_targets(observation)
        artifact_records = self._artifact_records(observation)
        desired_input = observation.get("desiredImageInputSha256")
        desired_boot = observation.get(
            "desiredImageBootInputSha256"
        )
        if desired_input is not None:
            _require_sha256(desired_input)
        if desired_boot is not None:
            _require_sha256(desired_boot)
        return _digest(
            {
                "artifactTargets": list(artifact_targets),
                "artifactRecords": [
                    _thaw(record)
                    for record in artifact_records
                ],
                "desiredImageInputSha256": desired_input,
                "desiredImageBootInputSha256": desired_boot,
            }
        )


    def _observe(self, *, skip_build: bool) -> Mapping[str, Any]:
        method = getattr(self.manager, "observe_convergence", None)
        if not callable(method):
            raise ConvergenceError("convergence_manager_capability_missing")
        raw = _call_supported(method, skip_build=skip_build)
        if not isinstance(raw, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        return raw

    @staticmethod
    def _artifact_targets(observation: Mapping[str, Any]) -> tuple[str, ...]:
        raw = observation.get("artifactTargets")
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise ConvergenceError("convergence_observation_invalid")
        result: list[str] = []
        for target in raw:
            if not isinstance(target, str) or _TARGET_NAME.fullmatch(target) is None or target in result:
                raise ConvergenceError("convergence_observation_invalid")
            result.append(target)
        return tuple(result)

    @staticmethod
    def _artifact_records(observation: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
        raw = observation.get("artifactRecords")
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise ConvergenceError("convergence_observation_invalid")
        return tuple(_sanitize_artifact_record(record) for record in raw)

    @staticmethod
    def _simple_action(state: str, *, converge: str) -> str:
        if state == "matching":
            return "reuse"
        if state == "unknown":
            return "inspect"
        if state in {"drift", "pending"}:
            return converge
        raise ConvergenceError("convergence_observation_invalid")


@dataclasses.dataclass(slots=True)
class _Progress:
    callback: Callable[[Mapping[str, Any]], Any] | None
    phases: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def emit(self, phase: str, state: str, started: float, detail: str) -> None:
        if state not in {"started", "running", "passed", "failed", "timed_out"}:
            return
        safe_phase = _safe_code(phase, "convergence")
        safe_detail = _safe_code(detail, "convergence")
        event = {
            "schema": PROGRESS_SCHEMA,
            "command": "up",
            "phase": safe_phase,
            "state": state,
            "durationMs": max(0, int((time.monotonic() - started) * 1000)),
            "detail": safe_detail,
        }
        if self.callback is not None:
            try:
                with self._lock:
                    self.callback(event)
            except Exception:
                pass

    def finish(self, phase: str, state: str, started: float, detail: str) -> None:
        self.emit(phase, state, started, detail)
        self.phases.append(
            {
                "phase": _safe_code(phase, "convergence"),
                "state": state,
                "durationMs": max(0, int((time.monotonic() - started) * 1000)),
                "detail": _safe_code(detail, "convergence"),
            }
        )

    def failure_recorded(self, phase: str, detail: str) -> bool:
        if not self.phases:
            return False
        latest = self.phases[-1]
        return (
            latest.get("phase") == _safe_code(phase, "convergence")
            and latest.get("state") in {"failed", "timed_out"}
            and latest.get("detail") == _safe_code(detail, "convergence")
        )

    @contextlib.contextmanager
    def heartbeat(self, phase: str, started: float, detail: str) -> Iterator[None]:
        stopped = threading.Event()

        def beat() -> None:
            while not stopped.wait(HEARTBEAT_SECONDS):
                self.emit(phase, "running", started, detail)

        thread = threading.Thread(target=beat, name="xenoid-convergence-progress", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join(timeout=0.1)


class ConvergenceExecutor:
    def __init__(
        self,
        manager: Any,
        live_acceptance: Any = None,
        artifact_builder: Any = None,
    ) -> None:
        self.manager = manager
        if artifact_builder is None:
            context = getattr(manager, "context", None)
            project_root = getattr(context, "project_root", None)
            if project_root is not None:
                from .artifacts import ArtifactBuilder

                artifact_builder = ArtifactBuilder(Path(project_root))
        self.live_acceptance = live_acceptance
        self.artifact_builder = artifact_builder
        self.planner = ConvergencePlanner(manager, artifact_builder=artifact_builder)
        self.journal = ConvergenceJournal.for_manager(manager)

    def run(
        self,
        plan: ConvergencePlan | Mapping[str, Any] | None = None,
        progress: Callable[[Mapping[str, Any]], Any] | None = None,
        skip_build: bool = False,
        dry_run: bool = False,
        regeneration_capability: Any = None,
        retain_accepted_journal: bool = False,
    ) -> dict[str, Any]:
        reporter = _Progress(progress)
        self._retain_accepted_journal = bool(retain_accepted_journal)
        resumed_hint = self.journal.exists()
        initial_phase = "resuming" if resumed_hint else "inspecting"
        command_started = time.monotonic()
        reporter.emit(initial_phase, "started", command_started, initial_phase)
        deadline: float | None = None
        result_context: dict[str, Any] = {
            "plan": None,
            "initialPlanDigest": None,
            "resolvedPlanDigest": None,
            "followUpPlanDigest": None,
            "resumed": resumed_hint,
            "dryRun": bool(dry_run),
            "before": {},
            "after": {},
        }
        try:
            deadline = self._outer_deadline()
            with self._operation_scope():
                result = self._run_locked(
                    plan=plan,
                    reporter=reporter,
                    skip_build=skip_build,
                    dry_run=dry_run,
                    regeneration_capability=regeneration_capability,
                    deadline=deadline,
                    result_context=result_context,
                    initial_phase=initial_phase,
                    command_started=command_started,
                )
            return result
        except KeyboardInterrupt:
            self._cancel("convergence_cancelled")
            self._discard_secrets()
            error = ConvergenceError("convergence_cancelled", phase=initial_phase)
            reporter.finish(initial_phase, "failed", command_started, error.code)
            return self._failure_result(error, reporter, result_context)
        except ConvergenceError as exc:
            self._discard_secrets()
            state = "timed_out" if exc.code.endswith("_timeout") else "failed"
            failed_phase = exc.phase or initial_phase
            if not reporter.failure_recorded(failed_phase, exc.code):
                reporter.finish(failed_phase, state, command_started, exc.code)
            return self._failure_result(exc, reporter, result_context)
        except Exception:
            self._discard_secrets()
            error = ConvergenceError("convergence_internal_error", phase=initial_phase)
            reporter.finish(initial_phase, "failed", command_started, error.code)
            return self._failure_result(error, reporter, result_context)

    def _run_locked(
        self,
        *,
        plan: ConvergencePlan | Mapping[str, Any] | None,
        reporter: _Progress,
        skip_build: bool,
        dry_run: bool,
        regeneration_capability: Any,
        deadline: float | None,
        result_context: dict[str, Any],
        initial_phase: str,
        command_started: float,
    ) -> dict[str, Any]:
        self._check_deadline(deadline, initial_phase)
        retained = self.journal.load()
        resumed = retained is not None
        result_context["resumed"] = resumed
        with reporter.heartbeat(initial_phase, command_started, initial_phase):
            current_observation = self._observe(skip_build=skip_build)
            if retained is not None:
                retained = self._adopt_interrupted_runtime(
                    retained,
                    current_observation,
                )
                selected_plan = ConvergencePlan.from_dict(retained["plan"])
                self._validate_resume_state(retained, current_observation)
            elif plan is None:
                selected_plan = self.planner.inspect(
                    skip_build=skip_build,
                    observation=current_observation,
                )
            elif isinstance(plan, ConvergencePlan):
                selected_plan = plan
            elif isinstance(plan, Mapping):
                selected_plan = ConvergencePlan.from_dict(plan)
            else:
                raise ConvergenceError("convergence_plan_invalid", phase=initial_phase)
        result_context["plan"] = selected_plan.to_dict()
        result_context["initialPlanDigest"] = selected_plan.plan_digest
        result_context["before"] = _observation_identity(current_observation)
        reporter.finish(initial_phase, "passed", command_started, "plan_ready")

        if dry_run:
            result_context["after"] = result_context["before"]
            return self._success_result(reporter, result_context)
        if selected_plan.resolution == "requires-artifacts":
            if retained is not None:
                raise ConvergenceError("journal_artifact_unavailable", phase="artifacts")
            if skip_build:
                raise ConvergenceError("artifact_records_stale", phase="artifacts")
            selected_plan = self._resolve_artifacts_once(
                selected_plan, reporter=reporter, deadline=deadline
            )
            result_context["resolvedPlanDigest"] = selected_plan.plan_digest
            result_context["plan"] = selected_plan.to_dict()
            current_observation = self._observe(skip_build=True)
        if selected_plan.resolution != "complete":
            raise ConvergenceError("artifact_resolution_incomplete", phase="artifacts")
        migrate_tokens = getattr(self.manager, "migrate_legacy_token_state", None)
        if callable(migrate_tokens):
            try:
                migrated = _call_supported(migrate_tokens)
            except Exception as exc:
                code = _safe_code(
                    getattr(exc, "code", None),
                    "legacy_token_state_invalid",
                )
                raise ConvergenceError(code, phase="inspecting") from exc
            if not isinstance(migrated, Mapping) or migrated.get("ok") is not True:
                raise ConvergenceError(
                    "legacy_token_state_invalid",
                    phase="inspecting",
                )


        accepted_observation = self._execute_plan(
            selected_plan,
            retained=retained,
            initial_observation=current_observation,
            reporter=reporter,
            deadline=deadline,
            regeneration_capability=regeneration_capability,
        )
        result_context["after"] = _observation_identity(accepted_observation)

        baseline_inputs = _input_identity_digest(selected_plan)
        reinspect_started = time.monotonic()
        reporter.emit("inspecting", "started", reinspect_started, "input_recheck")
        with reporter.heartbeat("inspecting", reinspect_started, "input_recheck"):
            latest_input_digest = self.planner.input_identity_digest(
                skip_build=skip_build,
            )
        reporter.finish("inspecting", "passed", reinspect_started, "input_rechecked")
        if latest_input_digest != baseline_inputs:
            latest_plan = self.planner.inspect(
                skip_build=skip_build
            )
            follow_up = latest_plan
            if follow_up.resolution == "requires-artifacts":
                if skip_build:
                    raise ConvergenceError("convergence_inputs_changed", phase="artifacts")
                follow_up = self._resolve_artifacts_once(
                    follow_up, reporter=reporter, deadline=deadline
                )
            result_context["followUpPlanDigest"] = follow_up.plan_digest
            follow_observation = self._observe(skip_build=True)
            accepted_observation = self._execute_plan(
                follow_up,
                retained=None,
                initial_observation=follow_observation,
                reporter=reporter,
                deadline=deadline,
                regeneration_capability=regeneration_capability,
            )
            result_context["plan"] = follow_up.to_dict()
            result_context["after"] = _observation_identity(accepted_observation)
            if (
                self.planner.input_identity_digest(
                    skip_build=skip_build
                )
                != _input_identity_digest(follow_up)
            ):
                raise ConvergenceError("convergence_inputs_changed", phase="inspecting")
        return self._success_result(reporter, result_context)

    def _resolve_artifacts_once(
        self,
        plan: ConvergencePlan,
        *,
        reporter: _Progress,
        deadline: float | None,
    ) -> ConvergencePlan:
        if self.artifact_builder is None:
            raise ConvergenceError("artifact_builder_unavailable", phase="artifacts")
        started = time.monotonic()
        reporter.emit("artifacts", "started", started, "artifact_resolution")
        self._check_deadline(deadline, "artifacts")
        with reporter.heartbeat("artifacts", started, "artifact_resolution"):
            result = self.artifact_builder.ensure(
                plan.artifact_targets,
                force=False,
                deadline=deadline,
            )
        if not isinstance(result, Mapping) or result.get("ok") is not True:
            reporter.finish("artifacts", "failed", started, "artifact_ensure_failed")
            raise ConvergenceError("artifact_ensure_failed", phase="artifacts")
        self._check_deadline(deadline, "artifacts")
        resolved = self.planner.inspect(skip_build=True)
        if resolved.resolution != "complete" or resolved.artifact_targets:
            reporter.finish("artifacts", "failed", started, "artifact_resolution_incomplete")
            raise ConvergenceError("artifact_resolution_incomplete", phase="artifacts")
        reporter.finish("artifacts", "passed", started, "artifacts_ready")
        return resolved

    def _execute_plan(
        self,
        plan: ConvergencePlan,
        *,
        retained: Mapping[str, Any] | None,
        initial_observation: Mapping[str, Any],
        reporter: _Progress,
        deadline: float | None,
        regeneration_capability: Any,
    ) -> Mapping[str, Any]:
        journal_state = dict(retained) if retained is not None else None
        if journal_state is not None and journal_state["planDigest"] != plan.plan_digest:
            raise ConvergenceError("convergence_state_conflict", recommended_action="resource-conflict")
        needs_journal = journal_state is not None or _plan_may_mutate(plan)
        if journal_state is None and needs_journal:
            boot_seed_target = (
                _boot_seed_target_for_plan(plan, initial_observation)
                if plan.boot_seed_action == "initialize_replace"
                else None
            )
            regeneration_id = _regeneration_transaction_id(regeneration_capability)
            legacy_evidence = (
                regeneration_capability.get("legacyEvidenceSha256")
                if isinstance(regeneration_capability, Mapping)
                else None
            )
            operation_id = (
                legacy_evidence[:32]
                if isinstance(legacy_evidence, str)
                and _SHA256.fullmatch(legacy_evidence) is not None
                else None
            )
            journal_state = self.journal.create(
                plan,
                operation_id=operation_id,
                regeneration_transaction_id=regeneration_id,
                observation=initial_observation,
                boot_seed_target=boot_seed_target,
            )
        elif journal_state is not None:
            self._validate_regeneration_capability(journal_state, regeneration_capability)
        completed = set(journal_state["completed"]) if journal_state else set()

        if journal_state is not None and "quarantined" not in completed:
            required = bool(journal_state["proxyQuarantineRequired"])
            if required:
                result = self._phase_call(
                    "quarantined",
                    "quarantine_proxy_for_lifecycle",
                    reporter,
                    deadline,
                    expected_data_uuid=journal_state["observedDataUuid"],
                    operation_id=journal_state["operationId"],
                )
                if result.get("quarantined") is False:
                    raise ConvergenceError("proxy_quarantine_failed", phase="quarantined")
            journal_state = self.journal.advance(
                "quarantined", proxyQuarantined=required
            )
            completed.add("quarantined")
            self._verify_after_phase(journal_state, skip_build=True)

        if plan.image_action == "ensure-desired" and "image_ensured" not in completed:
            result = self._phase_call(
                "image_ensured",
                "ensure_runtime_image",
                reporter,
                deadline,
                expected_input_sha256=plan.desired_image_input_sha256,
                expected_boot_input_sha256=plan.desired_image_boot_input_sha256,
            )
            image_record = result.get("selectedImageRecord", result)
            selected = _sanitize_selected_image_record(image_record)
            if selected is None or (
                selected.get("inputSha256") != plan.desired_image_input_sha256
                or selected.get("bootInputSha256") != plan.desired_image_boot_input_sha256
            ):
                raise ConvergenceError("runtime_image_identity_mismatch", phase="image_ensured")
            journal_state = self.journal.advance(
                "image_ensured",
                selectedImageInputSha256=selected["inputSha256"],
                selectedImageBootInputSha256=selected["bootInputSha256"],
            )
            completed.add("image_ensured")
            self._verify_after_phase(journal_state, skip_build=True)

        if plan.protection_action == "maintenance":
            if journal_state is None:
                raise ConvergenceError("convergence_state_invalid")
            initial_runtime = initial_observation.get("runtime")
            runtime_was_running = (
                isinstance(initial_runtime, Mapping)
                and initial_runtime.get("state") == "running"
            )
            if (
                runtime_was_running
                and "runtime_quiesced" not in completed
                and "shared_protection_maintained" not in completed
            ):
                self._phase_call(
                    "runtime_quiesced",
                    "quiesce_owned_container",
                    reporter,
                    deadline,
                    expected_container_id=_expected_runtime_id(journal_state),
                )
                journal_state = self.journal.advance("runtime_quiesced")
                completed.add("runtime_quiesced")
                self._verify_after_phase(journal_state, skip_build=True)
            if "shared_protection_maintained" not in completed:
                expected_digest = journal_state["protectionExpectedDigest"]
                self._phase_call(
                    "shared_protection_maintained",
                    "maintain_shared_protection",
                    reporter,
                    deadline,
                    expected_digest=expected_digest,
                )
                journal_state = self.journal.advance("shared_protection_maintained")
                completed.add("shared_protection_maintained")
                self._verify_after_phase(journal_state, skip_build=True)

        selected_image = _selected_image_for_execution(plan, journal_state)
        if plan.boot_seed_action == "initialize_replace":
            if journal_state is None or journal_state["bootSeedTarget"] is None:
                raise ConvergenceError("convergence_state_invalid")
            if "seed_runtime_started" not in completed:
                result = self._phase_call(
                    "seed_runtime_started",
                    "start_seed_runtime",
                    reporter,
                    deadline,
                    image_record=selected_image,
                    boot_seed_target=journal_state["bootSeedTarget"],
                    expected_data_uuid=journal_state["observedDataUuid"],
                    operation_id=journal_state["operationId"],
                )
                container_id = _result_container_id(result)
                journal_state = self.journal.advance(
                    "seed_runtime_started", seedContainerId=container_id
                )
                completed.add("seed_runtime_started")
                self._verify_after_phase(journal_state, skip_build=True)
            if "seed_initialized" not in completed:
                self._phase_call(
                    "seed_initialized",
                    "initialize_seed_runtime",
                    reporter,
                    deadline,
                    expected_container_id=journal_state["seedContainerId"],
                    boot_seed_target=journal_state["bootSeedTarget"],
                )
                journal_state = self.journal.advance("seed_initialized")
                completed.add("seed_initialized")
                self._verify_after_phase(journal_state, skip_build=True)

        remove_required = plan.runtime_action == "recreate" or plan.boot_seed_action == "initialize_replace"
        if remove_required and "container_removed" not in completed:
            if journal_state is None:
                raise ConvergenceError("convergence_state_invalid")
            expected = journal_state["seedContainerId"] or journal_state["oldContainerId"]
            self._phase_call(
                "container_removed",
                "remove_owned_container_for_recreate",
                reporter,
                deadline,
                expected_container_id=expected,
                prepare_location=plan.location_action in {"converge", "resume"},
            )
            journal_state = self.journal.advance("container_removed")
            completed.add("container_removed")
            self._verify_after_phase(journal_state, skip_build=True, allow_absent=True)

        storage_required = plan.runtime_action in {"create", "recreate"} or plan.boot_seed_action == "initialize_replace"
        if storage_required and "storage_converged" not in completed:
            if journal_state is None:
                raise ConvergenceError("convergence_state_invalid")
            expected_data_uuid = (
                journal_state["bootSeedTarget"]["dataUuid"]
                if journal_state["bootSeedTarget"] is not None
                else journal_state["observedDataUuid"]
            )
            expected_rootfs_uuid = (
                journal_state["bootSeedTarget"]["rootfsUuid"]
                if journal_state["bootSeedTarget"] is not None
                else journal_state["observedRootfsUuid"]
            )
            result = self._phase_call(
                "storage_converged",
                "converge_storage",
                reporter,
                deadline,
                boot_seed_target=journal_state["bootSeedTarget"],
                regeneration_capability=regeneration_capability,
                expected_data_uuid=expected_data_uuid,
                expected_rootfs_uuid=expected_rootfs_uuid,
            )
            data_uuid = result.get("dataUuid")
            rootfs_uuid = result.get("rootfsUuid")
            if (
                expected_data_uuid is not None
                and data_uuid != expected_data_uuid
                or expected_rootfs_uuid is not None
                and rootfs_uuid != expected_rootfs_uuid
            ):
                raise ConvergenceError(
                    "storage_identity_mismatch",
                    phase="storage_converged",
                )
            data_uuid = expected_data_uuid or data_uuid
            rootfs_uuid = expected_rootfs_uuid or rootfs_uuid
            journal_state = self.journal.advance(
                "storage_converged",
                observedDataUuid=data_uuid,
                observedRootfsUuid=rootfs_uuid,
            )
            completed.add("storage_converged")
            self._verify_after_phase(journal_state, skip_build=True, allow_absent=True)

        if plan.runtime_action in {"create", "recreate"} or plan.boot_seed_action == "initialize_replace":
            if journal_state is None:
                raise ConvergenceError("convergence_state_invalid")
            if "container_created" not in completed:
                result = self._phase_call(
                    "container_created",
                    "create_owned_container",
                    reporter,
                    deadline,
                    image_record=selected_image,
                    expected_data_uuid=journal_state["observedDataUuid"],
                    expected_rootfs_uuid=journal_state["observedRootfsUuid"],
                    adopt_stopped_only=True,
                )
                container_id = _result_container_id(result)
                quarantine = getattr(
                    self.manager,
                    "quarantine_proxy_for_lifecycle",
                    None,
                )
                if not callable(quarantine):
                    raise ConvergenceError(
                        "convergence_manager_capability_missing",
                        phase="container_created",
                    )
                quarantined = _call_supported(
                    quarantine,
                    expected_data_uuid=journal_state["observedDataUuid"],
                    operation_id=journal_state["operationId"],
                    deadline=deadline,
                    progress=reporter.callback,
                )
                if (
                    not isinstance(quarantined, Mapping)
                    or quarantined.get("ok") is not True
                    or quarantined.get("quarantined") is False
                ):
                    raise ConvergenceError(
                        _safe_code(
                            quarantined.get("error")
                            if isinstance(quarantined, Mapping)
                            else None,
                            "proxy_quarantine_failed",
                        ),
                        phase="container_created",
                    )
                journal_state = self.journal.advance(
                    "container_created",
                    newContainerId=container_id,
                    proxyQuarantined=True,
                )
                completed.add("container_created")
                self._verify_after_phase(journal_state, skip_build=True)
            if "runtime_started" not in completed:
                self._phase_call(
                    "runtime_started",
                    "start_owned_container",
                    reporter,
                    deadline,
                    expected_container_id=journal_state["newContainerId"],
                    expected_image_input_sha256=journal_state[
                        "selectedImageInputSha256"
                    ],
                    expected_image_boot_input_sha256=journal_state[
                        "selectedImageBootInputSha256"
                    ],
                    wait=True,
                )
                journal_state = self.journal.advance("runtime_started")
                completed.add("runtime_started")
                self._verify_after_phase(journal_state, skip_build=True)
        elif plan.runtime_action in {"start", "restart"}:
            expected = _expected_runtime_id(journal_state) if journal_state else initial_observation["runtime"].get("containerId")
            if journal_state is None or "runtime_started" not in completed:
                self._phase_call(
                    "runtime_started",
                    "start_owned_container",
                    reporter,
                    deadline,
                    expected_container_id=expected,
                    expected_image_input_sha256=(
                        journal_state.get("selectedImageInputSha256")
                        if journal_state
                        else None
                    ),
                    expected_image_boot_input_sha256=(
                        journal_state.get("selectedImageBootInputSha256")
                        if journal_state
                        else None
                    ),
                    wait=True,
                )
                if journal_state is not None:
                    journal_state = self.journal.advance("runtime_started")
                    completed.add("runtime_started")
                    self._verify_after_phase(journal_state, skip_build=True)

        final_actions = _plan_component_actions(plan)
        if plan.live_observation_required:
            if journal_state is not None and journal_state.get("liveResolution") is not None:
                final_actions = journal_state["liveResolution"]["componentActions"]
            elif journal_state is None or "live_resolved" not in completed:
                resolution = self._observe_live(
                    mode="convergence-resolve",
                    journal_state=journal_state,
                    plan=plan,
                    observation=initial_observation,
                    deadline=deadline,
                    reporter=reporter,
                )
                final_actions = _refine_component_actions(plan, resolution)
                live_resolution = {
                    "observationSha256": resolution["observationSha256"],
                    "componentActions": final_actions,
                    "acceptanceChecks": list(plan.acceptance_checks),
                }
                if journal_state is not None:
                    journal_state = self.journal.advance(
                        "live_resolved", liveResolution=live_resolution
                    )
                    completed.add("live_resolved")
                    self._verify_after_phase(journal_state, skip_build=True)

        _ensure_resolved_actions(final_actions)
        final_container_id = (
            _expected_runtime_id(journal_state)
            if journal_state is not None
            else initial_observation["runtime"].get("containerId")
        )
        deploy_mapping = dict(final_actions["deploy"] or {})
        deploy_required = final_actions["daemon"] == "install" or any(
            action == "deploy" for action in deploy_mapping.values()
        )
        if deploy_required and (journal_state is None or "components_deployed" not in completed):
            self._phase_call(
                "components_deployed",
                "deploy_components",
                reporter,
                deadline,
                mapping={"daemon": final_actions["daemon"], **deploy_mapping},
                artifact_records=[_thaw(record) for record in plan.artifact_records],
                expected_container_id=final_container_id,
            )
            if journal_state is not None:
                journal_state = self.journal.advance("components_deployed")
                completed.add("components_deployed")
                self._verify_after_phase(journal_state, skip_build=True)

        control_required = (
            plan.runtime_action != "reuse"
            or final_actions["daemon"] in {"install", "reconcile"}
            or deploy_required
        )
        if control_required and (journal_state is None or "control_ready" not in completed):
            self._phase_call(
                "control_ready", "reconcile_control_plane", reporter, deadline
            )
            if journal_state is not None:
                journal_state = self.journal.advance("control_ready")
                completed.add("control_ready")
                self._verify_after_phase(journal_state, skip_build=True)

        journal_state = self._component_phase(
            "identity_converged",
            "reconcile_identity",
            final_actions["identity"],
            {"action": final_actions["identity"], "regeneration_capability": regeneration_capability},
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "location_converged",
            "reconcile_location",
            final_actions["location"],
            {"action": final_actions["location"], "regeneration_capability": regeneration_capability},
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "keybox_converged",
            "reconcile_keybox",
            final_actions["keybox"],
            {"action": final_actions["keybox"]},
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "camera_converged",
            "reconcile_camera",
            final_actions["camera"],
            {"action": final_actions["camera"]},
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "google_converged",
            "reconcile_google",
            final_actions["google"],
            {
                "action": final_actions["google"],
                "fresh_bootstrap": (
                    journal_state is not None
                    and plan.runtime_action == "create"
                    and plan.boot_seed_action == "initialize_replace"
                    and journal_state.get("oldContainerId") is None
                ),
            },
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "proxy_converged",
            "reconcile_proxy_desired",
            final_actions["proxy"],
            {},
            journal_state,
            completed,
            reporter,
            deadline,
        )
        journal_state = self._component_phase(
            "protection_converged",
            "reconcile_protection",
            "reconcile" if final_actions["protection"] == "maintenance" else final_actions["protection"],
            {
                "action": final_actions["protection"],
                "expected_digest": (
                    journal_state["protectionExpectedDigest"]
                    if journal_state is not None
                    else _protection_digest(initial_observation)
                ),
            },
            journal_state,
            completed,
            reporter,
            deadline,
        )

        accepted = self._observe_live(
            mode="convergence-final",
            journal_state=journal_state,
            plan=plan,
            observation=initial_observation,
            deadline=deadline,
            reporter=reporter,
        )
        if accepted.get("ok") is not True:
            code = _safe_code(accepted.get("errorCode"), "live_acceptance_failed")
            raise ConvergenceError(code, phase="accepted")
        if journal_state is not None:
            if "accepted" not in completed:
                journal_state = self.journal.advance("accepted")
            if not getattr(self, "_retain_accepted_journal", False):
                self.journal.clear()
        accepted_observation = accepted.get("observation")
        if isinstance(accepted_observation, Mapping):
            return accepted_observation
        return self._observe(skip_build=True)

    def _component_phase(
        self,
        phase: str,
        method: str,
        action: str | None,
        kwargs: Mapping[str, Any],
        journal_state: dict[str, Any] | None,
        completed: set[str],
        reporter: _Progress,
        deadline: float | None,
    ) -> dict[str, Any] | None:
        if action in {None, "reuse"}:
            return journal_state
        if action == "inspect":
            raise ConvergenceError("convergence_live_resolution_conflict", phase=phase)
        if journal_state is not None and phase in completed:
            return journal_state
        result = self._phase_call(
            phase, method, reporter, deadline, **dict(kwargs)
        )
        if journal_state is not None:
            updates: dict[str, Any] = {}
            if phase == "proxy_converged":
                generation = result.get("generation")
                enabled = result.get("enabled")
                if (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation < 0
                    or enabled is not None
                    and not isinstance(enabled, bool)
                ):
                    raise ConvergenceError(
                        "convergence_live_resolution_conflict",
                        phase=phase,
                    )
                updates["proxyGeneration"] = generation
                if enabled is not None:
                    updates["proxyEnabled"] = enabled
            journal_state = self.journal.advance(phase, **updates)
            completed.add(phase)
            self._verify_after_phase(journal_state, skip_build=True)
        return journal_state

    def _phase_call(
        self,
        phase: str,
        method_name: str,
        reporter: _Progress,
        outer_deadline: float | None,
        **kwargs: Any,
    ) -> Mapping[str, Any]:
        started = time.monotonic()
        reporter.emit(phase, "started", started, phase)
        deadline = _shorter_deadline(outer_deadline, _PHASE_DEADLINES_SECONDS.get(phase))
        self._check_deadline(deadline, phase)
        method = getattr(self.manager, method_name, None)
        if not callable(method):
            reporter.finish(phase, "failed", started, "manager_capability_missing")
            raise ConvergenceError("convergence_manager_capability_missing", phase=phase)
        try:
            timeout_scope = (
                command_timeout(max(0.001, deadline - time.monotonic()))
                if deadline is not None
                else contextlib.nullcontext()
            )
            with timeout_scope, reporter.heartbeat(phase, started, phase):
                result = _call_supported(
                    method,
                    **kwargs,
                    deadline=deadline,
                    progress=reporter.callback,
                )
        except KeyboardInterrupt:
            raise
        except ConvergenceError:
            raise
        except Exception as exc:
            self._check_deadline(deadline, phase)
            code = _safe_code(getattr(exc, "code", None), f"{phase}_failed")
            reporter.finish(
                phase,
                "timed_out" if code.endswith("_timeout") else "failed",
                started,
                code,
            )
            raise ConvergenceError(code, phase=phase) from exc
        self._check_deadline(deadline, phase)
        if not isinstance(result, Mapping) or result.get("ok") is not True:
            code = _safe_code(
                result.get("errorCode", result.get("code", result.get("error")))
                if isinstance(result, Mapping)
                else None,
                f"{phase}_failed",
            )
            reporter.finish(
                phase,
                "timed_out" if code.endswith("_timeout") else "failed",
                started,
                code,
            )
            raise ConvergenceError(code, phase=phase)
        reporter.finish(phase, "passed", started, f"{phase}_ready")
        return result

    def _observe_live(
        self,
        *,
        mode: str,
        journal_state: Mapping[str, Any] | None,
        plan: ConvergencePlan,
        observation: Mapping[str, Any],
        deadline: float | None,
        reporter: _Progress,
    ) -> Mapping[str, Any]:
        phase = "live_resolved" if mode == "convergence-resolve" else "accepted"
        started = time.monotonic()
        reporter.emit(phase, "started", started, mode.replace("convergence-", ""))
        observer = self._acceptance_owner()
        context_method = getattr(self.manager, "acceptance_context", None)
        context = _call_supported(context_method) if callable(context_method) else self.manager
        expected = _acceptance_expected(plan, journal_state, observation)
        observe = getattr(observer, "observe", None)
        if not callable(observe):
            raise ConvergenceError("live_acceptance_unavailable", phase=phase)
        with reporter.heartbeat(phase, started, mode.replace("convergence-", "")):
            result = _call_supported(
                observe,
                context=context,
                expected=expected,
                mode=mode,
                deadline=deadline,
                progress=reporter.callback,
            )
        self._check_deadline(deadline, phase)
        if not isinstance(result, Mapping):
            reporter.finish(phase, "failed", started, "live_acceptance_invalid")
            raise ConvergenceError("live_acceptance_invalid", phase=phase)
        if mode == "convergence-resolve":
            if result.get("observationValid") is not True:
                code = _safe_code(result.get("errorCode"), "live_observation_invalid")
                reporter.finish(phase, "failed", started, code)
                raise ConvergenceError(code, phase=phase)
            observation_sha = result.get("observationSha256")
            if observation_sha is None and isinstance(result.get("observation"), Mapping):
                observation_sha = _digest(result["observation"])
            _require_sha256(observation_sha)
            actions = result.get("componentActions")
            if not isinstance(actions, Mapping):
                raise ConvergenceError("convergence_live_resolution_conflict", phase=phase)
            result = dict(result)
            result["observationSha256"] = observation_sha
            reporter.finish(phase, "passed", started, "live_observation_ready")
            return result
        if result.get("ok") is not True:
            code = _safe_code(result.get("errorCode"), "live_acceptance_failed")
            reporter.finish(phase, "failed", started, code)
            raise ConvergenceError(code, phase=phase)
        observation_sha = result.get("observationSha256")
        if observation_sha is not None:
            _require_sha256(observation_sha)
        reporter.finish(phase, "passed", started, "live_acceptance_passed")
        return result

    def _adopt_interrupted_runtime(
        self,
        journal_state: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> dict[str, Any]:
        runtime = observation.get("runtime")
        if not isinstance(runtime, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        container_id = runtime.get("containerId")
        if container_id is None:
            return dict(journal_state)
        expected = {
            journal_state.get("oldContainerId"),
            journal_state.get("seedContainerId"),
            journal_state.get("newContainerId"),
        } - {None}
        if container_id in expected:
            return dict(journal_state)
        if (
            runtime.get("state") != "stopped"
            or runtime.get("ownershipValid") is not True
            or runtime.get("integrationIdentityValid") is not True
            or runtime.get("networkMatches") is not True
            or runtime.get("volumeMatches") is not True
            or runtime.get("storageValid") is not True
            or runtime.get("createSpecMatches") is not True
            or runtime.get("imageInputSha256")
            != journal_state.get("selectedImageInputSha256")
            or runtime.get("imageBootInputSha256")
            != journal_state.get("selectedImageBootInputSha256")
        ):
            return dict(journal_state)
        boot_seed = journal_state.get("bootSeedTarget") or {}
        allowed_data = {
            journal_state.get("observedDataUuid"),
            boot_seed.get("dataUuid"),
        } - {None}
        allowed_rootfs = {
            journal_state.get("observedRootfsUuid"),
            boot_seed.get("rootfsUuid"),
        } - {None}
        if (
            runtime.get("dataUuid") not in allowed_data
            or runtime.get("rootfsUuid") not in allowed_rootfs
        ):
            return dict(journal_state)
        plan = ConvergencePlan.from_dict(journal_state["plan"])
        completed = set(journal_state.get("completed", ()))
        field: str | None = None
        if (
            plan.boot_seed_action == "initialize_replace"
            and journal_state.get("seedContainerId") is None
            and "seed_runtime_started" not in completed
            and "quarantined" in completed
            and (
                plan.image_action != "ensure-desired"
                or "image_ensured" in completed
            )
            and (
                plan.protection_action != "maintenance"
                or "shared_protection_maintained" in completed
            )
        ):
            field = "seedContainerId"
        elif (
            journal_state.get("newContainerId") is None
            and "container_created" not in completed
            and "storage_converged" in completed
            and (
                plan.runtime_action in {"create", "recreate"}
                or plan.boot_seed_action == "initialize_replace"
            )
        ):
            field = "newContainerId"
        if field is None:
            return dict(journal_state)
        return self.journal.bind_runtime_id(
            field,
            str(_require_identifier(container_id)),
        )


    def _acceptance_owner(self) -> Any:
        if self.live_acceptance is not None:
            return self.live_acceptance
        try:
            from .live_observe import LiveAcceptance
        except ImportError as exc:
            raise ConvergenceError("live_acceptance_unavailable") from exc
        self.live_acceptance = LiveAcceptance()
        return self.live_acceptance

    def _verify_after_phase(
        self,
        journal_state: Mapping[str, Any],
        *,
        skip_build: bool,
        allow_absent: bool = False,
    ) -> None:
        observation = self._observe(skip_build=skip_build)
        self._validate_resume_state(journal_state, observation, allow_absent=allow_absent)

    def _validate_resume_state(
        self,
        journal_state: Mapping[str, Any],
        observation: Mapping[str, Any],
        *,
        allow_absent: bool = False,
    ) -> None:
        runtime = observation.get("runtime")
        if not isinstance(runtime, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        for flag in ("ownershipValid", "integrationIdentityValid"):
            if runtime.get(flag) is not True:
                raise ConvergenceError(
                    "convergence_state_conflict", recommended_action="resource-conflict"
                )
        if runtime.get("storageValid") is not True:
            plan = ConvergencePlan.from_dict(journal_state["plan"])
            completed = set(journal_state.get("completed", ()))
            storage_recovery_allowed = (
                runtime.get("state") == "absent"
                and "storage_converged" not in completed
                and (
                    plan.runtime_action == "create"
                    or plan.runtime_action == "recreate"
                    and "container_removed" in completed
                    or plan.boot_seed_action == "initialize_replace"
                    and "seed_initialized" in completed
                )
            )
            if not storage_recovery_allowed:
                raise ConvergenceError(
                    "convergence_state_conflict", recommended_action="resource-conflict"
                )
        current_id = runtime.get("containerId")
        expected_ids = {
            journal_state.get("oldContainerId"),
            journal_state.get("seedContainerId"),
            journal_state.get("newContainerId"),
        } - {None}
        if current_id is not None and current_id not in expected_ids:
            raise ConvergenceError(
                "convergence_state_conflict", recommended_action="resource-conflict"
            )
        if current_id is None and not allow_absent:
            phase = journal_state.get("phase")
            plan = ConvergencePlan.from_dict(journal_state["plan"])
            completed = set(journal_state.get("completed", ()))
            removal_ready = (
                "seed_initialized" in completed
                if plan.boot_seed_action == "initialize_replace"
                else (
                    plan.runtime_action == "recreate"
                    and journal_state.get("oldContainerId") is not None
                    and "quarantined" in completed
                    and (
                        plan.image_action != "ensure-desired"
                        or "image_ensured" in completed
                    )
                    and (
                        plan.protection_action != "maintenance"
                        or "shared_protection_maintained" in completed
                    )
                )
            )
            absent_allowed = (
                phase in {"container_removed", "storage_converged"}
                or removal_ready
                or (
                    plan.runtime_action == "create"
                    and _PHASE_INDEX[str(phase)]
                    < _PHASE_INDEX["container_created"]
                )
            )
            if not absent_allowed:
                raise ConvergenceError(
                    "convergence_state_conflict", recommended_action="resource-conflict"
                )
        boot_seed = journal_state.get("bootSeedTarget") or {}
        for observed_key, journal_key, target_key in (
            ("dataUuid", "observedDataUuid", "dataUuid"),
            ("rootfsUuid", "observedRootfsUuid", "rootfsUuid"),
        ):
            current = runtime.get(observed_key) or None
            allowed = {journal_state.get(journal_key), boot_seed.get(target_key)} - {None}
            if current is not None and current not in allowed:
                raise ConvergenceError(
                    "convergence_state_conflict", recommended_action="resource-conflict"
                )
        components = observation.get("components")
        proxy = components.get("proxy") if isinstance(components, Mapping) else None
        current_generation = proxy.get("generation") if isinstance(proxy, Mapping) else None
        recorded_generation = journal_state.get("proxyGeneration")
        if current_generation is not None and recorded_generation is not None and current_generation != recorded_generation:
            raise ConvergenceError(
                "convergence_state_conflict", recommended_action="resource-conflict"
            )
        protection = (
            components.get("protection")
            if isinstance(components, Mapping)
            and isinstance(components.get("protection"), Mapping)
            else None
        )
        protection_observed = (
            protection.get("observed")
            if isinstance(protection, Mapping)
            and isinstance(protection.get("observed"), Mapping)
            else protection
        )
        if (
            not isinstance(protection, Mapping)
            or not isinstance(protection_observed, Mapping)
            or protection_observed.get("engineId")
            != journal_state.get("protectionEngineId")
            or protection.get("expectedDigest")
            != journal_state.get("protectionExpectedDigest")
        ):
            raise ConvergenceError("convergence_inputs_changed")
        if "shared_protection_maintained" in journal_state.get("completed", ()):
            if (
                protection_observed.get("ok") is not True
                or protection.get("currentDigest")
                != journal_state.get("protectionExpectedDigest")
            ):
                raise ConvergenceError(
                    "convergence_state_conflict",
                    recommended_action="protection-maintenance",
                )

    def _validate_regeneration_capability(
        self, journal_state: Mapping[str, Any], capability: Any
    ) -> None:
        journal_id = journal_state.get("regenerationTransactionId")
        supplied_id = _regeneration_transaction_id(capability)
        if journal_id != supplied_id:
            raise ConvergenceError("convergence_state_conflict")

    def _observe(self, *, skip_build: bool) -> Mapping[str, Any]:
        method = getattr(self.manager, "observe_convergence", None)
        if not callable(method):
            raise ConvergenceError("convergence_manager_capability_missing")
        result = _call_supported(method, skip_build=skip_build)
        if not isinstance(result, Mapping):
            raise ConvergenceError("convergence_observation_invalid")
        return result

    def _outer_deadline(self) -> float | None:
        raw = getattr(self.manager, "convergence_deadline", None)
        value = raw() if callable(raw) else raw
        if value is None:
            remaining = bounded_timeout(None)
            return (
                None
                if remaining is None
                else time.monotonic() + max(0.0, float(remaining))
            )
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConvergenceError("convergence_deadline_invalid")
        return float(value)

    def _check_deadline(self, deadline: float | None, phase: str) -> None:
        if deadline is not None and time.monotonic() >= deadline:
            self._cancel(f"{phase}_timeout")
            raise ConvergenceError(f"{phase}_timeout", phase=phase)

    def _cancel(self, reason: str) -> None:
        method = getattr(self.manager, "cancel_convergence", None)
        if callable(method):
            try:
                _call_supported(method, reason=_safe_code(reason, "convergence_cancelled"))
            except Exception:
                pass

    def _discard_secrets(self) -> None:
        method = getattr(self.manager, "discard_convergence_secrets", None)
        if callable(method):
            try:
                _call_supported(method)
            except Exception:
                pass

    @contextlib.contextmanager
    def _operation_scope(self) -> Iterator[None]:
        context = getattr(self.manager, "context", None)
        instance_id = getattr(context, "instance_id", None)
        state_root = getattr(context, "state_root", None)
        if instance_id and operation_lock_is_held(instance_id):
            yield
            return
        method = getattr(self.manager, "instance_operation_lock", None)
        if callable(method):
            with method():
                yield
            return
        if state_root is None:
            yield
            return
        with instance_operation_lock(Path(state_root)):
            yield

    def _success_result(
        self, reporter: _Progress, context: Mapping[str, Any]
    ) -> dict[str, Any]:
        plan_dict = context.get("plan")
        plan_obj = ConvergencePlan.from_dict(plan_dict) if isinstance(plan_dict, Mapping) else None
        return {
            "schema": RESULT_SCHEMA,
            "ok": True,
            "resumed": bool(context.get("resumed")),
            "dryRun": bool(context.get("dryRun")),
            "plan": plan_dict,
            "initialPlanDigest": context.get("initialPlanDigest"),
            "resolvedPlanDigest": context.get("resolvedPlanDigest"),
            "followUpPlanDigest": context.get("followUpPlanDigest"),
            "phases": list(reporter.phases),
            "before": dict(context.get("before", {})),
            "after": dict(context.get("after", {})),
            "nextActions": [] if plan_obj is None else [recommended_action(plan_obj, resumed=False)] if context.get("dryRun") else [],
        }

    def _failure_result(
        self,
        error: ConvergenceError,
        reporter: _Progress,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        diagnostics = _bounded_diagnostics(
            [{"phase": error.phase or "convergence", "code": error.code}]
        )
        return {
            "schema": RESULT_SCHEMA,
            "ok": False,
            "resumed": bool(context.get("resumed")),
            "dryRun": bool(context.get("dryRun")),
            "plan": context.get("plan"),
            "initialPlanDigest": context.get("initialPlanDigest"),
            "resolvedPlanDigest": context.get("resolvedPlanDigest"),
            "followUpPlanDigest": context.get("followUpPlanDigest"),
            "phases": list(reporter.phases),
            "before": dict(context.get("before", {})),
            "after": dict(context.get("after", {})),
            "nextActions": [error.recommended_action],
            "error": error.code,
            "diagnostics": diagnostics,
        }


def _call_supported(method: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(**kwargs)
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return method(**kwargs)
    supported = {key: value for key, value in kwargs.items() if key in signature.parameters}
    return method(**supported)


def _shorter_deadline(outer: float | None, seconds: float | None) -> float | None:
    inner = None if seconds is None else time.monotonic() + seconds
    if outer is None:
        return inner
    if inner is None:
        return outer
    return min(outer, inner)


def _result_container_id(result: Mapping[str, Any]) -> str:
    value = result.get("containerId")
    return str(_require_identifier(value))


def _boot_seed_target_for_plan(
    plan: ConvergencePlan,
    observation: Mapping[str, Any],
) -> dict[str, str]:
    runtime = (
        observation.get("runtime")
        if isinstance(observation.get("runtime"), Mapping)
        else {}
    )
    if runtime.get("bootSeedRequired") is True or (
        runtime.get("state") == "absent"
        and runtime.get("dataUuid") is None
        and runtime.get("rootfsUuid") is None
    ):
        return _new_boot_seed_target()
    data_uuid = _require_uuid(runtime.get("dataUuid"))
    rootfs_uuid = _require_uuid(runtime.get("rootfsUuid"))
    return {
        "transactionId": secrets.token_hex(16),
        "dataUuid": str(data_uuid),
        "rootfsUuid": str(rootfs_uuid),
    }


def _new_boot_seed_target() -> dict[str, str]:
    transaction_id = secrets.token_hex(16)
    return {
        "transactionId": transaction_id,
        "dataUuid": storage_rotation_target(transaction_id),
        "rootfsUuid": storage_rotation_target(transaction_id, rootfs=True),
    }


def _regeneration_transaction_id(capability: Any) -> str | None:
    if capability is None:
        return None
    if isinstance(capability, Mapping):
        value = capability.get("transactionId")
    else:
        value = getattr(capability, "transaction_id", None)
    if not isinstance(value, str) or _HEX_32.fullmatch(value) is None:
        raise ConvergenceError("regeneration_capability_invalid")
    return value


def _expected_runtime_id(journal_state: Mapping[str, Any] | None) -> str | None:
    if journal_state is None:
        return None
    return (
        journal_state.get("newContainerId")
        or journal_state.get("seedContainerId")
        or journal_state.get("oldContainerId")
    )


def _selected_image_for_execution(
    plan: ConvergencePlan, journal_state: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    if plan.image_action == "reuse-selected":
        return _thaw(plan.selected_image_record)
    if journal_state is None:
        raise ConvergenceError("convergence_state_invalid")
    return {
        "inputSha256": journal_state.get("selectedImageInputSha256"),
        "bootInputSha256": journal_state.get("selectedImageBootInputSha256"),
    }


def _protection_digest(observation: Mapping[str, Any]) -> str | None:
    components = observation.get("components")
    protection = components.get("protection") if isinstance(components, Mapping) else None
    value = protection.get("expectedDigest") if isinstance(protection, Mapping) else None
    if value is not None:
        _require_sha256(value)
    return value


def _plan_component_actions(plan: ConvergencePlan) -> dict[str, Any]:
    return {
        "daemon": plan.daemon_action,
        "deploy": None if plan.deploy_components is None else dict(plan.deploy_components),
        "identity": plan.identity_action,
        "location": plan.location_action,
        "proxy": plan.proxy_action,
        "keybox": plan.keybox_action,
        "camera": plan.camera_action,
        "google": plan.google_action,
        "protection": plan.protection_action,
    }


def _refine_component_actions(
    plan: ConvergencePlan, resolution: Mapping[str, Any]
) -> dict[str, Any]:
    original = _plan_component_actions(plan)
    proposed = resolution.get("componentActions")
    if not isinstance(proposed, Mapping) or set(proposed) != set(original):
        raise ConvergenceError("convergence_live_resolution_conflict")
    allowed: dict[str, frozenset[str]] = {
        "daemon": _DAEMON_ACTIONS,
        "identity": _IDENTITY_ACTIONS,
        "location": _LOCATION_ACTIONS,
        "proxy": _PROXY_ACTIONS,
        "keybox": _COMPONENT_ACTIONS,
        "camera": _COMPONENT_ACTIONS,
        "google": _COMPONENT_ACTIONS,
        "protection": _PROTECTION_ACTIONS,
    }
    final: dict[str, Any] = {}
    for name, current in original.items():
        candidate = proposed[name]
        if name == "deploy":
            candidate = _normalize_deploy_components(candidate)
            if current is not None and dict(candidate or {}) != dict(current):
                raise ConvergenceError("convergence_live_resolution_conflict")
            final[name] = None if candidate is None else dict(candidate)
            continue
        candidate = _validate_action(candidate, allowed[name], nullable=False)
        if current not in {None, "inspect"} and candidate != current:
            raise ConvergenceError("convergence_live_resolution_conflict")
        final[name] = candidate
    return final


def _ensure_resolved_actions(actions: Mapping[str, Any]) -> None:
    for name, action in actions.items():
        if name == "deploy":
            if action is None or any(value == "inspect" for value in action.values()):
                raise ConvergenceError("convergence_live_resolution_conflict")
        elif action in {None, "inspect"}:
            raise ConvergenceError("convergence_live_resolution_conflict")


def _acceptance_expected(
    plan: ConvergencePlan,
    journal_state: Mapping[str, Any] | None,
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    runtime = observation.get("runtime") if isinstance(observation.get("runtime"), Mapping) else {}
    components = observation.get("components") if isinstance(observation.get("components"), Mapping) else {}
    proxy = components.get("proxy") if isinstance(components.get("proxy"), Mapping) else {}
    selected_input, selected_boot = _selected_digests(plan)
    if journal_state is not None:
        selected_input = journal_state.get("selectedImageInputSha256") or selected_input
        selected_boot = journal_state.get("selectedImageBootInputSha256") or selected_boot
    return {
        "containerId": _expected_runtime_id(journal_state) or runtime.get("containerId"),
        "dataUuid": journal_state.get("observedDataUuid") if journal_state else runtime.get("dataUuid"),
        "rootfsUuid": journal_state.get("observedRootfsUuid") if journal_state else runtime.get("rootfsUuid"),
        "proxyGeneration": journal_state.get("proxyGeneration") if journal_state else proxy.get("generation"),
        "selectedImageInputSha256": selected_input,
        "selectedImageBootInputSha256": selected_boot,
        "protectionDigest": (
            journal_state.get("protectionExpectedDigest")
            if journal_state
            else _protection_digest(observation)
        ),
        "protectionEngineId": (
            journal_state.get("protectionEngineId")
            if journal_state
            else None
        ),
        "componentActions": _plan_component_actions(plan),
    }


def _plan_may_mutate(plan: ConvergencePlan) -> bool:
    if plan.image_action == "ensure-desired" or plan.runtime_action != "reuse":
        return True
    if plan.boot_seed_action != "none" or plan.daemon_action in {"install", "reconcile"}:
        return True
    if plan.deploy_components is None or any(
        action in {"deploy", "inspect"} for action in plan.deploy_components.values()
    ):
        return True
    return any(
        action not in {None, "reuse"}
        for action in (
            plan.identity_action,
            plan.location_action,
            plan.proxy_action,
            plan.keybox_action,
            plan.camera_action,
            plan.google_action,
            plan.protection_action,
        )
    )


def _input_identity_digest(plan: ConvergencePlan) -> str:
    return _digest(
        {
            "artifactTargets": list(plan.artifact_targets),
            "artifactRecords": [_thaw(record) for record in plan.artifact_records],
            "desiredImageInputSha256": plan.desired_image_input_sha256,
            "desiredImageBootInputSha256": plan.desired_image_boot_input_sha256,
        }
    )


def _observation_identity(observation: Mapping[str, Any]) -> dict[str, Any]:
    if "containerId" in observation:
        return {
            "containerId": observation.get("containerId"),
            "imageInputSha256": observation.get(
                "selectedImageInputSha256"
            ),
            "imageBootInputSha256": observation.get(
                "selectedImageBootInputSha256"
            ),
            "dataUuid": observation.get("dataUuid"),
            "rootfsUuid": observation.get("rootfsUuid"),
            "proxyGeneration": observation.get(
                "proxyGeneration"
            ),
            "protectionDigest": observation.get(
                "protectionDigest"
            ),
        }
    runtime = observation.get("runtime") if isinstance(observation.get("runtime"), Mapping) else {}
    components = (
        observation.get("components") if isinstance(observation.get("components"), Mapping) else {}
    )
    proxy = components.get("proxy") if isinstance(components.get("proxy"), Mapping) else {}
    protection = (
        components.get("protection")
        if isinstance(components.get("protection"), Mapping)
        else {}
    )
    return {
        "containerId": runtime.get("containerId"),
        "imageInputSha256": runtime.get("imageInputSha256"),
        "imageBootInputSha256": runtime.get("imageBootInputSha256"),
        "dataUuid": runtime.get("dataUuid"),
        "rootfsUuid": runtime.get("rootfsUuid"),
        "proxyGeneration": proxy.get("generation"),
        "protectionDigest": protection.get("currentDigest"),
    }


def _bounded_diagnostics(items: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    consumed = 2
    for item in items:
        clean = {
            "phase": _safe_code(item.get("phase"), "convergence"),
            "code": _safe_code(item.get("code"), "convergence_failed"),
        }
        encoded = _canonical_bytes(clean)
        if consumed + len(encoded) + (1 if result else 0) > MAX_DIAGNOSTIC_BYTES:
            break
        result.append(clean)
        consumed += len(encoded) + (1 if result else 0)
    return result


__all__ = [
    "ConvergenceError",
    "ConvergenceExecutor",
    "ConvergenceJournal",
    "ConvergencePlan",
    "ConvergencePlanner",
    "JOURNAL_SCHEMA",
    "PLAN_SCHEMA",
    "PROGRESS_SCHEMA",
    "RESULT_SCHEMA",
    "recommended_action",
]
