"""Host-owned stable and boot-scoped identity for one logical Android device."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol

from .config import InstanceContext, InstanceError

IDENTITY_SCHEMA = "dev.xenoid.device-identity/v1"
STATE_FILENAME = "device-identity.json"
REGENERATE_SCHEMA = "dev.xenoid.device-regenerate/v1"
REGENERATE_FILENAME = "device-regenerate.json"
_EPOCH_DOMAIN = b"xenoid-device-epoch/v1\0"
_ANDROID_ID = re.compile(r"^[0-9a-f]{16}$")
_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,31}$")
_IMEI = re.compile(r"^[0-9]{15}$")
_IMEISV = re.compile(r"^[0-9]{2}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_EPOCH = re.compile(r"^[0-9a-f]{64}$")
_STABLE_KEYS = {"androidId", "serial", "imei", "imeisv"}
_BOOT_KEYS = {"containerEpoch", "bootId", "randomUuid", "phase", "createdAt"}
_STATE_KEYS = {"schema", "instanceId", "stable", "active", "pending", "updatedAt"}
_SEED_EPOCH = "0" * 64
_FIELD_MAP = {
    "android_id": "androidId",
    "settings.secure.android_id": "androidId",
    "serial": "serial",
    "ro.serialno": "serial",
    "ro.boot.serialno": "serial",
    "imei": "imei",
    "radio.imei": "imei",
    "persist.xenoid.radio.imei": "imei",
    "imeisv": "imeisv",
    "radio.imeisv": "imeisv",
    "persist.xenoid.radio.imeisv": "imeisv",
    "boot_id": "bootId",
    "random_uuid": "randomUuid",
}


class IdentityError(InstanceError):
    """Stable, secret-free identity failure."""


class IdentityRuntime(Protocol):
    def location_runtime_container_id(self) -> Optional[str]: ...
    def collect_persisted_device_identity(self) -> dict[str, Any]: ...


class FingerprintClient(Protocol):
    def apply_fingerprint(self, profile: dict[str, Any], regenerate_unique: bool = True) -> dict[str, Any]: ...


def _now() -> int:
    return int(time.time())


def _uuid4() -> str:
    raw = bytearray(secrets.token_bytes(16))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    text = raw.hex()
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"


def _imei_check_digit(first_fourteen: str) -> str:
    total = 0
    for index, character in enumerate(first_fourteen):
        digit = int(character)
        if index % 2 == 1:
            digit *= 2
            digit = digit // 10 + digit % 10
        total += digit
    return str((10 - total % 10) % 10)


def _valid_imei(value: str) -> bool:
    return bool(_IMEI.fullmatch(value)) and _imei_check_digit(value[:14]) == value[14]


_IMEI_TAC = "35180461"  # Google Pixel 6 Pro (G8V0U) Type Allocation Code


def _generate_stable() -> dict[str, str]:
    # TAC is a same-model constant; only the 6-digit serial section rotates.
    first_fourteen = _IMEI_TAC + "".join(
        str(secrets.randbelow(10)) for _ in range(6)
    )
    return {
        "androidId": secrets.token_hex(8),
        "serial": secrets.token_hex(8).upper(),
        "imei": first_fourteen + _imei_check_digit(first_fourteen),
        "imeisv": "01",
    }


def container_epoch(container_id: str) -> str:
    if not isinstance(container_id, str) or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise IdentityError("device_identity_runtime_invalid", "owned container identity is invalid")
    return hashlib.sha256(_EPOCH_DOMAIN + container_id.encode("ascii")).hexdigest()


def identity_field_key(field: str) -> Optional[str]:
    return _FIELD_MAP.get(field)


def validate_identity_value(key: str, value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise IdentityError("device_identity_value_invalid", "invalid device identity value")
    if key == "androidId" and _ANDROID_ID.fullmatch(value.lower()):
        return value.lower()
    if key == "serial" and _SERIAL.fullmatch(value):
        return value
    if key == "imei" and _valid_imei(value):
        return value
    if key == "imeisv" and _IMEISV.fullmatch(value):
        return value
    if key in {"bootId", "randomUuid"} and _UUID.fullmatch(value.lower()):
        return value.lower()
    raise IdentityError("device_identity_value_invalid", "invalid device identity value")


def _validate_stable(raw: Any) -> dict[str, str]:
    if not isinstance(raw, Mapping) or set(raw) != _STABLE_KEYS:
        raise IdentityError("device_identity_state_invalid", "invalid stable device identity")
    return {key: validate_identity_value(key, raw[key]) for key in sorted(_STABLE_KEYS)}


def _validate_boot(raw: Any, expected_phase: str) -> Optional[dict[str, Any]]:
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or set(raw) != _BOOT_KEYS:
        raise IdentityError("device_identity_state_invalid", "invalid boot-scoped device identity")
    epoch = raw["containerEpoch"]
    created = raw["createdAt"]
    if not isinstance(epoch, str) or _EPOCH.fullmatch(epoch) is None:
        raise IdentityError("device_identity_state_invalid", "invalid device identity epoch")
    if raw["phase"] != expected_phase:
        raise IdentityError("device_identity_state_invalid", "invalid device identity phase")
    if isinstance(created, bool) or not isinstance(created, int) or created < 0:
        raise IdentityError("device_identity_state_invalid", "invalid device identity timestamp")
    return {
        "containerEpoch": epoch,
        "bootId": validate_identity_value("bootId", raw["bootId"]),
        "randomUuid": validate_identity_value("randomUuid", raw["randomUuid"]),
        "phase": expected_phase,
        "createdAt": created,
    }


class RegenerationJournal:
    """Crash journal for an in-flight `device regenerate`.

    Marked before the first mutation and cleared only after the storage
    identity commits. While present, runtime startup fails closed with
    `device_regeneration_pending` so an interrupted regenerate can never
    silently converge into a half-rotated device; re-running
    `device regenerate` resumes and completes it.
    """

    def __init__(self, context: InstanceContext):
        self.context = context
        self.path = context.state_root / REGENERATE_FILENAME

    def pending(self) -> bool:
        return self.path.is_file()

    def mark(self) -> None:
        self.context.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.context.state_root.chmod(0o700)
        payload = (
            json.dumps(
                {
                    "schema": REGENERATE_SCHEMA,
                    "instanceId": self.context.instance_id,
                    "startedAt": _now(),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.context.state_root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return
        directory_fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


class DeviceIdentityStore:
    """Strict 0600 owner for stable and per-container Android identity."""

    def __init__(self, context: InstanceContext):
        self.context = context
        self.path = context.state_root / STATE_FILENAME

    def load(self) -> Optional[dict[str, Any]]:
        try:
            info = self.path.lstat()
            if not self.path.is_file() or info.st_mode & 0o077:
                raise IdentityError("device_identity_state_permissions", "device identity permissions are unsafe")
            with self.path.open("rb") as stream:
                raw = json.load(stream)
        except FileNotFoundError:
            return None
        except IdentityError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise IdentityError("device_identity_state_invalid", "invalid device identity state") from exc
        return self.validate(raw)

    def save(self, state: Mapping[str, Any]) -> dict[str, Any]:
        clean = self.validate(state)
        self.context.state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.context.state_root.chmod(0o700)
        payload = (json.dumps(clean, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.context.state_root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return clean

    def validate(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != _STATE_KEYS:
            raise IdentityError("device_identity_state_invalid", "invalid device identity state")
        if raw["schema"] != IDENTITY_SCHEMA or raw["instanceId"] != self.context.instance_id:
            raise IdentityError("device_identity_mismatch", "device identity belongs to another instance")
        updated = raw["updatedAt"]
        if isinstance(updated, bool) or not isinstance(updated, int) or updated < 0:
            raise IdentityError("device_identity_state_invalid", "invalid device identity timestamp")
        active = _validate_boot(raw["active"], "applied")
        pending = _validate_boot(raw["pending"], "pending")
        if active is not None and pending is not None and active["containerEpoch"] == pending["containerEpoch"]:
            raise IdentityError("device_identity_state_invalid", "duplicate active and pending device epoch")
        return {
            "schema": IDENTITY_SCHEMA,
            "instanceId": self.context.instance_id,
            "stable": _validate_stable(raw["stable"]),
            "active": active,
            "pending": pending,
            "updatedAt": updated,
        }

    def initialize(self, candidates: Optional[Mapping[str, Any]] = None) -> dict[str, Any]:
        existing = self.load()
        if existing is not None:
            return existing
        stable = _generate_stable()
        candidate_values = dict(candidates or {})
        for external, internal in _FIELD_MAP.items():
            if internal not in _STABLE_KEYS or external not in candidate_values:
                continue
            try:
                stable[internal] = validate_identity_value(internal, candidate_values[external])
            except IdentityError:
                continue
        for internal in _STABLE_KEYS:
            if internal not in candidate_values:
                continue
            try:
                stable[internal] = validate_identity_value(internal, candidate_values[internal])
            except IdentityError:
                continue
        now = _now()
        return self.save({
            "schema": IDENTITY_SCHEMA,
            "instanceId": self.context.instance_id,
            "stable": stable,
            "active": None,
            "pending": None,
            "updatedAt": now,
        })

    def rotate_stable(self) -> dict[str, Any]:
        state = self.load()
        if state is None:
            state = self.initialize()
        return self.save({
            **state,
            "stable": _generate_stable(),
            "active": None,
            "pending": None,
            "updatedAt": _now(),
        })

    def prepare_epoch(self, container_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        state = self.load()
        if state is None:
            raise IdentityError("device_identity_not_initialized", "device identity is not initialized")
        epoch = container_epoch(container_id)
        pending = state["pending"]
        active = state["active"]
        if pending is not None and pending["containerEpoch"] == epoch:
            return state, pending
        if pending is not None and pending["containerEpoch"] == _SEED_EPOCH:
            # Offline-seeded values bind to the first epoch they converge into,
            # so the values written into the data image before boot match the
            # ones applied after it.
            boot = {**pending, "containerEpoch": epoch}
            state = self.save({**state, "pending": boot, "updatedAt": _now()})
            return state, state["pending"]
        if active is not None and active["containerEpoch"] == epoch:
            return state, active
        boot = {
            "containerEpoch": epoch,
            "bootId": _uuid4(),
            "randomUuid": _uuid4(),
            "phase": "pending",
            "createdAt": _now(),
        }
        state = self.save({**state, "pending": boot, "updatedAt": _now()})
        return state, state["pending"]

    def seed_next_boot(self) -> dict[str, Any]:
        """Pre-seed the boot-scoped values the next new container epoch will use.

        `start()` calls this on every container creation and writes the values
        into the offline data image before first boot, so the zygote boot
        snapshot and the post-boot live apply agree.
        """
        state = self.load()
        if state is None:
            raise IdentityError("device_identity_not_initialized", "device identity is not initialized")
        boot = {
            "containerEpoch": _SEED_EPOCH,
            "bootId": _uuid4(),
            "randomUuid": _uuid4(),
            "phase": "pending",
            "createdAt": _now(),
        }
        state = self.save({**state, "pending": boot, "updatedAt": _now()})
        return state["pending"]

    def mark_applied(self, epoch: str) -> dict[str, Any]:
        state = self.load()
        if state is None or state["pending"] is None or state["pending"]["containerEpoch"] != epoch:
            if state is not None and state["active"] is not None and state["active"]["containerEpoch"] == epoch:
                return state
            raise IdentityError("device_identity_epoch_mismatch", "device identity epoch changed before commit")
        active = {**state["pending"], "phase": "applied"}
        return self.save({**state, "active": active, "pending": None, "updatedAt": _now()})

    def update_field(self, field: str, value: Any) -> dict[str, Any]:
        key = identity_field_key(field)
        if key is None:
            raise IdentityError("device_identity_field_not_owned", "field is not owned by instance identity")
        normalized = validate_identity_value(key, value)
        state = self.load()
        if state is None:
            state = self.initialize()
        if key in _STABLE_KEYS:
            state = {**state, "stable": {**state["stable"], key: normalized}}
        else:
            selected = "pending" if state["pending"] is not None else "active"
            if state[selected] is None:
                raise IdentityError("device_identity_epoch_missing", "boot-scoped identity has no active epoch")
            state = {**state, selected: {**state[selected], key: normalized}}
        return self.save({**state, "updatedAt": _now()})


def materialize_profile(profile: Mapping[str, Any], state: Mapping[str, Any], boot: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise IdentityError("device_profile_invalid", "device profile must be an object")
    effective = copy.deepcopy(dict(profile))
    ids = effective.get("ids")
    if ids is not None and not isinstance(ids, dict):
        raise IdentityError("device_profile_invalid", "device profile ids must be an object")
    effective["ids"] = {
        **(ids or {}),
        "android_id": state["stable"]["androidId"],
        "serial": state["stable"]["serial"],
        "imei": state["stable"]["imei"],
        "imeisv": state["stable"]["imeisv"],
        "boot_id": boot["bootId"],
        "random_uuid": boot["randomUuid"],
    }
    usb = effective.get("usb")
    if usb is not None:
        if not isinstance(usb, dict):
            raise IdentityError("device_profile_invalid", "device profile usb must be an object")
        usb["serial"] = state["stable"]["serial"]
    return effective


def public_identity_state(state: Mapping[str, Any]) -> dict[str, Any]:
    stable = state["stable"]
    selected = state["pending"] or state["active"]
    return {
        "initialized": True,
        "androidId": stable["androidId"],
        "serial": stable["serial"],
        "imei": "*" * 11 + stable["imei"][-4:],
        "imeisv": stable["imeisv"],
        "containerEpoch": selected["containerEpoch"] if selected else None,
        "phase": selected["phase"] if selected else None,
    }


def converge_instance_identity(
    context: InstanceContext,
    runtime: IdentityRuntime,
    client: FingerprintClient,
    profile: Mapping[str, Any],
    *,
    rotate_stable: bool = False,
) -> dict[str, Any]:
    store = DeviceIdentityStore(context)
    state = store.load()
    adopted = False
    if state is None:
        candidates = runtime.collect_persisted_device_identity()
        state = store.initialize(candidates)
        adopted = any(
            key in candidates and candidates[key]
            for key in ("androidId", "android_id", "serial", "imei", "imeisv")
        )
    if rotate_stable:
        state = store.rotate_stable()
    container_id = runtime.location_runtime_container_id()
    if not container_id:
        raise IdentityError("device_identity_runtime_invalid", "owned Android container is not running")
    state, boot = store.prepare_epoch(container_id)
    effective = materialize_profile(profile, state, boot)
    result = client.apply_fingerprint(effective, regenerate_unique=False)
    if not isinstance(result, dict) or result.get("ok") is not True:
        return {
            "ok": False,
            "error": "device_identity_apply_failed",
            "identity": public_identity_state(state),
            "apply": result,
        }
    committed = store.mark_applied(boot["containerEpoch"])
    return {
        "ok": True,
        "adopted": adopted,
        "rotated": rotate_stable,
        "identity": public_identity_state(committed),
        "apply": result,
    }
