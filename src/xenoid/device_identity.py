"""Host-owned stable and boot-scoped identity for one logical Android device."""
from __future__ import annotations

import ctypes
import errno
import copy
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
import stat
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol

from .config import InstanceContext, InstanceError

IDENTITY_SCHEMA = "dev.xenoid.device-identity/v1"
STATE_FILENAME = "device-identity.json"
REGENERATE_SCHEMA = "dev.xenoid.device-regenerate/v2"
LEGACY_REGENERATE_FILENAME = "device-regenerate.json"
REGENERATE_FILENAME = "device-regenerate-v2.json"
_LEGACY_EVIDENCE_RE = re.compile(
    r"^device-regenerate-v1\.([0-9a-f]{64})\.evidence\.json$"
)
_EPOCH_DOMAIN = b"xenoid-device-epoch/v1\0"
_ANDROID_ID = re.compile(r"^[0-9a-f]{16}$")
_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,31}$")
_IMEI = re.compile(r"^[0-9]{15}$")
_IMEISV = re.compile(r"^[0-9]{2}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_EPOCH = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION = re.compile(r"^[0-9a-f]{32}$")
_STABLE_KEYS = {"androidId", "serial", "imei", "imeisv"}
_BOOT_KEYS = {"containerEpoch", "bootId", "randomUuid", "phase", "createdAt"}
_PENDING_STABLE_KEYS = {"transactionId", "beforeDigest", "target", "digest"}
_STATE_KEYS = {"schema", "instanceId", "stable", "active", "pending", "pendingStable", "updatedAt"}
_LEGACY_STATE_KEYS = _STATE_KEYS - {"pendingStable"}
_SEED_EPOCH = "0" * 64
REGENERATION_PHASES = (
    "prepared",
    "proxy_quarantined",
    "container_removed",
    "stable_committed",
    "network_committed",
    "sim_committed",
    "storage_pending",
    "storage_committed",
    "runtime_converging",
    "runtime_verified",
    "google_wiping",
    "committed",
)
GOOGLE_CLEAR_PACKAGES = (
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
)
GOOGLE_MARKER_ROOTS = ("ce", "de")
_REGENERATION_KEYS = {
    "schema",
    "instanceId",
    "transactionId",
    "phase",
    "before",
    "target",
    "legacyEvidenceSha256",
    "googleClearedPackages",
    "googleActivePackage",
    "googleMarkerRoots",
    "googlePackageArmed",
    "createdAt",
    "updatedAt",
}
_REGENERATION_BEFORE_KEYS = {
    "containerId",
    "imageId",
    "runtimeEpoch",
    "stableDigest",
    "networkEpoch",
    "simEpoch",
    "dataFilesystemUuid",
    "rootfsFilesystemUuid",
    "locationDigest",
    "proxyEnabled",
    "proxyGeneration",
    "googleBindingDigest",
}
_REGENERATION_TARGET_KEYS = {
    "stableDigest",
    "networkEpoch",
    "simEpoch",
    "storageTransactionId",
    "dataFilesystemUuid",
    "rootfsFilesystemUuid",
    "locationProfileDigest",
    "proxyGeneration",
    "googleBindingDigest",
}
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

def stable_identity_digest(stable: Mapping[str, Any]) -> str:
    clean = _validate_stable(stable)
    payload = json.dumps(
        clean,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _regeneration_text(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or value != value.strip() or pattern.fullmatch(value) is None:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration state",
        )
    return value


def _regeneration_digest(value: Any) -> str:
    return _regeneration_text(value, _EPOCH)


def _regeneration_epoch(value: Any, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    return _regeneration_text(value, _TRANSACTION)


def _regeneration_uuid(value: Any) -> str:
    return _regeneration_text(value, _UUID)


def _regeneration_generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration state",
        )
    return value


def _regeneration_timestamp(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration state",
        )
    return value


def _validate_regeneration_before(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != _REGENERATION_BEFORE_KEYS:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration before-state",
        )
    container_id = _regeneration_digest(raw["containerId"])
    image_id = raw["imageId"]
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration image identity",
        )
    proxy_enabled = raw["proxyEnabled"]
    if not isinstance(proxy_enabled, bool):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration proxy state",
        )
    return {
        "containerId": container_id,
        "imageId": image_id,
        "runtimeEpoch": _regeneration_digest(raw["runtimeEpoch"]),
        "stableDigest": _regeneration_digest(raw["stableDigest"]),
        "networkEpoch": _regeneration_epoch(raw["networkEpoch"], allow_empty=True),
        "simEpoch": _regeneration_epoch(raw["simEpoch"], allow_empty=True),
        "dataFilesystemUuid": _regeneration_uuid(raw["dataFilesystemUuid"]),
        "rootfsFilesystemUuid": _regeneration_uuid(raw["rootfsFilesystemUuid"]),
        "locationDigest": _regeneration_digest(raw["locationDigest"]),
        "proxyEnabled": proxy_enabled,
        "proxyGeneration": _regeneration_generation(raw["proxyGeneration"]),
        "googleBindingDigest": _regeneration_digest(raw["googleBindingDigest"]),
    }


def _validate_regeneration_target(
    raw: Any,
    before: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != _REGENERATION_TARGET_KEYS:
        raise IdentityError(
            "device_regeneration_state_invalid",
            "invalid device regeneration target-state",
        )
    target = {
        "stableDigest": _regeneration_digest(raw["stableDigest"]),
        "networkEpoch": _regeneration_epoch(raw["networkEpoch"]),
        "simEpoch": _regeneration_epoch(raw["simEpoch"]),
        "storageTransactionId": _regeneration_epoch(raw["storageTransactionId"]),
        "dataFilesystemUuid": _regeneration_uuid(raw["dataFilesystemUuid"]),
        "rootfsFilesystemUuid": _regeneration_uuid(raw["rootfsFilesystemUuid"]),
        "locationProfileDigest": _regeneration_digest(raw["locationProfileDigest"]),
        "proxyGeneration": _regeneration_generation(raw["proxyGeneration"]),
        "googleBindingDigest": _regeneration_digest(raw["googleBindingDigest"]),
    }
    if (
        target["stableDigest"] == before["stableDigest"]
        or target["networkEpoch"] == before["networkEpoch"]
        or target["simEpoch"] == before["simEpoch"]
        or target["dataFilesystemUuid"] == before["dataFilesystemUuid"]
        or target["rootfsFilesystemUuid"] == before["rootfsFilesystemUuid"]
        or target["proxyGeneration"] != before["proxyGeneration"]
        or target["locationProfileDigest"] == before["locationDigest"]
        or target["googleBindingDigest"] != before["googleBindingDigest"]
    ):
        raise IdentityError(
            "device_regeneration_state_invalid",
            "device regeneration target does not preserve fixed transition invariants",
        )
    return target




class RegenerationJournal:
    """Strict private journal for one exactly-once device regeneration."""

    def __init__(self, context: InstanceContext):
        self.context = context
        self.path = context.state_root / REGENERATE_FILENAME
        self.legacy_path = context.state_root / LEGACY_REGENERATE_FILENAME

    @staticmethod
    def _private_legacy_info(path: Path) -> os.stat_result:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size <= 0
            or info.st_size > 64 * 1024
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration evidence is unsafe",
            )
        return info

    def _read_legacy(self, path: Path) -> tuple[dict[str, Any], str]:
        self._private_legacy_info(path)
        try:
            payload = path.read_bytes()
            raw = json.loads(payload)
        except (OSError, ValueError, UnicodeError) as exc:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration evidence is invalid",
            ) from exc
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"schema", "instanceId", "startedAt"}
            or raw["schema"] != "dev.xenoid.device-regenerate/v1"
            or raw["instanceId"] != self.context.instance_id
            or isinstance(raw["startedAt"], bool)
            or not isinstance(raw["startedAt"], int)
            or raw["startedAt"] < 0
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration evidence is invalid",
            )
        return dict(raw), hashlib.sha256(payload).hexdigest()

    def _evidence_paths(self) -> list[tuple[Path, str]]:
        result: list[tuple[Path, str]] = []
        try:
            entries = os.scandir(self.context.state_root)
        except FileNotFoundError:
            return result
        with entries:
            for entry in entries:
                matched = _LEGACY_EVIDENCE_RE.fullmatch(entry.name)
                if matched is not None:
                    result.append(
                        (self.context.state_root / entry.name, matched.group(1))
                    )
                elif entry.name.startswith("device-regenerate-v1."):
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "unknown legacy regeneration evidence file exists",
                    )
        if len(result) > 1:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "multiple legacy regeneration evidence files exist",
            )
        return result

    def legacy_source_digest(self) -> str:
        _, digest = self._read_legacy(self.legacy_path)
        evidence = self._evidence_paths()
        if evidence:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy source and evidence both exist",
            )
        return digest

    def _validate_legacy_evidence(self, state: Mapping[str, Any]) -> None:
        source_exists = False
        try:
            self._private_legacy_info(self.legacy_path)
            source_exists = True
        except FileNotFoundError:
            pass
        evidence = self._evidence_paths()
        expected = state.get("legacyEvidenceSha256")
        if expected is None:
            if source_exists:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "unexpected legacy journal accompanies regeneration v2",
                )
            if evidence:
                evidence_path, named_digest = evidence[0]
                _, observed_digest = self._read_legacy(evidence_path)
                if observed_digest != named_digest:
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "legacy regeneration evidence digest mismatch",
                    )
            return
        expected_path = (
            self.context.state_root
            / f"device-regenerate-v1.{expected}.evidence.json"
        )
        if source_exists and evidence:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy source and evidence both exist",
            )
        if source_exists:
            _, digest = self._read_legacy(self.legacy_path)
            if digest != expected:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "legacy regeneration source digest mismatch",
                )
            return
        if len(evidence) != 1 or evidence[0][0] != expected_path:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration evidence is missing or mismatched",
            )
        _, digest = self._read_legacy(expected_path)
        if digest != expected or evidence[0][1] != expected:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration evidence digest mismatch",
            )

    @staticmethod
    def _rename_noreplace(source: Path, destination: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        source_bytes = os.fsencode(source)
        destination_bytes = os.fsencode(destination)
        if hasattr(libc, "renamex_np"):
            function = libc.renamex_np
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(source_bytes, destination_bytes, 0x00000004)
        elif hasattr(libc, "renameat2"):
            function = libc.renameat2
            function.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            function.restype = ctypes.c_int
            result = function(-100, source_bytes, -100, destination_bytes, 1)
        else:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "no no-replace rename primitive is available",
            )
        if result != 0:
            error = ctypes.get_errno()
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy evidence publication failed",
            ) from OSError(error or errno.EIO, os.strerror(error or errno.EIO))

    def finish_legacy_evidence(self) -> dict[str, Any]:
        state = self.load()
        if state is None or state["legacyEvidenceSha256"] is None:
            return state or {}
        try:
            self._private_legacy_info(self.legacy_path)
        except FileNotFoundError:
            return state
        digest = state["legacyEvidenceSha256"]
        _, observed = self._read_legacy(self.legacy_path)
        if observed != digest:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "legacy regeneration source digest mismatch",
            )
        destination = (
            self.context.state_root
            / f"device-regenerate-v1.{digest}.evidence.json"
        )
        self._rename_noreplace(self.legacy_path, destination)
        os.chmod(destination, 0o600, follow_symlinks=False)
        directory_fd = os.open(
            self.context.state_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return self.load() or {}

    def _write(self, state: Mapping[str, Any]) -> dict[str, Any]:
        clean = self.validate(state)
        root_info = self.context.state_root.lstat()
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration state directory is unsafe",
            )
        self.context.state_root.chmod(0o700)
        payload = (
            json.dumps(
                clean,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            dir=self.context.state_root,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            directory_fd = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
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

    def load(self) -> Optional[dict[str, Any]]:
        try:
            root_info = self.context.state_root.lstat()
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid != os.getuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "device regeneration state directory is unsafe",
                )
            info = self.path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size <= 0
                or info.st_size > 256 * 1024
            ):
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "device regeneration journal is unsafe",
                )
            descriptor = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    opened.st_dev != info.st_dev
                    or opened.st_ino != info.st_ino
                    or opened.st_nlink != 1
                ):
                    raise IdentityError(
                        "device_regeneration_state_invalid",
                        "device regeneration journal changed while opening",
                    )
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = json.load(stream)
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            try:
                self._read_legacy(self.legacy_path)
            except FileNotFoundError:
                evidence = self._evidence_paths()
                if evidence:
                    evidence_path, named_digest = evidence[0]
                    _, observed_digest = self._read_legacy(evidence_path)
                    if observed_digest != named_digest:
                        raise IdentityError(
                            "device_regeneration_state_invalid",
                            "legacy regeneration evidence digest mismatch",
                        )
                return None
            if self._evidence_paths():
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "legacy source and evidence both exist",
                )
            raise IdentityError(
                "device_regeneration_legacy_pending",
                "legacy regeneration requires explicit recovery",
            )
        except IdentityError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid device regeneration journal",
            ) from exc
        clean = self.validate(raw)
        self._validate_legacy_evidence(clean)
        return clean

    def pending(self) -> bool:
        return self.load() is not None

    def validate(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != _REGENERATION_KEYS:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid device regeneration journal",
            )
        if (
            raw["schema"] != REGENERATE_SCHEMA
            or raw["instanceId"] != self.context.instance_id
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal belongs to another instance",
            )
        transaction_id = _regeneration_text(raw["transactionId"], _TRANSACTION)
        phase = raw["phase"]
        if phase not in REGENERATION_PHASES:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid device regeneration phase",
            )
        before = _validate_regeneration_before(raw["before"])
        target = _validate_regeneration_target(raw["target"], before)
        legacy = raw["legacyEvidenceSha256"]
        if legacy is not None:
            legacy = _regeneration_digest(legacy)
        cleared_raw = raw["googleClearedPackages"]
        if (
            not isinstance(cleared_raw, list)
            or cleared_raw != list(GOOGLE_CLEAR_PACKAGES[: len(cleared_raw)])
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid Google package wipe progress",
            )
        active = raw["googleActivePackage"]
        if active is not None and (
            active not in GOOGLE_CLEAR_PACKAGES
            or active in cleared_raw
            or len(cleared_raw) >= len(GOOGLE_CLEAR_PACKAGES)
            or active != GOOGLE_CLEAR_PACKAGES[len(cleared_raw)]
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid active Google package wipe",
            )
        roots_raw = raw["googleMarkerRoots"]
        if (
            not isinstance(roots_raw, list)
            or any(root not in GOOGLE_MARKER_ROOTS for root in roots_raw)
            or roots_raw != [
                root for root in GOOGLE_MARKER_ROOTS if root in roots_raw
            ]
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid Google marker roots",
            )
        armed = raw["googlePackageArmed"]
        if not isinstance(armed, bool):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid Google package wipe arm state",
            )
        if active is None and (roots_raw or armed):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "Google wipe marker exists without an active package",
            )
        if active is not None and not armed and roots_raw:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "Google wipe roots were recorded before arming",
            )
        phase_index = REGENERATION_PHASES.index(phase)
        google_index = REGENERATION_PHASES.index("google_wiping")
        if phase_index < google_index and (cleared_raw or active is not None or roots_raw or armed):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "Google wipe progress precedes runtime verification",
            )
        if phase == "committed" and (
            cleared_raw not in ([], list(GOOGLE_CLEAR_PACKAGES))
            or active is not None
            or roots_raw
            or armed
        ):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "committed device regeneration has incomplete Google cleanup",
            )
        created_at = _regeneration_timestamp(raw["createdAt"])
        updated_at = _regeneration_timestamp(raw["updatedAt"])
        if updated_at < created_at:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration timestamps are not monotonic",
            )
        return {
            "schema": REGENERATE_SCHEMA,
            "instanceId": self.context.instance_id,
            "transactionId": transaction_id,
            "phase": phase,
            "before": before,
            "target": target,
            "legacyEvidenceSha256": legacy,
            "googleClearedPackages": list(cleared_raw),
            "googleActivePackage": active,
            "googleMarkerRoots": list(roots_raw),
            "googlePackageArmed": armed,
            "createdAt": created_at,
            "updatedAt": updated_at,
        }

    def prepare(
        self,
        transaction_id: str,
        before: Mapping[str, Any],
        target: Mapping[str, Any],
        *,
        legacy_evidence_sha256: Optional[str] = None,
        legacy_restart: bool = False,
    ) -> dict[str, Any]:
        if legacy_restart:
            if legacy_evidence_sha256 is None:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "legacy restart requires evidence digest",
                )
            observed = self.legacy_source_digest()
            if observed != legacy_evidence_sha256:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "legacy regeneration source digest mismatch",
                )
            try:
                self.path.lstat()
            except FileNotFoundError:
                pass
            else:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "device regeneration journal already exists",
                )
        elif self.load() is not None:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal already exists",
            )
        transaction = _regeneration_text(transaction_id, _TRANSACTION)
        now = _now()
        return self._write(
            {
                "schema": REGENERATE_SCHEMA,
                "instanceId": self.context.instance_id,
                "transactionId": transaction,
                "phase": "prepared",
                "before": dict(before),
                "target": dict(target),
                "legacyEvidenceSha256": legacy_evidence_sha256,
                "googleClearedPackages": [],
                "googleActivePackage": None,
                "googleMarkerRoots": [],
                "googlePackageArmed": False,
                "createdAt": now,
                "updatedAt": now,
            }
        )

    def advance(self, phase: str, **updates: Any) -> dict[str, Any]:
        state = self.load()
        if state is None:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal is missing",
            )
        if phase not in REGENERATION_PHASES:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid device regeneration phase",
            )
        current = REGENERATION_PHASES.index(state["phase"])
        target = REGENERATION_PHASES.index(phase)
        if target not in {current, current + 1}:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration phase transition is not monotonic",
            )
        unknown = set(updates) - _REGENERATION_KEYS
        if unknown or {"schema", "instanceId", "transactionId", "before", "target", "createdAt"} & set(updates):
            raise IdentityError(
                "device_regeneration_state_invalid",
                "invalid device regeneration journal update",
            )
        return self._write(
            {
                **state,
                **updates,
                "phase": phase,
                "updatedAt": _now(),
            }
        )

    def capability(self) -> dict[str, str]:
        state = self.load()
        if state is None:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal is missing",
            )
        return {"transactionId": state["transactionId"]}

    def require_capability(self, capability: Any) -> dict[str, Any]:
        state = self.load()
        if state is None:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal is missing",
            )
        transaction = (
            capability.get("transactionId")
            if isinstance(capability, Mapping)
            else getattr(capability, "transaction_id", None)
        )
        if transaction != state["transactionId"]:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration capability does not match the journal",
            )
        return state

    def clear(self) -> None:
        state = self.load()
        if state is None:
            return
        if state["phase"] != "committed":
            raise IdentityError(
                "device_regeneration_state_invalid",
                "device regeneration journal cannot be cleared before commit",
            )
        self.path.unlink()
        directory_fd = os.open(
            self.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

def _validate_pending_stable(raw: Any) -> Optional[dict[str, Any]]:
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or set(raw) != _PENDING_STABLE_KEYS:
        raise IdentityError(
            "device_identity_state_invalid",
            "invalid pending stable device identity",
        )
    transaction_id = _regeneration_text(raw["transactionId"], _TRANSACTION)
    before_digest = _regeneration_digest(raw["beforeDigest"])
    target = _validate_stable(raw["target"])
    digest = _regeneration_digest(raw["digest"])
    if stable_identity_digest(target) != digest or digest == before_digest:
        raise IdentityError(
            "device_identity_state_invalid",
            "pending stable identity digest mismatch",
        )
    return {
        "transactionId": transaction_id,
        "beforeDigest": before_digest,
        "target": target,
        "digest": digest,
    }




class DeviceIdentityStore:
    """Strict 0600 owner for stable and per-container Android identity."""

    def __init__(self, context: InstanceContext):
        self.context = context
        self.path = context.state_root / STATE_FILENAME

    def load(self) -> Optional[dict[str, Any]]:
        try:
            info = self.path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise IdentityError("device_identity_state_permissions", "device identity permissions are unsafe")
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = json.load(stream)
            finally:
                os.close(descriptor)
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
        if (
            not isinstance(raw, Mapping)
            or set(raw) != _STATE_KEYS
            and set(raw) != _LEGACY_STATE_KEYS
        ):
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
        stable = _validate_stable(raw["stable"])
        pending_stable = _validate_pending_stable(raw.get("pendingStable"))
        if pending_stable is not None:
            current_digest = stable_identity_digest(stable)
            if current_digest not in {
                pending_stable["beforeDigest"],
                pending_stable["digest"],
            }:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "stable identity matches neither regeneration before nor target",
                )
        return {
            "schema": IDENTITY_SCHEMA,
            "instanceId": self.context.instance_id,
            "stable": stable,
            "active": active,
            "pending": pending,
            "pendingStable": pending_stable,
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
            "pendingStable": None,
            "updatedAt": now,
        })

    def rotate_stable(self) -> dict[str, Any]:
        state = self.load()
        if state is None:
            state = self.initialize()
        if state["pendingStable"] is not None:
            raise IdentityError(
                "device_regeneration_pending",
                "stable identity is owned by an active regeneration transaction",
            )
        return self.save({
            **state,
            "stable": _generate_stable(),
            "active": None,
            "pending": None,
            "updatedAt": _now(),
        })

    def prepare_regeneration_stable(
        self,
        transaction_id: str,
        target: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        transaction = _regeneration_text(transaction_id, _TRANSACTION)
        state = self.load()
        if state is None:
            state = self.initialize()
        pending = state["pendingStable"]
        if pending is not None:
            if pending["transactionId"] != transaction:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "another stable-identity regeneration target is pending",
                )
            return state
        before_digest = stable_identity_digest(state["stable"])
        generated = _validate_stable(target) if target is not None else _generate_stable()
        digest = stable_identity_digest(generated)
        while digest == before_digest:
            if target is not None:
                raise IdentityError(
                    "device_regeneration_state_invalid",
                    "stable regeneration target matches the active identity",
                )
            generated = _generate_stable()
            digest = stable_identity_digest(generated)
        pending = {
            "transactionId": transaction,
            "beforeDigest": before_digest,
            "target": generated,
            "digest": digest,
        }
        return self.save(
            {
                **state,
                "pendingStable": pending,
                "updatedAt": _now(),
            }
        )

    def commit_regeneration_stable(self, transaction_id: str) -> dict[str, Any]:
        transaction = _regeneration_text(transaction_id, _TRANSACTION)
        state = self.load()
        pending = state.get("pendingStable") if state is not None else None
        if not isinstance(pending, Mapping) or pending.get("transactionId") != transaction:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable regeneration target is missing or mismatched",
            )
        current = stable_identity_digest(state["stable"])
        if current == pending["digest"]:
            return state
        if current != pending["beforeDigest"]:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable identity matches neither regeneration before nor target",
            )
        return self.save(
            {
                **state,
                "stable": pending["target"],
                "updatedAt": _now(),
            }
        )

    def clear_regeneration_stable(self, transaction_id: str) -> dict[str, Any]:
        transaction = _regeneration_text(transaction_id, _TRANSACTION)
        state = self.load()
        pending = state.get("pendingStable") if state is not None else None
        if not isinstance(pending, Mapping) or pending.get("transactionId") != transaction:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable regeneration target is missing or mismatched",
            )
        if stable_identity_digest(state["stable"]) != pending["digest"]:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "stable regeneration target is not committed",
            )
        return self.save(
            {
                **state,
                "pendingStable": None,
                "updatedAt": _now(),
            }
        )

    def recover_orphaned_regeneration_stable(self) -> bool:
        state = self.load()
        pending = state.get("pendingStable") if state is not None else None
        if not isinstance(pending, Mapping):
            return False
        current = stable_identity_digest(state["stable"])
        if current != pending["beforeDigest"]:
            raise IdentityError(
                "device_regeneration_state_invalid",
                "orphaned stable target cannot be discarded after mutation",
            )
        self.save(
            {
                **state,
                "pendingStable": None,
                "updatedAt": _now(),
            }
        )
        return True

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
        pending = state["pending"]
        if (
            isinstance(pending, Mapping)
            and pending.get("containerEpoch") == _SEED_EPOCH
        ):
            return pending
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
        if state["pendingStable"] is not None:
            raise IdentityError(
                "device_regeneration_pending",
                "identity mutation is blocked by active regeneration",
            )
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
