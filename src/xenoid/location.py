"""Explicit, proxy-independent location identity state for one instance.

The host state file is the only owner of the instance's location transaction.
It stores one master seed, a cache of per-country deterministic profiles, the
active country, and at most one pending country transaction.  A pending
transaction is staged into the Android daemon, armed with the runtime epoch
derived from the owned container ID, applied through exactly one container
recreate, verified, and only then promoted.  Crashes at any point resume the
same pending profile without generating a new identity and without restarting
a container epoch that already changed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from .cellular import (
    CellularError,
    dataset_countries,
    dataset_version,
    generate_cellular_profile,
    mask_secret,
    masked_profile_summary,
    validate_profile,
)

LOCATION_SCHEMA = "dev.xenoid.location-state/v2"
_V1_LOCATION_SCHEMA = "dev.xenoid.location-state/v1"
STAGE_SCHEMA = "dev.xenoid.location-stage/v1"
DEFAULT_COUNTRY = "SG"
STATE_FILENAME = "location-identity.json"
LEGACY_STATE_FILENAME = "regional-identity.json"
_SEED_DOMAIN = "xenoid-location-profile/v1:"
_SEED_DOMAIN_EPOCH = "xenoid-location-profile/v2:"
_EPOCH_DOMAIN = "xenoid-location-epoch/v1:"
_COUNTRY = re.compile(r"^[A-Z]{2}$", re.ASCII)
_EPOCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$", re.ASCII)
_SIM_EPOCH = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_STATE_KEYS = {
    "schema", "instanceId", "masterSeed", "desiredCountry",
    "profiles", "active", "pending", "updatedAt", "simEpoch",
}
_PROFILE_ENTRY_KEYS = {"country", "profile", "profileDigest", "datasetVersion", "createdAt", "simEpoch"}
_ACTIVE_KEYS = {"country", "profileDigest", "appliedAt", "lastValidatedRuntimeEpoch", "simEpoch"}
_PENDING_KEYS = {
    "country", "profileDigest", "phase", "stagedRuntimeEpoch",
    "restartFromEpoch", "restartCompletedEpoch", "createdAt",
}
_PENDING_PHASES = ("new", "staged", "armed", "restarted")


class LocationError(ValueError):
    """Stable, secret-free location identity failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _text(value: Any, maximum: int = 256, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip() or "\x00" in value:
        raise LocationError("location_state_invalid")
    if not allow_empty and not value:
        raise LocationError("location_state_invalid")
    if len(value.encode("utf-8")) > maximum:
        raise LocationError("location_state_invalid")
    return value


def _epoch_text(value: Any) -> str:
    if value == "":
        return ""
    text = _text(value, 192)
    if _EPOCH.fullmatch(text) is None:
        raise LocationError("location_state_invalid")
    return text


def _timestamp(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LocationError("location_state_invalid")
    return value


def _digest_text(value: Any) -> str:
    text = _text(value, 64)
    if _HEX_64.fullmatch(text) is None:
        raise LocationError("location_state_invalid")
    return text


def location_runtime_epoch(container_id: str) -> str:
    """Derive the deterministic location epoch for one owned container."""
    if not isinstance(container_id, str) or _CONTAINER_ID.fullmatch(container_id) is None:
        raise LocationError("runtime_identity_mismatch")
    return hashlib.sha256((_EPOCH_DOMAIN + container_id).encode("ascii")).hexdigest()


def normalize_country(value: Any) -> str:
    """Normalize a case-insensitive ISO alpha-2 code to a supported country."""
    if not isinstance(value, str):
        raise LocationError("location_country_invalid")
    country = value.strip().upper()
    if _COUNTRY.fullmatch(country) is None:
        raise LocationError("location_country_invalid")
    if country not in dataset_countries():
        raise LocationError("location_country_unsupported")
    return country


def supported_countries() -> list[dict[str, Any]]:
    """Public view of the supported country dataset."""
    result: list[dict[str, Any]] = []
    for country, record in sorted(dataset_countries().items()):
        carriers = [
            {"name": item["name"], "mcc": item["mcc"], "mnc": item["mnc"],
             "apn": item["apn"], "bands": list(item["bands"])}
            for item in record["carriers"]
        ]
        result.append({
            "countryCode": country,
            "callingCode": record["callingCode"],
            "timezone": record["timezones"][0],
            "locales": list(record["locales"]),
            "carriers": carriers,
        })
    return result


def _derive_seed(master_seed: bytes, country: str, sim_epoch: str = "") -> bytes:
    if sim_epoch:
        return hmac.new(
            master_seed,
            (_SEED_DOMAIN_EPOCH + country + ":" + sim_epoch).encode("ascii"),
            hashlib.sha256,
        ).digest()
    return hmac.new(
        master_seed, (_SEED_DOMAIN + country).encode("ascii"), hashlib.sha256,
    ).digest()


class LocationStateStore:
    """0600 atomic host state for one instance's location transaction."""

    def __init__(self, state_root: Path):
        self.root = Path(state_root)
        self.path = self.root / STATE_FILENAME
        self.legacy_path = self.root / LEGACY_STATE_FILENAME

    # ------------------------------------------------------------- persistence
    def load(self) -> Optional[dict[str, Any]]:
        try:
            info = self.path.lstat()
            if not self.path.is_file() or info.st_mode & 0o077:
                raise LocationError("location_state_permissions")
            with self.path.open("rb") as stream:
                raw = json.load(stream)
        except FileNotFoundError:
            return None
        except LocationError:
            raise
        except (OSError, ValueError, UnicodeError) as exc:
            raise LocationError("location_state_invalid") from exc
        if isinstance(raw, dict) and raw.get("schema") == _V1_LOCATION_SCHEMA:
            raw = {
                **raw,
                "schema": LOCATION_SCHEMA,
                "simEpoch": "",
                "profiles": {
                    country: {**entry, "simEpoch": ""}
                    for country, entry in raw.get("profiles", {}).items()
                    if isinstance(entry, dict)
                },
                "active": (
                    {**raw["active"], "simEpoch": ""}
                    if isinstance(raw.get("active"), dict)
                    else None
                ),
            }
        return self._validate_state(raw)

    def save(self, state: Mapping[str, Any]) -> None:
        clean = self._validate_state(state)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.root.chmod(0o700)
        payload = (json.dumps(clean, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
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

    def drop_legacy(self) -> bool:
        """Remove the abandoned regional state file after location succeeds."""
        try:
            info = self.legacy_path.lstat()
        except FileNotFoundError:
            return False
        if not self.legacy_path.is_file():
            raise LocationError("location_legacy_cleanup_failed")
        self.legacy_path.unlink()
        directory_fd = os.open(self.legacy_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return True

    # ------------------------------------------------------------- validation
    def _validate_state(self, raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != _STATE_KEYS:
            raise LocationError("location_state_invalid")
        if raw.get("schema") != LOCATION_SCHEMA:
            raise LocationError("location_state_invalid")
        instance_id = _text(raw.get("instanceId"), 128)
        try:
            master_seed = base64.b64decode(_text(raw.get("masterSeed"), 64), validate=True)
        except (ValueError, TypeError) as exc:
            raise LocationError("location_state_invalid") from exc
        if len(master_seed) != 32:
            raise LocationError("location_state_invalid")
        desired = normalize_country(raw.get("desiredCountry"))
        sim_epoch = raw.get("simEpoch")
        if sim_epoch != "" and (
            not isinstance(sim_epoch, str) or _SIM_EPOCH.fullmatch(sim_epoch) is None
        ):
            raise LocationError("location_state_invalid")
        profiles_raw = raw.get("profiles")
        if not isinstance(profiles_raw, dict):
            raise LocationError("location_state_invalid")
        profiles: dict[str, Any] = {}
        for country_code, entry in profiles_raw.items():
            country = normalize_country(country_code)
            if not isinstance(entry, dict) or set(entry) != _PROFILE_ENTRY_KEYS:
                raise LocationError("location_state_invalid")
            if entry.get("country") != country:
                raise LocationError("location_state_invalid")
            entry_epoch = entry.get("simEpoch")
            if entry_epoch != "" and (
                not isinstance(entry_epoch, str) or _SIM_EPOCH.fullmatch(entry_epoch) is None
            ):
                raise LocationError("location_state_invalid")
            profile = validate_profile(entry.get("profile"))
            if profile["locationKey"] != f"{country}/{profile['timezone']}":
                raise LocationError("location_state_invalid")
            if _digest_text(entry.get("profileDigest")) != profile["identityDigest"]:
                raise LocationError("location_state_invalid")
            if _text(entry.get("datasetVersion"), 32) != dataset_version():
                raise LocationError("location_dataset_version_changed")
            _timestamp(entry.get("createdAt"))
            profiles[country] = dict(entry, profile=profile)
        active = self._validate_active(raw.get("active"), profiles, sim_epoch)
        pending = self._validate_pending(raw.get("pending"), profiles)
        if active is None and pending is None and desired not in profiles:
            raise LocationError("location_state_invalid")
        if pending is not None and pending["country"] != desired:
            raise LocationError("location_state_invalid")
        _timestamp(raw.get("updatedAt"))
        state = dict(raw)
        state["instanceId"] = instance_id
        state["desiredCountry"] = desired
        state["simEpoch"] = sim_epoch
        state["profiles"] = profiles
        state["active"] = active
        state["pending"] = pending
        return state

    def _validate_active(
        self, value: Any, profiles: Mapping[str, Any], current_epoch: str = "",
    ) -> Optional[dict[str, Any]]:
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != _ACTIVE_KEYS:
            raise LocationError("location_state_invalid")
        country = normalize_country(value.get("country"))
        digest = _digest_text(value.get("profileDigest"))
        active_epoch = value.get("simEpoch")
        if active_epoch != "" and (
            not isinstance(active_epoch, str) or _SIM_EPOCH.fullmatch(active_epoch) is None
        ):
            raise LocationError("location_state_invalid")
        entry = profiles.get(country)
        if entry is None:
            raise LocationError("location_state_invalid")
        if entry["profileDigest"] != digest and active_epoch == current_epoch:
            # A digest mismatch is only tolerable for a superseded active record
            # (its SIM epoch was rotated; the fresh pending transaction takes over).
            raise LocationError("location_state_invalid")
        _timestamp(value.get("appliedAt"))
        _epoch_text(value.get("lastValidatedRuntimeEpoch"))
        return dict(value)

    def _validate_pending(
        self, value: Any, profiles: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != _PENDING_KEYS:
            raise LocationError("location_state_invalid")
        country = normalize_country(value.get("country"))
        digest = _digest_text(value.get("profileDigest"))
        entry = profiles.get(country)
        if entry is None or entry["profileDigest"] != digest:
            raise LocationError("location_state_invalid")
        phase = value.get("phase")
        if phase not in _PENDING_PHASES:
            raise LocationError("location_state_invalid")
        staged = _epoch_text(value.get("stagedRuntimeEpoch"))
        restart_from = _epoch_text(value.get("restartFromEpoch"))
        restart_done = _epoch_text(value.get("restartCompletedEpoch"))
        if phase == "new" and (staged or restart_from or restart_done):
            raise LocationError("location_state_invalid")
        if phase == "staged" and (not staged or restart_from or restart_done):
            raise LocationError("location_state_invalid")
        if phase == "armed" and (not staged or not restart_from or restart_done):
            raise LocationError("location_state_invalid")
        if phase == "restarted" and (not staged or not restart_from or not restart_done):
            raise LocationError("location_state_invalid")
        if phase == "restarted" and restart_done == restart_from:
            raise LocationError("location_state_invalid")
        _timestamp(value.get("createdAt"))
        return dict(value)

    # ------------------------------------------------------------- transitions
    def _write(self, state: Mapping[str, Any]) -> dict[str, Any]:
        next_state = dict(state)
        next_state["updatedAt"] = int(time.time())
        self.save(next_state)
        return next_state

    def ensure(self, instance_id: str, country: Optional[str] = None) -> tuple[dict[str, Any], bool]:
        """Load the state, creating the SG-default state on first use."""
        existing = self.load()
        if existing is not None:
            if existing["instanceId"] != _text(instance_id, 128):
                raise LocationError("instance_identity_mismatch")
            return existing, False
        target = normalize_country(country) if country is not None else DEFAULT_COUNTRY
        master_seed = secrets.token_bytes(32)
        profile = generate_cellular_profile(target, _derive_seed(master_seed, target, ""))
        now = int(time.time())
        state = {
            "schema": LOCATION_SCHEMA,
            "instanceId": instance_id,
            "masterSeed": base64.b64encode(master_seed).decode("ascii"),
            "desiredCountry": target,
            "simEpoch": "",
            "profiles": {
                target: {
                    "country": target,
                    "profile": profile,
                    "profileDigest": profile["identityDigest"],
                    "datasetVersion": dataset_version(),
                    "createdAt": now,
                    "simEpoch": "",
                },
            },
            "active": None,
            "pending": None,
            "updatedAt": now,
        }
        self.save(state)
        return self._validate_state(state), True

    def set_desired(self, country: str) -> tuple[dict[str, Any], bool]:
        """Select a target country; returns (state, transaction_changed)."""
        state = self.load()
        if state is None:
            raise LocationError("location_state_missing")
        target = normalize_country(country)
        active = state["active"]
        pending = state["pending"]
        if (
            state["desiredCountry"] == target
            and pending is None
            and active is not None
            and active["country"] == target
        ):
            return state, False
        if pending is not None and pending["country"] == target and state["desiredCountry"] == target:
            return state, False
        state = dict(state)
        state["desiredCountry"] = target
        state["profiles"] = dict(state["profiles"])
        entry = state["profiles"].get(target)
        if entry is None or entry["simEpoch"] != state["simEpoch"]:
            # No cached profile, or the SIM epoch rotated under this country:
            # derive a fresh SIM identity for the current epoch.
            master_seed = base64.b64decode(state["masterSeed"], validate=True)
            profile = generate_cellular_profile(
                target, _derive_seed(master_seed, target, state["simEpoch"])
            )
            entry = {
                "country": target,
                "profile": profile,
                "profileDigest": profile["identityDigest"],
                "datasetVersion": dataset_version(),
                "createdAt": int(time.time()),
                "simEpoch": state["simEpoch"],
            }
            state["profiles"][target] = entry
        state["pending"] = {
            "country": target,
            "profileDigest": entry["profileDigest"],
            "phase": "new",
            "stagedRuntimeEpoch": "",
            "restartFromEpoch": "",
            "restartCompletedEpoch": "",
            "createdAt": int(time.time()),
        }
        return self._write(state), True

    def rotate_sim_identity(self) -> dict[str, Any]:
        """Rotate the SIM epoch: the current country gets a brand-new SIM
        (IMSI/ICCID/MSISDN/cell) while country, locale, and carrier facts stay.

        One atomic state write rotates the epoch, re-derives the desired
        country's profile, and (when a location is active) opens a fresh
        pending transaction so the standard convergence restages, recreates
        once for the RIL reload, verifies, and promotes. Profiles for other
        countries are re-derived lazily on next selection.
        """
        state = self.load()
        if state is None:
            raise LocationError("location_state_missing")
        master_seed = base64.b64decode(state["masterSeed"], validate=True)
        epoch = secrets.token_hex(16)
        while epoch == state["simEpoch"]:
            epoch = secrets.token_hex(16)
        state = dict(state)
        state["simEpoch"] = epoch
        state["profiles"] = dict(state["profiles"])
        target = state["desiredCountry"]
        profile = generate_cellular_profile(target, _derive_seed(master_seed, target, epoch))
        entry = {
            "country": target,
            "profile": profile,
            "profileDigest": profile["identityDigest"],
            "datasetVersion": dataset_version(),
            "createdAt": int(time.time()),
            "simEpoch": epoch,
        }
        state["profiles"][target] = entry
        pending = state["pending"]
        if pending is not None:
            # A country switch is in flight; restart it under the new epoch.
            state["pending"] = {
                "country": pending["country"],
                "profileDigest": entry["profileDigest"],
                "phase": "new",
                "stagedRuntimeEpoch": "",
                "restartFromEpoch": "",
                "restartCompletedEpoch": "",
                "createdAt": int(time.time()),
            }
        elif state["active"] is not None and state["active"]["country"] == target:
            state["pending"] = {
                "country": target,
                "profileDigest": entry["profileDigest"],
                "phase": "new",
                "stagedRuntimeEpoch": "",
                "restartFromEpoch": "",
                "restartCompletedEpoch": "",
                "createdAt": int(time.time()),
            }
        return self._write(state)

    def mark_staged(self, runtime_epoch: str) -> dict[str, Any]:
        state = self.load()
        if state is None or state["pending"] is None:
            raise LocationError("location_pending_missing")
        epoch = _epoch_text(runtime_epoch)
        if not epoch:
            raise LocationError("location_state_invalid")
        pending = dict(state["pending"])
        if pending["phase"] not in ("new", "staged"):
            raise LocationError("location_phase_invalid")
        if pending["phase"] == "staged" and pending["stagedRuntimeEpoch"] != epoch:
            pending["restartFromEpoch"] = ""
        pending["stagedRuntimeEpoch"] = epoch
        pending["phase"] = "staged"
        state = dict(state, pending=pending)
        return self._write(state)

    def arm_restart(self) -> dict[str, Any]:
        state = self.load()
        if state is None or state["pending"] is None:
            raise LocationError("location_pending_missing")
        pending = dict(state["pending"])
        if pending["phase"] != "staged":
            raise LocationError("location_phase_invalid")
        pending["restartFromEpoch"] = pending["stagedRuntimeEpoch"]
        pending["phase"] = "armed"
        state = dict(state, pending=pending)
        return self._write(state)

    def mark_restarted(self, runtime_epoch: str) -> dict[str, Any]:
        state = self.load()
        if state is None or state["pending"] is None:
            raise LocationError("location_pending_missing")
        epoch = _epoch_text(runtime_epoch)
        pending = dict(state["pending"])
        if pending["phase"] != "armed":
            raise LocationError("location_phase_invalid")
        if not epoch or epoch == pending["restartFromEpoch"]:
            raise LocationError("location_restart_not_observed")
        pending["restartCompletedEpoch"] = epoch
        pending["phase"] = "restarted"
        state = dict(state, pending=pending)
        return self._write(state)

    def promote(self, runtime_epoch: str) -> dict[str, Any]:
        state = self.load()
        if state is None or state["pending"] is None:
            raise LocationError("location_pending_missing")
        if state["pending"]["phase"] != "restarted":
            raise LocationError("location_phase_invalid")
        epoch = _epoch_text(runtime_epoch)
        if not epoch:
            raise LocationError("location_state_invalid")
        pending = state["pending"]
        now = int(time.time())
        state = dict(state)
        state["active"] = {
            "country": pending["country"],
            "profileDigest": pending["profileDigest"],
            "appliedAt": now,
            "lastValidatedRuntimeEpoch": epoch,
            "simEpoch": state["simEpoch"],
        }
        state["pending"] = None
        state["desiredCountry"] = pending["country"]
        return self._write(state)

    def mark_validated(self, runtime_epoch: str) -> dict[str, Any]:
        state = self.load()
        if state is None or state["active"] is None:
            raise LocationError("location_active_missing")
        epoch = _epoch_text(runtime_epoch)
        if not epoch:
            raise LocationError("location_state_invalid")
        active = dict(state["active"])
        active["lastValidatedRuntimeEpoch"] = epoch
        state = dict(state, active=active)
        return self._write(state)

    # ------------------------------------------------------------- decisions
    def target_profile(self, state: Mapping[str, Any]) -> dict[str, Any]:
        """Return the cached profile the current transaction converges toward."""
        pending = state.get("pending")
        active = state.get("active")
        target = pending if isinstance(pending, Mapping) else active
        if not isinstance(target, Mapping):
            country = state.get("desiredCountry")
            entry = state.get("profiles", {}).get(country)
            if not isinstance(entry, Mapping):
                raise LocationError("location_state_invalid")
            return entry["profile"]
        entry = state.get("profiles", {}).get(target.get("country"))
        if not isinstance(entry, Mapping) or entry["profileDigest"] != target.get("profileDigest"):
            raise LocationError("location_state_invalid")
        return entry["profile"]


def convergence_action(
    state: Mapping[str, Any],
    android: Optional[Mapping[str, Any]],
    current_epoch: str,
) -> dict[str, Any]:
    """Pure convergence decision for one location transaction.

    ``android`` is the daemon ``/location/status`` payload (or ``None`` when
    the daemon has no location state or is unreachable).  ``current_epoch`` is
    the epoch derived from the currently owned container, or empty when no
    container exists.  The returned ``step`` is one of:

    - ``bootstrap``: no runtime yet; start the runtime, then stage.
    - ``stage``: publish the target profile in the current epoch.
    - ``recreate``: exactly one recreate of the armed epoch is still due.
    - ``resume``: the armed epoch already changed; record it and continue.
    - ``verify``: daemon state matches the target; run read-back verification.
    - ``promote``: verification inputs are consistent; promote pending.
    - ``noop``: active identity already verified in the current epoch.
    """
    pending = state.get("pending")
    active = state.get("active")
    target = pending if isinstance(pending, Mapping) else active
    if not isinstance(target, Mapping):
        # First boot: desired country has a cached profile but nothing staged.
        if not current_epoch:
            return {"step": "bootstrap", "country": state.get("desiredCountry")}
        return {"step": "stage", "country": state.get("desiredCountry"), "recreate": True}
    digest = target.get("profileDigest")
    country = target.get("country")
    android_digest = android.get("profileDigest") if isinstance(android, Mapping) else None
    android_state = android.get("state") if isinstance(android, Mapping) else None
    android_epoch = android.get("runtimeEpoch") if isinstance(android, Mapping) else None
    if isinstance(pending, Mapping):
        phase = pending.get("phase")
        if not current_epoch:
            return {"step": "bootstrap", "country": country}
        if phase in ("new", "staged"):
            return {"step": "stage", "country": country, "recreate": True}
        if phase == "armed":
            if current_epoch == pending.get("restartFromEpoch"):
                return {"step": "recreate", "country": country}
            return {"step": "resume", "country": country, "runtimeEpoch": current_epoch}
        if phase == "restarted":
            if current_epoch != pending.get("restartCompletedEpoch"):
                # Unexpected epoch drift (external recreate); re-stage and finish.
                return {"step": "stage", "country": country, "recreate": False}
            if android_digest == digest and android_state in ("staged", "active"):
                return {"step": "verify", "country": country, "promote": True}
            return {"step": "stage", "country": country, "recreate": False}
        raise LocationError("location_phase_invalid")
    # Active-only steady state.
    if android_digest == digest and android_state == "active" and android_epoch == current_epoch:
        return {"step": "noop", "country": country}
    if not current_epoch:
        return {"step": "bootstrap", "country": country}
    return {"step": "verify", "country": country, "promote": False, "restage": android_digest != digest}


def public_summary(state: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """Masked, secret-free host view of the location state."""
    if not isinstance(state, Mapping):
        return {"state": "absent"}
    result: dict[str, Any] = {
        "state": "active" if isinstance(state.get("active"), Mapping) else "pending"
        if isinstance(state.get("pending"), Mapping) else "initialized",
        "desiredCountry": state.get("desiredCountry"),
        "cachedCountries": sorted(state.get("profiles", {}).keys()),
        "updatedAt": state.get("updatedAt"),
    }
    active = state.get("active")
    if isinstance(active, Mapping):
        entry = state.get("profiles", {}).get(active.get("country"), {})
        profile = entry.get("profile") if isinstance(entry, Mapping) else None
        view = {
            "country": active.get("country"),
            "profileDigest": active.get("profileDigest"),
            "appliedAt": active.get("appliedAt"),
            "lastValidatedRuntimeEpoch": active.get("lastValidatedRuntimeEpoch"),
        }
        if isinstance(profile, Mapping):
            view["profile"] = masked_profile_summary(profile)
        result["active"] = view
    pending = state.get("pending")
    if isinstance(pending, Mapping):
        result["pending"] = {
            "country": pending.get("country"),
            "profileDigest": pending.get("profileDigest"),
            "phase": pending.get("phase"),
            "createdAt": pending.get("createdAt"),
        }
    return result


def masked_android_status(status: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """Ensure a daemon location status payload never exposes raw SIM secrets."""
    if not isinstance(status, Mapping):
        return {"ok": False, "error": "location_status_unavailable"}
    result = dict(status)
    for key in ("imsi", "iccid", "msisdn"):
        if key in result:
            result[key] = mask_secret(result.get(key))
    return result


__all__ = [
    "DEFAULT_COUNTRY",
    "LEGACY_STATE_FILENAME",
    "LOCATION_SCHEMA",
    "STAGE_SCHEMA",
    "STATE_FILENAME",
    "LocationError",
    "LocationStateStore",
    "convergence_action",
    "location_runtime_epoch",
    "masked_android_status",
    "normalize_country",
    "public_summary",
    "supported_countries",
]
