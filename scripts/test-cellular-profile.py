#!/usr/bin/env python3
"""Runtime-free contracts for deterministic location cellular identities."""
from __future__ import annotations

import base64
import json
import re
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.cellular import (PROFILE_SCHEMA, CellularError, dataset_countries,
                             dataset_version, encode_profile_v1, generate_cellular_profile,
                             masked_profile_summary, validate_profile)
from xenoid.location import (DEFAULT_COUNTRY, LocationError, LocationStateStore,
                             convergence_action, location_runtime_epoch, normalize_country,
                             public_summary, supported_countries)

INSTANCE = "123e4567-e89b-42d3-a456-426614174000"
EPOCH_1 = location_runtime_epoch("a" * 64)
EPOCH_2 = location_runtime_epoch("b" * 64)
EPOCH_3 = location_runtime_epoch("c" * 64)


def require(value: bool) -> None:
    if not value:
        raise AssertionError


def expect(code: str, action) -> None:
    try:
        action()
    except (CellularError, LocationError) as exc:
        if exc.code != code:
            raise AssertionError(f"{code} != {exc.code}")
        return
    raise AssertionError(code)


def android(state, digest, phase="active", epoch=EPOCH_1):
    return {"ok": True, "profileDigest": digest, "state": phase, "runtimeEpoch": epoch}


def test_supported_countries_and_normalization() -> None:
    countries = {entry["countryCode"]: entry for entry in supported_countries()}
    require(set(countries) == {"AU", "DE", "GB", "HK", "JP", "SG", "US"})
    for entry in countries.values():
        require(entry["callingCode"].startswith("+"))
        require("/" in entry["timezone"])
        require(entry["locales"] and entry["carriers"])
    require(normalize_country("sg") == "SG" and normalize_country(" Us ") == "US")
    expect("location_country_invalid", lambda: normalize_country("USA"))
    expect("location_country_invalid", lambda: normalize_country("1S"))
    expect("location_country_unsupported", lambda: normalize_country("ZZ"))
    expect("location_country_unsupported", lambda: normalize_country("CN"))
    require(DEFAULT_COUNTRY == "SG")


def test_profile_invariants_all_countries() -> None:
    dataset = dataset_countries()
    for country in dataset:
        first = generate_cellular_profile(country, b"a" * 32)
        require(generate_cellular_profile(country, b"a" * 32) == first)
        require(generate_cellular_profile(country, b"b" * 32) != first)
        require(first["schema"] == PROFILE_SCHEMA)
        require(first["locationKey"] == f"{country}/{first['timezone']}")
        require(first["timezone"] == dataset[country]["timezones"][0])
        require(first["callingCode"] == dataset[country]["callingCode"])
        require(first["operator"]["isoCountry"] == country.lower())
        require(len(encode_profile_v1(first)) < 65536)
        digest = first["identityDigest"]
        tampered = json.loads(json.dumps(first))
        tampered["cell"]["tac"] = 42000 if first["cell"]["tac"] != 42000 else 42001
        expect("cellular_digest_invalid", lambda: validate_profile(tampered))
        require(validate_profile(first)["identityDigest"] == digest)
    expect("location_country_unsupported", lambda: generate_cellular_profile("ZZ", b"a" * 32))
    expect("cellular_seed_invalid", lambda: generate_cellular_profile("SG", b"short"))


def test_msisdn_templates_match_frozen_patterns() -> None:
    dataset = dataset_countries()
    seen = set()
    for country, record in dataset.items():
        spec = record["msisdn"]
        pattern = re.compile(spec["nationalPattern"])
        calling = record["callingCode"]
        for seed in (b"m" * 32, b"n" * 32, b"o" * 32):
            profile = generate_cellular_profile(country, seed)
            msisdn = profile["sim"]["msisdn"]
            require(msisdn.startswith(calling))
            national = msisdn[len(calling):]
            require(len(national) in spec["nationalLengths"])
            require(pattern.fullmatch(national) is not None)
            require(8 <= len(msisdn) - 1 <= 15)
            template = spec["template"]
            require(len(template) == len(msisdn))
            require(all(want == got for want, got in zip(template, msisdn) if want != "#"))
            seen.add(msisdn)
    require(len(seen) == 3 * len(dataset))
    summary = masked_profile_summary(generate_cellular_profile("SG", b"m" * 32))
    require(set(summary["msisdn"][:-4]) == {"*"})
    require(summary["imsi"].startswith("***"))


def _pending_store(directory: str, country: str = "SG") -> LocationStateStore:
    store = LocationStateStore(Path(directory))
    store.ensure(INSTANCE)
    store.set_desired(country)
    return store


def test_first_boot_creates_sg_pending() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = LocationStateStore(Path(directory))
        state, created = store.ensure(INSTANCE)
        require(created)
        require(state["desiredCountry"] == "SG")
        require(state["active"] is None and state["pending"] is None)
        require(sorted(state["profiles"]) == ["SG"])
        mode = stat.S_IMODE(store.path.stat().st_mode)
        require(mode == 0o600)
        loaded, again = store.ensure(INSTANCE)
        require(not again and loaded == state)
        expect("instance_identity_mismatch", lambda: store.ensure("other-instance"))
        state, changed = store.set_desired("SG")
        require(changed and state["pending"]["country"] == "SG")
        require(state["pending"]["phase"] == "new")
        same, unchanged = store.set_desired("SG")
        require(not unchanged and same["pending"]["phase"] == "new")


def test_crash_safe_recreate_exactly_once() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        pending = store.load()["pending"]
        # new -> stage decision, then arm, then recreate only while epoch unchanged
        action = convergence_action(store.load(), None, EPOCH_1)
        require(action == {"step": "stage", "country": "SG", "recreate": True})
        store.mark_staged(EPOCH_1)
        store.arm_restart()
        action = convergence_action(store.load(), None, EPOCH_1)
        require(action["step"] == "recreate")
        # crash and retry before docker returned: same epoch, still one recreate due
        action = convergence_action(store.load(), None, EPOCH_1)
        require(action["step"] == "recreate")
        # container changed while we were crashed: resume, never recreate again
        action = convergence_action(store.load(), None, EPOCH_2)
        require(action["step"] == "resume" and action["runtimeEpoch"] == EPOCH_2)
        store.mark_restarted(EPOCH_2)
        staged = android(store.load(), pending["profileDigest"], "staged", EPOCH_1)
        action = convergence_action(store.load(), staged, EPOCH_2)
        require(action["step"] == "verify" and action["promote"])
        store.promote(EPOCH_2)
        state = store.load()
        require(state["active"]["country"] == "SG" and state["pending"] is None)
        active = android(state, pending["profileDigest"], "active", EPOCH_2)
        require(convergence_action(state, active, EPOCH_2)["step"] == "noop")
        # stale daemon view triggers a refresh, never a recreate
        stale = android(state, pending["profileDigest"], "active", EPOCH_1)
        action = convergence_action(state, stale, EPOCH_2)
        require(action["step"] == "verify" and not action.get("restage"))
        missing = convergence_action(state, None, EPOCH_2)
        require(missing["step"] == "verify" and missing.get("restage"))
        store.mark_validated(EPOCH_2)
        require(store.load()["active"]["lastValidatedRuntimeEpoch"] == EPOCH_2)


def test_rotation_and_cached_restore() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        sg_digest = store.load()["pending"]["profileDigest"]
        store.mark_staged(EPOCH_1)
        store.arm_restart()
        store.mark_restarted(EPOCH_2)
        store.promote(EPOCH_2)
        state, changed = store.set_desired("US")
        require(changed and state["pending"]["country"] == "US")
        us_digest = state["pending"]["profileDigest"]
        require(us_digest != sg_digest)
        # user changes mind before any restart: restore transaction to SG
        state, changed = store.set_desired("SG")
        require(changed and state["pending"]["country"] == "SG")
        require(state["pending"]["profileDigest"] == sg_digest)
        store.mark_staged(EPOCH_2)
        store.arm_restart()
        store.mark_restarted(EPOCH_3)
        store.promote(EPOCH_3)
        state = store.load()
        require(state["active"]["profileDigest"] == sg_digest)
        require(sorted(state["profiles"]) == ["SG", "US"])
        # switching to the previously seen US restores the same identity
        state, changed = store.set_desired("US")
        require(state["pending"]["profileDigest"] == us_digest)
        require(state["profiles"]["US"]["profile"] == generate_cellular_profile(
            "US", __import__("hmac").new(
                base64.b64decode(state["masterSeed"]),
                b"xenoid-location-profile/v1:US", __import__("hashlib").sha256).digest()))


def test_state_permissions_and_corruption() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        store.path.chmod(0o644)
        expect("location_state_permissions", lambda: store.load())
        store.path.chmod(0o600)
        payload = json.loads(store.path.read_text())
        payload["pending"]["phase"] = "armed"
        store.path.write_text(json.dumps(payload))
        expect("location_state_invalid", lambda: store.load())
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        expect("location_phase_invalid", lambda: store.arm_restart())
        expect("location_phase_invalid", lambda: store.mark_restarted(EPOCH_2))
        expect("location_phase_invalid", lambda: store.promote(EPOCH_2))
        expect("location_restart_not_observed", lambda: (
            store.mark_staged(EPOCH_1), store.arm_restart(),
            store.mark_restarted(EPOCH_1)))
        # armed transaction rejects a same-epoch restart marker
        expect("location_phase_invalid", lambda: store.promote(EPOCH_2))
    with tempfile.TemporaryDirectory() as directory:
        store = LocationStateStore(Path(directory))
        store.ensure(INSTANCE)
        expect("location_pending_missing", lambda: store.mark_staged(EPOCH_1))
        expect("location_active_missing", lambda: store.mark_validated(EPOCH_1))


def test_public_summary_masks_secrets() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        summary = public_summary(store.load())
        require(summary["state"] == "pending")
        require(summary["pending"]["country"] == "SG")
        require("imsi" not in json.dumps(summary))
        store.mark_staged(EPOCH_1)
        store.arm_restart()
        store.mark_restarted(EPOCH_2)
        store.promote(EPOCH_2)
        summary = public_summary(store.load())
        require(summary["state"] == "active")
        profile_view = summary["active"]["profile"]
        require(set(profile_view["imsi"][:-4]) == {"*"})
        require(set(profile_view["msisdn"][:-4]) == {"*"})
        require(summary["cachedCountries"] == ["SG"])
        require(public_summary(None) == {"state": "absent"})


def test_legacy_state_cleanup() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = _pending_store(directory)
        require(not store.drop_legacy())
        legacy = Path(directory) / "regional-identity.json"
        legacy.write_text("{}\n")
        require(store.drop_legacy())
        require(not legacy.exists())


# Independent copy of the AOSP AccessNetworkUtils.getOperatingBandForEarfcn
# downlink ranges for the dataset bands. The image telephony bridge uses that
# exact table, so generated (band, earfcn) pairs must round-trip through it.
AOSP_EARFCN_BANDS = {
    1: (0, 599), 2: (600, 1199), 3: (1200, 1949), 4: (1950, 2399),
    5: (2400, 2649), 7: (2750, 3449), 8: (3450, 3799), 12: (5010, 5179),
    19: (6000, 6149), 20: (6150, 6449), 28: (9210, 9659), 66: (66436, 67335),
    71: (68586, 68935),
}


def aosp_band_for_earfcn(earfcn: int) -> int:
    for band, (low, high) in AOSP_EARFCN_BANDS.items():
        if low <= earfcn <= high:
            return band
    return 0


def test_earfcn_band_roundtrip_matches_aosp_bridge() -> None:
    for country, record in dataset_countries().items():
        bands = {band for carrier in record["carriers"] for band in carrier["bands"]}
        require(bands and bands <= set(AOSP_EARFCN_BANDS))
        for seed in (b"e" * 32, b"f" * 32):
            profile = generate_cellular_profile(country, seed)
            cell = profile["cell"]
            require(aosp_band_for_earfcn(cell["earfcn"]) == cell["band"])
            require(cell["bandwidthKhz"] == 10000)


def main() -> int:
    test_supported_countries_and_normalization()
    test_profile_invariants_all_countries()
    test_msisdn_templates_match_frozen_patterns()
    test_earfcn_band_roundtrip_matches_aosp_bridge()
    test_first_boot_creates_sg_pending()
    test_crash_safe_recreate_exactly_once()
    test_rotation_and_cached_restore()
    test_state_permissions_and_corruption()
    test_public_summary_masks_secrets()
    test_legacy_state_cleanup()
    print("location cellular profile contracts ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
