"""Deterministic location cellular identity profiles and binary encoding.

This module is intentionally stateless: it owns the pinned carrier dataset,
profile generation from a per-country seed, strict profile validation, and the
``XENOID_PROFILE_V1`` wire format consumed by the legacy RIL.  Persistent
location transactions live in ``xenoid.location``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from pathlib import Path
from typing import Any, Mapping

PROFILE_SCHEMA = "dev.xenoid.cellular-profile/v2"
PROFILE_MAGIC = b"XENOID_PROFILE_V1\0"
PROFILE_VERSION = 1
MAX_PROFILE_BYTES = 64 * 1024
_PROFILE_KEYS = {
    "schema", "slot", "sim", "carrier", "operator", "cell", "dataCall",
    "locale", "timezone", "callingCode", "locationKey", "identityDigest",
}
_DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "cellular" / "carriers.json"
_DATASET_SHA256 = "3aa19173c09f91921b51ebb78b5a46a2319573d06cb68b2918e83ef1b84df8f1"
_CALLING_CODE = re.compile(r"^\+[1-9][0-9]{0,3}$", re.ASCII)


class CellularError(ValueError):
    """Stable, secret-free cellular identity failure."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CellularError("cellular_profile_invalid") from exc


def _text(value: Any, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise CellularError("cellular_profile_invalid")
    if len(value.encode("utf-8")) > maximum:
        raise CellularError("cellular_profile_invalid")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _luhn_digit(value: str) -> str:
    total = 0
    for index, digit in enumerate(reversed(value)):
        number = int(digit) * (2 if index % 2 == 0 else 1)
        total += number // 10 + number % 10
    return str((-total) % 10)


def _digits(seed: bytes, label: str, length: int) -> str:
    output = ""
    counter = 0
    while len(output) < length:
        output += str(int.from_bytes(
            hmac.new(seed, f"{label}:{counter}".encode("ascii"), hashlib.sha256).digest(),
            "big",
        ))
        counter += 1
    return output[:length]


def _bounded_number(seed: bytes, label: str, minimum: int, maximum: int) -> int:
    if minimum > maximum:
        raise CellularError("cellular_dataset_invalid")
    span = maximum - minimum + 1
    value = int.from_bytes(
        hmac.new(seed, label.encode("ascii"), hashlib.sha256).digest()[:8], "big"
    )
    return minimum + value % span


def _load_dataset() -> dict[str, Any]:
    try:
        payload = _DATASET_PATH.read_bytes()
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), _DATASET_SHA256):
            raise CellularError("cellular_dataset_invalid")
        raw = json.loads(payload.decode("utf-8"))
    except CellularError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise CellularError("cellular_dataset_unavailable") from exc
    if not isinstance(raw, dict) or raw.get("schema") != "dev.xenoid.cellular-dataset/v1":
        raise CellularError("cellular_dataset_invalid")
    countries = raw.get("countries")
    if not isinstance(countries, dict) or not countries:
        raise CellularError("cellular_dataset_invalid")
    return raw


def dataset_countries() -> dict[str, Any]:
    """Return the validated pinned per-country dataset records."""
    return _load_dataset()["countries"]


def dataset_version() -> str:
    """Return the pinned dataset snapshot version."""
    version = _load_dataset().get("snapshotVersion")
    if not isinstance(version, str) or not version:
        raise CellularError("cellular_dataset_invalid")
    return version


def validate_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one complete cellular profile against the pinned dataset."""
    return _validate_profile(profile)


def _country_record(country: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country):
        raise CellularError("location_country_invalid")
    dataset = dataset_countries().get(country)
    if not isinstance(dataset, dict):
        raise CellularError("location_country_unsupported")
    timezones = dataset.get("timezones")
    carriers = dataset.get("carriers")
    if (
        not isinstance(timezones, list)
        or not timezones
        or any(not isinstance(item, str) or not item for item in timezones)
        or not isinstance(carriers, list)
        or not carriers
    ):
        raise CellularError("carrier_dataset_invalid")
    return country, dataset


def _validate_imsi(value: str, mcc: str, mnc: str) -> None:
    if len(value) != 15 or not value.isdigit() or not value.startswith(mcc + mnc):
        raise CellularError("cellular_profile_invalid")


def _validate_msisdn(value: str, dataset: Mapping[str, Any]) -> None:
    if not isinstance(value, str) or not value.startswith("+") or not value[1:].isdigit():
        raise CellularError("cellular_msisdn_invalid")
    if not 8 <= len(value) - 1 <= 15:
        raise CellularError("cellular_msisdn_invalid")
    spec = dataset.get("msisdn")
    if not isinstance(spec, Mapping):
        raise CellularError("cellular_msisdn_invalid")
    calling = _text(dataset.get("callingCode"), 5)
    if not value.startswith(calling):
        raise CellularError("cellular_msisdn_invalid")
    national = value[len(calling):]
    lengths = spec.get("nationalLengths")
    pattern = spec.get("nationalPattern")
    template = spec.get("template")
    if (
        not isinstance(lengths, list)
        or len(national) not in lengths
        or not isinstance(pattern, str)
        or re.fullmatch(pattern, national) is None
        or not isinstance(template, str)
        or len(template) != len(value)
        or any(
            want != got for want, got in zip(template, value) if want != "#"
        )
    ):
        raise CellularError("cellular_msisdn_invalid")


def _validate_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        raise CellularError("cellular_profile_invalid")
    if set(profile) != _PROFILE_KEYS:
        raise CellularError("cellular_profile_invalid")
    if profile.get("schema") != PROFILE_SCHEMA:
        raise CellularError("cellular_profile_invalid")
    slot = profile["slot"]
    if slot != {"slotId": 0, "portId": 0, "logicalSlotIndex": 0, "present": True,
                "ready": True, "embedded": False}:
        raise CellularError("cellular_slot_invalid")
    sim = profile["sim"]
    carrier = profile["carrier"]
    operator = profile["operator"]
    cell = profile["cell"]
    data_call = profile["dataCall"]
    if not all(isinstance(item, Mapping) for item in (sim, carrier, operator, cell, data_call)):
        raise CellularError("cellular_profile_invalid")
    mcc = _text(carrier.get("mcc"), 3)
    mnc = _text(carrier.get("mnc"), 3)
    if len(mcc) != 3 or len(mnc) not in (2, 3) or not mcc.isdigit() or not mnc.isdigit():
        raise CellularError("cellular_plmn_invalid")
    imsi = _text(sim.get("imsi"), 15)
    _validate_imsi(imsi, mcc, mnc)
    iccid = _text(sim.get("iccid"), 20)
    if len(iccid) != 20 or not iccid.isdigit() or _luhn_digit(iccid[:-1]) != iccid[-1]:
        raise CellularError("cellular_iccid_invalid")
    iso_country = _text(operator.get("isoCountry"))
    if len(iso_country) != 2 or not iso_country.islower() or operator.get("isoNetwork") != iso_country:
        raise CellularError("cellular_location_invalid")
    country, dataset = _country_record(iso_country.upper())
    if operator.get("numeric") != mcc + mnc or operator.get("roaming") is not False:
        raise CellularError("cellular_plmn_invalid")
    known_carriers = [
        item for item in dataset["carriers"]
        if isinstance(item, Mapping) and item.get("mcc") == mcc and item.get("mnc") == mnc
    ]
    if not known_carriers:
        raise CellularError("carrier_dataset_missing")
    known = known_carriers[0]
    if carrier.get("name") != known.get("name") or carrier.get("apn") != known.get("apn"):
        raise CellularError("cellular_profile_invalid")
    bands = carrier.get("bands")
    if not isinstance(bands, list) or not bands or sorted(bands) != sorted(known.get("bands")):
        raise CellularError("carrier_band_invalid")
    band = cell.get("band")
    if not isinstance(band, int) or band not in bands:
        raise CellularError("cellular_band_invalid")
    earfcn = cell.get("earfcn")
    if not isinstance(earfcn, int) or not 0 <= earfcn <= 262143:
        raise CellularError("cellular_earfcn_invalid")
    if cell.get("technology") != "LTE" or cell.get("bandwidthKhz") != 10000:
        raise CellularError("cellular_bandwidth_invalid")
    rssnr = cell.get("rssnr")
    if isinstance(rssnr, bool) or not isinstance(rssnr, int) or not 30 <= rssnr <= 200:
        raise CellularError("cellular_signal_invalid")
    if data_call.get("iface") != "rmnet_data0" or data_call.get("state") != "CONNECTED":
        raise CellularError("cellular_data_call_invalid")
    if data_call.get("protocol") not in {"IP", "IPV4V6", "IPV6"}:
        raise CellularError("cellular_data_call_invalid")
    locale = profile["locale"]
    if not isinstance(locale, list) or not locale or any(not isinstance(item, str) for item in locale):
        raise CellularError("cellular_locale_invalid")
    timezone = _text(profile["timezone"])
    if timezone not in dataset["timezones"]:
        raise CellularError("carrier_timezone_missing")
    calling = _text(profile["callingCode"], 5)
    if calling != dataset["callingCode"] or _CALLING_CODE.fullmatch(calling) is None:
        raise CellularError("cellular_calling_code_invalid")
    _validate_msisdn(_text(sim.get("msisdn"), 16), dataset)
    location_key = _text(profile["locationKey"], 192)
    if location_key != f"{country}/{timezone}":
        raise CellularError("cellular_location_invalid")
    digest = profile.get("identityDigest")
    unsigned = {key: value for key, value in profile.items() if key != "identityDigest"}
    if not isinstance(digest, str) or digest != _digest(unsigned):
        raise CellularError("cellular_digest_invalid")
    return dict(profile)


def _generate_msisdn(seed: bytes, dataset: Mapping[str, Any]) -> str:
    spec = dataset.get("msisdn")
    if not isinstance(spec, Mapping):
        raise CellularError("cellular_dataset_invalid")
    template = spec.get("template")
    if (
        not isinstance(template, str)
        or not template.startswith("+")
        or any(not (char.isdigit() or char == "#") for char in template[1:])
        or "#" not in template
    ):
        raise CellularError("cellular_dataset_invalid")
    stream = iter(_digits(seed, "msisdn", template.count("#")))
    number = "".join(next(stream) if char == "#" else char for char in template)
    _validate_msisdn(number, {"msisdn": spec, "callingCode": dataset.get("callingCode")})
    return number


def generate_cellular_profile(country: str, seed: bytes) -> dict[str, Any]:
    """Generate the deterministic profile for one supported country code."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise CellularError("cellular_seed_invalid")
    country, dataset = _country_record(country)
    timezone = dataset["timezones"][0]
    location_key = f"{country}/{timezone}"
    carriers = dataset["carriers"]
    index = _bounded_number(seed, "carrier", 0, len(carriers) - 1)
    selected = carriers[index]
    if not isinstance(selected, Mapping):
        raise CellularError("carrier_dataset_invalid")
    mcc = _text(selected.get("mcc"), 3)
    mnc = _text(selected.get("mnc"), 3)
    if len(mcc) != 3 or len(mnc) not in (2, 3) or not mcc.isdigit() or not mnc.isdigit():
        raise CellularError("carrier_plmn_invalid")
    subscriber = _digits(seed, "subscriber", 15 - len(mcc) - len(mnc))
    imsi = mcc + mnc + subscriber
    iccid_body = "89" + mcc + mnc + _digits(seed, "iccid", 20 - 2 - len(mcc) - len(mnc) - 1)
    iccid = iccid_body + _luhn_digit(iccid_body)
    msisdn = _generate_msisdn(seed, dataset)
    bands = selected.get("bands")
    if not isinstance(bands, list) or not bands or any(not isinstance(item, int) for item in bands):
        raise CellularError("carrier_band_invalid")
    band = bands[_bounded_number(seed, "band", 0, len(bands) - 1)]
    # LTE EARFCN downlink ranges per 3GPP TS 36.101, mirroring the AOSP
    # AccessNetworkUtils.getOperatingBandForEarfcn table used by the image's
    # telephony band bridge; the generated pair must round-trip exactly.
    earfcn_ranges = {1: (0, 599), 2: (600, 1199), 3: (1200, 1949), 4: (1950, 2399),
                     5: (2400, 2649), 7: (2750, 3449), 8: (3450, 3799), 12: (5010, 5179),
                     19: (6000, 6149), 20: (6150, 6449), 28: (9210, 9659), 66: (66436, 67335),
                     71: (68586, 68935)}
    low, high = earfcn_ranges.get(band, (0, 262143))
    earfcn = _bounded_number(seed, "earfcn", low, high)
    profile = {
        "schema": PROFILE_SCHEMA,
        "slot": {"slotId": 0, "portId": 0, "logicalSlotIndex": 0,
                 "present": True, "ready": True, "embedded": False},
        "sim": {"imsi": imsi, "iccid": iccid, "msisdn": msisdn,
                "spn": selected["name"], "gid1": "", "ad": "", "mncLength": len(mnc)},
        "carrier": {"name": selected["name"], "mcc": mcc, "mnc": mnc,
                    "apn": selected["apn"], "bands": sorted(bands)},
        "operator": {"alphaLong": selected["name"], "alphaShort": selected["name"],
                     "numeric": mcc + mnc, "isoCountry": country.lower(), "isoNetwork": country.lower(),
                     "roaming": False},
        "cell": {"technology": "LTE", "tac": _bounded_number(seed, "tac", 1, 65535),
                 "eci": _bounded_number(seed, "eci", 1, 268435455),
                 "pci": _bounded_number(seed, "pci", 0, 503), "earfcn": earfcn, "band": band,
                 "bandwidthKhz": 10000,
                 "rsrp": -_bounded_number(seed, "rsrp", 75, 105),
                 "rsrq": -_bounded_number(seed, "rsrq", 8, 20),
                 "rssnr": _bounded_number(seed, "rssnr", 30, 200),
                 "cqi": _bounded_number(seed, "cqi", 7, 15),
                 "timingAdvance": _bounded_number(seed, "timingAdvance", 0, 63)},
        "dataCall": {"iface": "rmnet_data0", "state": "CONNECTED", "protocol": "IPV4V6",
                     "addresses": [], "gateways": [], "dnses": [], "mtu": 1500},
        "locale": list(dataset["locales"]),
        "timezone": timezone,
        "callingCode": dataset["callingCode"],
        "locationKey": location_key,
    }
    profile["identityDigest"] = _digest(profile)
    return _validate_profile(profile)


def encode_profile_v1(profile: Mapping[str, Any]) -> bytes:
    clean = _validate_profile(profile)
    sim = clean["sim"]
    carrier = clean["carrier"]
    cell = clean["cell"]
    fields: dict[int, bytes] = {
        1: carrier["mcc"].encode("ascii"),
        2: carrier["mnc"].encode("ascii"),
        3: sim["imsi"].encode("ascii"),
        4: sim["iccid"].encode("ascii"),
        5: sim["msisdn"].encode("ascii"),
        6: carrier["name"].encode("utf-8"),
        7: carrier["apn"].encode("ascii"),
        8: struct.pack(">I", cell["tac"]),
        9: struct.pack(">I", cell["eci"]),
        10: struct.pack(">I", cell["pci"]),
        11: struct.pack(">I", cell["earfcn"]),
        12: struct.pack(">I", cell["band"]),
        13: struct.pack(">i", cell["rsrp"]),
        14: struct.pack(">i", cell["rsrq"]),
        15: struct.pack(">i", cell["rssnr"]),
        16: struct.pack(">I", cell["cqi"]),
        17: struct.pack(">I", cell["timingAdvance"]),
        18: ",".join(clean["locale"]).encode("ascii"),
        19: clean["timezone"].encode("ascii"),
        20: clean["identityDigest"].encode("ascii"),
        21: struct.pack(">I", cell["bandwidthKhz"]),
    }
    payload = bytearray()
    for field_id in sorted(fields):
        encoded = fields[field_id]
        if not encoded or len(encoded) > 8192:
            raise CellularError("cellular_profile_too_large")
        payload.extend(struct.pack(">HI", field_id, len(encoded)))
        payload.extend(encoded)
    if len(payload) > MAX_PROFILE_BYTES:
        raise CellularError("cellular_profile_too_large")
    header = PROFILE_MAGIC + struct.pack(">II", PROFILE_VERSION, len(fields))
    return header + bytes(payload) + hashlib.sha256(payload).digest()


def mask_secret(value: Any) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return ""
    return "*" * max(0, len(value) - 4) + value[-4:]


def masked_profile_summary(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Public, secret-free view of one validated profile."""
    clean = _validate_profile(profile)
    sim = clean["sim"]
    carrier = clean["carrier"]
    cell = clean["cell"]
    return {
        "locationKey": clean["locationKey"],
        "countryCode": clean["operator"]["isoCountry"].upper(),
        "timezone": clean["timezone"],
        "locale": list(clean["locale"]),
        "callingCode": clean["callingCode"],
        "carrier": carrier["name"],
        "operatorNumeric": carrier["mcc"] + carrier["mnc"],
        "apn": carrier["apn"],
        "band": cell["band"],
        "earfcn": cell["earfcn"],
        "bandwidthKhz": cell["bandwidthKhz"],
        "imsi": mask_secret(sim["imsi"]),
        "iccid": mask_secret(sim["iccid"]),
        "msisdn": mask_secret(sim["msisdn"]),
        "profileDigest": clean["identityDigest"],
    }


__all__ = [
    "CellularError",
    "MAX_PROFILE_BYTES",
    "PROFILE_MAGIC",
    "PROFILE_SCHEMA",
    "PROFILE_VERSION",
    "canonical_bytes",
    "dataset_countries",
    "dataset_version",
    "encode_profile_v1",
    "generate_cellular_profile",
    "mask_secret",
    "masked_profile_summary",
    "validate_profile",
]
