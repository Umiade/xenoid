#!/usr/bin/env python3
"""Validate Xenoid's PackageManager hardware feature contract."""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "runtime/redroid/xenoid-hardware-features.xml"

REQUIRED_FEATURES = frozenset({
    "android.hardware.camera",
    "android.hardware.camera.any",
    "android.hardware.camera.flash",
    "android.hardware.camera.front",
    "android.hardware.sensor.accelerometer",
    "android.hardware.sensor.barometer",
    "android.hardware.sensor.compass",
    "android.hardware.sensor.gyroscope",
    "android.hardware.sensor.light",
    "android.hardware.sensor.proximity",
    "android.hardware.sensor.stepcounter",
    "android.hardware.sensor.stepdetector",
})

FORBIDDEN_FEATURES = frozenset({
    "android.hardware.camera.autofocus",
    "android.hardware.camera.capability.manual_post_processing",
    "android.hardware.camera.capability.manual_sensor",
    "android.hardware.camera.capability.raw",
    "android.hardware.camera.concurrent",
    "android.hardware.camera.external",
    "android.hardware.camera.level.full",
    "android.hardware.fingerprint",
    "android.hardware.nfc",
    "android.hardware.nfc.any",
    "android.hardware.nfc.ese",
    "android.hardware.nfc.hce",
    "android.hardware.nfc.hcef",
    "android.hardware.nfc.uicc",
    "android.hardware.sensor.head_tracker",
    "android.hardware.sensor.hifi_sensors",
    "android.hardware.uwb",
})


class ContractError(ValueError):
    pass


def parse_contract(path: Path) -> tuple[set[str], set[str]]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ContractError("hardware_feature_contract_unreadable") from exc
    if root.tag != "permissions" or root.attrib:
        raise ContractError("hardware_feature_contract_invalid")

    available: set[str] = set()
    unavailable: set[str] = set()
    for child in root:
        if child.tag not in {"feature", "unavailable-feature"} or set(child.attrib) != {"name"}:
            raise ContractError("hardware_feature_contract_invalid")
        name = child.attrib["name"]
        target = available if child.tag == "feature" else unavailable
        if not name or name in target:
            raise ContractError("hardware_feature_contract_invalid")
        target.add(name)

    if available != REQUIRED_FEATURES or unavailable != FORBIDDEN_FEATURES:
        raise ContractError("hardware_feature_contract_mismatch")
    if available & unavailable:
        raise ContractError("hardware_feature_contract_invalid")
    return available, unavailable


def parse_pm_features(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ContractError("package_features_unreadable") from exc
    features: set[str] = set()
    for raw in lines:
        line = raw.strip().rstrip("\r")
        if not line:
            continue
        if not line.startswith("feature:"):
            raise ContractError("package_features_invalid")
        name = line.removeprefix("feature:")
        if not name:
            raise ContractError("package_features_invalid")
        features.add(name)
    return features


def validate_observed(features: set[str]) -> None:
    missing = REQUIRED_FEATURES - features
    forbidden = set(FORBIDDEN_FEATURES & features)
    forbidden.update(name for name in features if name.startswith("android.hardware.nfc"))
    if missing:
        raise ContractError("package_features_required_missing")
    if forbidden:
        raise ContractError("package_features_forbidden_present")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--pm-features", type=Path)
    args = parser.parse_args()

    try:
        available, unavailable = parse_contract(args.contract)
        observed: set[str] | None = None
        if args.pm_features is not None:
            observed = parse_pm_features(args.pm_features)
            validate_observed(observed)
    except ContractError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 1

    result: dict[str, object] = {
        "ok": True,
        "required": sorted(available),
        "forbidden": sorted(unavailable),
    }
    if observed is not None:
        result["observedFeatureCount"] = len(observed)
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
