#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples/fingerprints/pixel-raven-android13.json"
IMPORTER = ROOT / "scripts/import-pixel-template.py"
profile = json.loads(PROFILE_PATH.read_text())
checks: dict[str, bool] = {}

build = profile.get("build") or {}
checks["canonical_build"] = build == {
    "brand": "google",
    "manufacturer": "Google",
    "model": "Pixel 6 Pro",
    "device": "raven",
    "product": "raven",
    "board": "raven",
    "platform": "gs101",
    "hardware": "raven",
    "soc_manufacturer": "Google",
    "soc_model": "Tensor",
    "release": "13",
    "sdk": "33",
    "id": "TP1A.221005.002",
    "incremental": "9012097",
    "description": "raven-user 13 TP1A.221005.002 9012097 release-keys",
    "fingerprint": "google/raven/raven:13/TP1A.221005.002/9012097:user/release-keys",
    "bootloader": "slider-1.2-8895132",
    "security_patch": "2022-10-05",
    "first_api_level": "31",
    "sku": "G8V0U",
    "tags": "release-keys",
    "type": "user",
    "kernel_build_suffix": "ab9012097",
    "abi": "arm64-v8a",
    "abilist": "arm64-v8a",
    "abilist32": "",
    "abilist64": "arm64-v8a",
    "bionic_arch": "arm64",
    "dalvik_isa_arm64": "arm64",
    "dalvik_isa_arm": "",
}


display = profile.get("display") or {}
checks["canonical_display"] = (
    (display.get("width"), display.get("height"), display.get("densityDpi")) == (1440, 3120, 560)
    and display.get("supportedRefreshRatesHz") == [60, 120]
    and display.get("defaultRefreshRateHz") == 120
    and display.get("peakRefreshRateHz") == 120
    and "brightness" not in display
)
checks["canonical_memory"] = profile.get("memory") == {
    "totalBytes": 12 * 1024**3,
    "totalKiB": 12 * 1024**2,
    "swapBytes": 0,
}
storage = profile.get("storage") or {}
checks["canonical_storage"] = (
    storage.get("capacityBytes") == 128_000_000_000
    and storage.get("sectorSizeBytes") * storage.get("sectorCount") == storage.get("capacityBytes")
    and storage.get("blockDevice") == "sda"
    and storage.get("mountSource") == "/dev/block/platform/14700000.ufs/by-name/userdata"
    and storage.get("technology") == "UFS 3.1"
    and storage.get("filesystem") == "f2fs"
    and storage.get("sparse") is True
    and storage.get("removable") is False
)
battery = profile.get("battery") or {}
checks["canonical_battery"] = (
    battery.get("capacityMah") == 5003
    and battery.get("minimumCapacityMah") == 4905
    and battery.get("chargeFullDesignUah") == 5_003_000
    and battery.get("chargeCounterUah") == battery.get("chargeFullUah") * battery.get("level") // battery.get("scale")
    and not (battery.get("plugged") == 0 and battery.get("status") == 2)
)

sensor_names = {sensor.get("name") for sensor in profile.get("sensors", [])}
checks["canonical_sensors"] = {
    "LSM6DSR Accelerometer",
    "LSM6DSR Gyroscope",
    "MMC56X3X Magnetometer",
    "TMD3719 Proximity",
    "TMD3719 Light",
    "ICP10101 Pressure",
    "VD6282 Rear Light Sensor",
}.issubset(sensor_names)
checks["obsolete_sensors_absent"] = not any(
    marker in name
    for name in sensor_names
    for marker in ("BMI160", "AK09918", "LTR-559", "BMP388", "LSM6DSO", "MMC5602", "TMD3725", "BMP380")
)
checks["implemented_cameras_only"] = (
    [camera.get("id") for camera in profile.get("cameras", [])] == ["0", "1"]
    and all(camera.get("physicalCameraIds") == [] for camera in profile.get("cameras", []))
    and all(camera.get("oisAvailable") is False for camera in profile.get("cameras", []))
)
checks["location_fields_absent"] = not {
    "locale", "timezone", "network", "mac", "mac_address", "wifi_mac"
}.intersection(profile)
checks["legacy_flat_fields_absent"] = not {
    "display_width", "display_height", "display_brightness", "input_name",
    "input_bustype", "input_vendor", "input_product", "input_version",
    "pressure_max", "tracking_max",
}.intersection(profile)

with tempfile.TemporaryDirectory(prefix="xenoid-profile-smoke-") as temporary:
    temporary_path = pathlib.Path(temporary)
    output_directory = temporary_path / "normalized"
    canonical = subprocess.run(
        [str(IMPORTER), str(PROFILE_PATH), "--out-dir", str(output_directory), "--overwrite"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    normalized_path = output_directory / PROFILE_PATH.name
    checks["canonical_round_trip"] = (
        canonical.returncode == 0
        and normalized_path.is_file()
        and json.loads(normalized_path.read_text()) == profile
    )

    missing = copy.deepcopy(profile)
    missing.pop("storage")
    missing_path = temporary_path / "missing.json"
    missing_path.write_text(json.dumps(missing))
    missing_result = subprocess.run(
        [str(IMPORTER), str(missing_path), "--out-dir", str(temporary_path / "missing-out")],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["missing_field_rejected"] = (
        missing_result.returncode != 0 and "profile.storage: required" in missing_result.stderr
    )

    inconsistent_storage = copy.deepcopy(profile)
    inconsistent_storage["storage"]["sectorCount"] -= 1
    inconsistent_storage_path = temporary_path / "inconsistent-storage.json"
    inconsistent_storage_path.write_text(json.dumps(inconsistent_storage))
    inconsistent_storage_result = subprocess.run(
        [
            str(IMPORTER),
            str(inconsistent_storage_path),
            "--out-dir",
            str(temporary_path / "inconsistent-storage-out"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["inconsistent_storage_rejected"] = (
        inconsistent_storage_result.returncode != 0
        and "capacityBytes must equal sectorSizeBytes * sectorCount"
        in inconsistent_storage_result.stderr
    )

    noncanonical_storage = copy.deepcopy(profile)
    noncanonical_storage["storage"]["blockDevice"] = "vda"
    noncanonical_storage_path = temporary_path / "noncanonical-storage.json"
    noncanonical_storage_path.write_text(json.dumps(noncanonical_storage))
    noncanonical_storage_result = subprocess.run(
        [
            str(IMPORTER),
            str(noncanonical_storage_path),
            "--out-dir",
            str(temporary_path / "noncanonical-storage-out"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["noncanonical_storage_rejected"] = (
        noncanonical_storage_result.returncode != 0
        and "must match canonical Raven 128 GB UFS 3.1 f2fs geometry"
        in noncanonical_storage_result.stderr
    )

    ext4_storage = copy.deepcopy(profile)
    ext4_storage["storage"]["filesystem"] = "ext4"
    ext4_storage_path = temporary_path / "ext4-storage.json"
    ext4_storage_path.write_text(json.dumps(ext4_storage))
    ext4_storage_result = subprocess.run(
        [
            str(IMPORTER),
            str(ext4_storage_path),
            "--out-dir",
            str(temporary_path / "ext4-storage-out"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["ext4_device_view_rejected"] = (
        ext4_storage_result.returncode != 0
        and "must match canonical Raven 128 GB UFS 3.1 f2fs geometry"
        in ext4_storage_result.stderr
    )

    wrong_mount_source = copy.deepcopy(profile)
    wrong_mount_source["storage"]["mountSource"] = "/dev/block/sda"
    wrong_mount_source_path = temporary_path / "wrong-mount-source.json"
    wrong_mount_source_path.write_text(json.dumps(wrong_mount_source))
    wrong_mount_source_result = subprocess.run(
        [
            str(IMPORTER),
            str(wrong_mount_source_path),
            "--out-dir",
            str(temporary_path / "wrong-mount-source-out"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["wrong_mount_source_rejected"] = (
        wrong_mount_source_result.returncode != 0
        and "must match canonical Raven 128 GB UFS 3.1 f2fs geometry"
        in wrong_mount_source_result.stderr
    )

    forbidden = copy.deepcopy(profile)
    forbidden["locale"] = "en-US"
    forbidden_path = temporary_path / "forbidden.json"
    forbidden_path.write_text(json.dumps(forbidden))
    forbidden_result = subprocess.run(
        [str(IMPORTER), str(forbidden_path), "--out-dir", str(temporary_path / "forbidden-out")],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["location_ownership_rejected"] = (
        forbidden_result.returncode != 0 and "not device-profile owned" in forbidden_result.stderr
    )

    invalid_battery = copy.deepcopy(profile)
    invalid_battery["battery"]["status"] = 2
    invalid_battery["battery"]["plugged"] = 0
    invalid_battery_path = temporary_path / "invalid-battery.json"
    invalid_battery_path.write_text(json.dumps(invalid_battery))
    invalid_battery_result = subprocess.run(
        [
            str(IMPORTER),
            str(invalid_battery_path),
            "--out-dir",
            str(temporary_path / "invalid-battery-out"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    checks["inconsistent_battery_rejected"] = (
        invalid_battery_result.returncode != 0
        and "status and plugged state are inconsistent"
        in invalid_battery_result.stderr
    )

result = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(0 if result["ok"] else 1)
