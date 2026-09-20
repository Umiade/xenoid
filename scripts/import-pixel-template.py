#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import re
import sys
import tempfile
from typing import Any

SCHEMA = "dev.xenoid.fingerprint/v1"
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
FORBIDDEN_TOP_LEVEL = {
    "locale",
    "timezone",
    "network",
    "mac",
    "mac_address",
    "wifi_mac",
}
LEGACY_FLAT_FIELDS = {
    "display_brightness",
    "display_height",
    "display_width",
    "input_bustype",
    "input_name",
    "input_product",
    "input_vendor",
    "input_version",
    "pressure_max",
    "tracking_max",
}


class ProfileError(ValueError):
    pass


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{path}: expected object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProfileError(f"{path}: expected array")
    return value


def _required(obj: dict[str, Any], key: str, path: str) -> Any:
    if key not in obj:
        raise ProfileError(f"{path}.{key}: required")
    return obj[key]


def _string(obj: dict[str, Any], key: str, path: str, *, allow_empty: bool = False) -> str:
    value = _required(obj, key, path)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ProfileError(f"{path}.{key}: expected {'string' if allow_empty else 'non-empty string'}")
    return value


def _integer(obj: dict[str, Any], key: str, path: str, *, minimum: int | None = None) -> int:
    value = _required(obj, key, path)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProfileError(f"{path}.{key}: expected integer")
    if minimum is not None and value < minimum:
        raise ProfileError(f"{path}.{key}: must be >= {minimum}")
    return value


def _number(obj: dict[str, Any], key: str, path: str, *, minimum: float | None = None) -> float:
    value = _required(obj, key, path)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileError(f"{path}.{key}: expected number")
    result = float(value)
    if minimum is not None and result < minimum:
        raise ProfileError(f"{path}.{key}: must be >= {minimum}")
    return result


def _boolean(obj: dict[str, Any], key: str, path: str) -> bool:
    value = _required(obj, key, path)
    if not isinstance(value, bool):
        raise ProfileError(f"{path}.{key}: expected boolean")
    return value


def _validate_build(profile: dict[str, Any]) -> None:
    build = _object(_required(profile, "build", "profile"), "profile.build")
    required_strings = (
        "brand", "manufacturer", "model", "device", "product", "board", "platform",
        "hardware", "soc_manufacturer", "soc_model", "release", "sdk", "id",
        "incremental", "description", "fingerprint", "bootloader", "security_patch",
        "first_api_level", "sku", "tags", "type", "kernel_build_suffix", "abi",
        "abilist", "abilist64", "bionic_arch", "dalvik_isa_arm64",
    )
    for key in required_strings:
        _string(build, key, "profile.build")
    _string(build, "abilist32", "profile.build", allow_empty=True)
    _string(build, "dalvik_isa_arm", "profile.build", allow_empty=True)

    fingerprint = build["fingerprint"]
    expected_fingerprint = (
        f"{build['brand']}/{build['product']}/{build['device']}:"
        f"{build['release']}/{build['id']}/{build['incremental']}:"
        f"{build['type']}/{build['tags']}"
    )
    if fingerprint != expected_fingerprint:
        raise ProfileError("profile.build.fingerprint: inconsistent build tuple")
    expected_description = (
        f"{build['product']}-{build['type']} {build['release']} {build['id']} "
        f"{build['incremental']} {build['tags']}"
    )
    if build["description"] != expected_description:
        raise ProfileError("profile.build.description: inconsistent build tuple")
    if build["abi"] != "arm64-v8a" or build["abilist"] != "arm64-v8a" or build["abilist64"] != "arm64-v8a":
        raise ProfileError("profile.build: Xenoid production runtime is arm64-v8a only")
    if build["abilist32"] or build["dalvik_isa_arm"]:
        raise ProfileError("profile.build: 32-bit ABI declarations are unsupported")


def _validate_display_and_input(profile: dict[str, Any]) -> None:
    display = _object(_required(profile, "display", "profile"), "profile.display")
    width = _integer(display, "width", "profile.display", minimum=1)
    height = _integer(display, "height", "profile.display", minimum=1)
    _integer(display, "densityDpi", "profile.display", minimum=1)
    _number(display, "physicalPpi", "profile.display", minimum=1)
    default_rate = _number(display, "defaultRefreshRateHz", "profile.display", minimum=1)
    peak_rate = _number(display, "peakRefreshRateHz", "profile.display", minimum=default_rate)
    rates = _array(_required(display, "supportedRefreshRatesHz", "profile.display"), "profile.display.supportedRefreshRatesHz")
    if not rates or any(isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0 for rate in rates):
        raise ProfileError("profile.display.supportedRefreshRatesHz: expected positive rates")
    if default_rate not in rates or peak_rate not in rates:
        raise ProfileError("profile.display: default and peak rates must be supported")
    modes = _array(_required(display, "modes", "profile.display"), "profile.display.modes")
    mode_rates: set[float] = set()
    mode_ids: set[int] = set()
    for index, raw_mode in enumerate(modes):
        path = f"profile.display.modes[{index}]"
        mode = _object(raw_mode, path)
        mode_id = _integer(mode, "id", path, minimum=1)
        if mode_id in mode_ids:
            raise ProfileError(f"{path}.id: duplicate")
        mode_ids.add(mode_id)
        if _integer(mode, "width", path, minimum=1) != width or _integer(mode, "height", path, minimum=1) != height:
            raise ProfileError(f"{path}: mode dimensions must match the panel")
        mode_rates.add(_number(mode, "refreshRateHz", path, minimum=1))
    if mode_rates != {float(rate) for rate in rates}:
        raise ProfileError("profile.display.modes: rates do not match supportedRefreshRatesHz")

    input_profile = _object(_required(profile, "input", "profile"), "profile.input")
    _string(input_profile, "name", "profile.input")
    for key in ("busType", "vendorId", "productId", "version"):
        _integer(input_profile, key, "profile.input", minimum=0)
    axes: dict[str, tuple[int, int]] = {}
    for key in ("x", "y", "pressure", "trackingId"):
        axis = _object(_required(input_profile, key, "profile.input"), f"profile.input.{key}")
        minimum = _integer(axis, "minimum", f"profile.input.{key}", minimum=0)
        maximum = _integer(axis, "maximum", f"profile.input.{key}", minimum=minimum)
        axes[key] = (minimum, maximum)
    if axes["x"] != (0, width - 1) or axes["y"] != (0, height - 1):
        raise ProfileError("profile.input: X/Y axes must match display pixel bounds")


def _validate_cpu_memory_storage(profile: dict[str, Any]) -> None:
    cpu = _object(_required(profile, "cpu", "profile"), "profile.cpu")
    _string(cpu, "implementer", "profile.cpu")
    cores = _array(_required(cpu, "cores", "profile.cpu"), "profile.cpu.cores")
    if len(cores) != 8:
        raise ProfileError("profile.cpu.cores: Raven requires exactly eight cores")
    processors: set[int] = set()
    core_views: list[tuple[str, str, int, int]] = []
    for index, raw_core in enumerate(cores):
        path = f"profile.cpu.cores[{index}]"
        core = _object(raw_core, path)
        processor = _integer(core, "processor", path, minimum=0)
        if processor in processors:
            raise ProfileError(f"{path}.processor: duplicate")
        processors.add(processor)
        part = _string(core, "part", path)
        model = _string(core, "model", path)
        minimum = _integer(core, "minimumFrequencyKhz", path, minimum=1)
        maximum = _integer(core, "maximumFrequencyKhz", path, minimum=minimum)
        core_views.append((part, model, minimum, maximum))
    if processors != set(range(len(cores))):
        raise ProfileError("profile.cpu.cores: processor IDs must be contiguous from zero")

    for index, view in enumerate(core_views):
        leader = 0 if index < 4 else (4 if index < 6 else 6)
        if view != core_views[leader]:
            raise ProfileError(f"profile.cpu.cores[{index}]: cluster values are inconsistent")

    memory = _object(_required(profile, "memory", "profile"), "profile.memory")
    total_bytes = _integer(memory, "totalBytes", "profile.memory", minimum=1)
    total_kib = _integer(memory, "totalKiB", "profile.memory", minimum=1)
    if total_bytes != total_kib * 1024:
        raise ProfileError("profile.memory: totalBytes must equal totalKiB * 1024")
    swap_bytes = _integer(memory, "swapBytes", "profile.memory", minimum=0)
    if total_kib % 4 or swap_bytes % 1024:
        raise ProfileError("profile.memory: values must align to 4 KiB pages")

    storage = _object(_required(profile, "storage", "profile"), "profile.storage")
    variant = _string(storage, "variant", "profile.storage")
    capacity = _integer(storage, "capacityBytes", "profile.storage", minimum=1)
    block_device = _string(storage, "blockDevice", "profile.storage")
    mount_source = _string(storage, "mountSource", "profile.storage")
    sector_size = _integer(storage, "sectorSizeBytes", "profile.storage", minimum=1)
    sector_count = _integer(storage, "sectorCount", "profile.storage", minimum=1)
    if capacity != sector_size * sector_count:
        raise ProfileError("profile.storage: capacityBytes must equal sectorSizeBytes * sectorCount")
    technology = _string(storage, "technology", "profile.storage")
    filesystem = _string(storage, "filesystem", "profile.storage")
    removable = _boolean(storage, "removable", "profile.storage")
    sparse = _boolean(storage, "sparse", "profile.storage")
    if (
        variant != "128GB"
        or capacity != 128_000_000_000
        or block_device != "sda"
        or mount_source != "/dev/block/platform/14700000.ufs/by-name/userdata"
        or sector_size != 512
        or sector_count != 250_000_000
        or technology != "UFS 3.1"
        or filesystem != "f2fs"
        or removable
        or not sparse
    ):
        raise ProfileError("profile.storage: must match canonical Raven 128 GB UFS 3.1 f2fs geometry")


def _validate_battery(profile: dict[str, Any]) -> None:
    battery = _object(_required(profile, "battery", "profile"), "profile.battery")
    level = _integer(battery, "level", "profile.battery", minimum=0)
    scale = _integer(battery, "scale", "profile.battery", minimum=100)
    if scale != 100 or level > 100:
        raise ProfileError("profile.battery: capacity must be a percentage")
    voltage = _integer(battery, "voltage", "profile.battery", minimum=1000)
    temperature = _integer(
        battery, "temperature", "profile.battery", minimum=-500
    )
    status = _integer(battery, "status", "profile.battery", minimum=1)
    plugged = _integer(battery, "plugged", "profile.battery", minimum=0)
    health = _integer(battery, "health", "profile.battery", minimum=1)
    present = _integer(battery, "present", "profile.battery", minimum=0)
    if voltage > 6000 or temperature > 1000:
        raise ProfileError("profile.battery: voltage or temperature is out of range")
    if status > 5 or plugged not in {0, 1, 2, 4} or health > 7 or present > 1:
        raise ProfileError("profile.battery: Android battery enum is out of range")
    if (
        (plugged == 0 and status == 2)
        or (plugged != 0 and status == 3)
        or (status == 5 and level != scale)
    ):
        raise ProfileError("profile.battery: status and plugged state are inconsistent")
    if _string(battery, "technology", "profile.battery") != "Li-ion":
        raise ProfileError("profile.battery.technology: expected Li-ion")
    capacity_mah = _integer(battery, "capacityMah", "profile.battery", minimum=1)
    minimum_mah = _integer(battery, "minimumCapacityMah", "profile.battery", minimum=1)
    if minimum_mah > capacity_mah:
        raise ProfileError("profile.battery.minimumCapacityMah: exceeds typical capacity")
    design_uah = _integer(battery, "chargeFullDesignUah", "profile.battery", minimum=1)
    full_uah = _integer(battery, "chargeFullUah", "profile.battery", minimum=1)
    counter_uah = _integer(battery, "chargeCounterUah", "profile.battery", minimum=0)
    if design_uah != capacity_mah * 1000:
        raise ProfileError("profile.battery: chargeFullDesignUah must use microamp-hours")
    if full_uah > design_uah or counter_uah > full_uah:
        raise ProfileError("profile.battery: charge capacity ordering is invalid")
    if counter_uah != full_uah * level // scale:
        raise ProfileError("profile.battery: chargeCounterUah must follow level/scale")


def _validate_sensors(profile: dict[str, Any]) -> None:
    sensors = _array(_required(profile, "sensors", "profile"), "profile.sensors")
    if not sensors:
        raise ProfileError("profile.sensors: empty")
    handles: set[int] = set()
    type_strings: set[str] = set()
    by_type: dict[str, dict[str, Any]] = {}
    for index, raw_sensor in enumerate(sensors):
        path = f"profile.sensors[{index}]"
        sensor = _object(raw_sensor, path)
        handle = _integer(sensor, "handle", path, minimum=1)
        if handle in handles:
            raise ProfileError(f"{path}.handle: duplicate")
        handles.add(handle)
        _integer(sensor, "type", path, minimum=1)
        type_string = _string(sensor, "typeString", path)
        if type_string in type_strings:
            raise ProfileError(f"{path}.typeString: duplicate")
        type_strings.add(type_string)
        by_type[type_string] = sensor
        _string(sensor, "name", path)
        _string(sensor, "vendor", path)
        _integer(sensor, "version", path, minimum=1)
        _number(sensor, "maximumRange", path, minimum=0)
        _number(sensor, "resolution", path, minimum=0)
        _number(sensor, "powerMa", path, minimum=0)
        minimum_delay = _integer(sensor, "minimumDelayUs", path, minimum=0)
        maximum_delay = _integer(sensor, "maximumDelayUs", path, minimum=0)
        if maximum_delay and maximum_delay < minimum_delay:
            raise ProfileError(f"{path}.maximumDelayUs: below minimumDelayUs")
        _integer(sensor, "flags", path, minimum=0)
    required = {
        "android.sensor.accelerometer": "LSM6DSR Accelerometer",
        "android.sensor.gyroscope": "LSM6DSR Gyroscope",
        "android.sensor.magnetic_field": "MMC56X3X Magnetometer",
        "android.sensor.proximity": "TMD3719 Proximity",
        "android.sensor.light": "TMD3719 Light",
        "android.sensor.pressure": "ICP10101 Pressure",
        "com.google.sensor.rear_light": "VD6282 Rear Light Sensor",
    }
    for type_string, name in required.items():
        sensor = by_type.get(type_string)
        if sensor is None or sensor.get("name") != name:
            raise ProfileError(
                f"profile.sensors: missing canonical {type_string} sensor"
            )
    forbidden_markers = (
        "significant_motion",
        "uwb",
        "flicker",
        "temperature",
        "gesture",
    )
    if any(
        marker in type_string.lower()
        for type_string in by_type
        for marker in forbidden_markers
    ):
        raise ProfileError("profile.sensors: unsupported sensor claim")
    rear = by_type["com.google.sensor.rear_light"]
    if rear.get("handle") != 19 or rear.get("type") != 65545:
        raise ProfileError("profile.sensors: invalid VD6282 private sensor identity")
    characteristic_keys = (
        "maximumRange",
        "resolution",
        "powerMa",
        "minimumDelayUs",
        "maximumDelayUs",
    )
    for calibrated, uncalibrated in (
        (
            "android.sensor.accelerometer",
            "android.sensor.accelerometer_uncalibrated",
        ),
        ("android.sensor.gyroscope", "android.sensor.gyroscope_uncalibrated"),
        (
            "android.sensor.magnetic_field",
            "android.sensor.magnetic_field_uncalibrated",
        ),
    ):
        source = by_type.get(calibrated)
        raw = by_type.get(uncalibrated)
        if source is None or raw is None or any(
            source.get(key) != raw.get(key) for key in characteristic_keys
        ):
            raise ProfileError(
                f"profile.sensors: {uncalibrated} characteristics diverge"
            )
    fusion_types = {
        "android.sensor.step_counter",
        "android.sensor.step_detector",
        "android.sensor.game_rotation_vector",
        "android.sensor.geomagnetic_rotation_vector",
        "android.sensor.gravity",
        "android.sensor.linear_acceleration",
        "android.sensor.rotation_vector",
        "android.sensor.orientation",
    }
    if any(
        type_string not in by_type
        or by_type[type_string].get("vendor") != "Google LLC"
        or not str(by_type[type_string].get("name", "")).startswith("CHRE ")
        for type_string in fusion_types
    ):
        raise ProfileError("profile.sensors: invalid Pixel fusion sensor identity")


def _validate_cameras(profile: dict[str, Any]) -> None:
    cameras = _array(_required(profile, "cameras", "profile"), "profile.cameras")
    if not cameras:
        raise ProfileError("profile.cameras: empty")
    camera_ids: set[str] = set()
    for index, raw_camera in enumerate(cameras):
        path = f"profile.cameras[{index}]"
        camera = _object(raw_camera, path)
        camera_id = _string(camera, "id", path)
        if camera_id in camera_ids:
            raise ProfileError(f"{path}.id: duplicate")
        camera_ids.add(camera_id)
        if _string(camera, "facing", path) not in {"back", "front", "external"}:
            raise ProfileError(f"{path}.facing: invalid")
        for key in ("sensorPixelArray", "sensorPhysicalSizeMm"):
            dimensions = _object(_required(camera, key, path), f"{path}.{key}")
            _number(dimensions, "width", f"{path}.{key}", minimum=0.001)
            _number(dimensions, "height", f"{path}.{key}", minimum=0.001)
        _number(camera, "focalLengthMm", path, minimum=0.001)
        _number(camera, "aperture", path, minimum=0.001)
        _boolean(camera, "flashAvailable", path)
        _boolean(camera, "oisAvailable", path)
        physical_ids = _array(_required(camera, "physicalCameraIds", path), f"{path}.physicalCameraIds")
        if any(not isinstance(value, str) or not value for value in physical_ids):
            raise ProfileError(f"{path}.physicalCameraIds: expected non-empty strings")
        output_sizes = _array(_required(camera, "outputSizes", path), f"{path}.outputSizes")
        if not output_sizes:
            raise ProfileError(f"{path}.outputSizes: empty")
        seen_sizes: set[tuple[int, int]] = set()
        for size_index, raw_size in enumerate(output_sizes):
            size_path = f"{path}.outputSizes[{size_index}]"
            size = _object(raw_size, size_path)
            dimensions = (
                _integer(size, "width", size_path, minimum=1),
                _integer(size, "height", size_path, minimum=1),
            )
            if dimensions in seen_sizes:
                raise ProfileError(f"{size_path}: duplicate")
            seen_sizes.add(dimensions)


def _validate_misc(profile: dict[str, Any]) -> None:
    thermal = _object(_required(profile, "thermal", "profile"), "profile.thermal")
    if not thermal:
        raise ProfileError("profile.thermal: empty")
    for zone_name, raw_zone in thermal.items():
        zone = _object(raw_zone, f"profile.thermal.{zone_name}")
        _string(zone, "type", f"profile.thermal.{zone_name}")
        _integer(zone, "temp", f"profile.thermal.{zone_name}")

    ids = _object(_required(profile, "ids", "profile"), "profile.ids")
    for key in ("android_id", "boot_id", "serial", "imei", "imeisv"):
        _string(ids, key, "profile.ids")

    usb = _object(_required(profile, "usb", "profile"), "profile.usb")
    for key in ("manufacturer", "product", "vendor_id", "product_id", "serial"):
        _string(usb, key, "profile.usb")

    provenance = _object(_required(profile, "provenance", "profile"), "profile.provenance")
    if not provenance or any(not isinstance(value, str) or not value for value in provenance.values()):
        raise ProfileError("profile.provenance: expected non-empty string values")


def normalize(data: dict[str, Any], source_name: str = "") -> dict[str, Any]:
    del source_name
    root = _object(data, "document")
    profile = _object(root.get("profile", root), "profile")
    forbidden = sorted((FORBIDDEN_TOP_LEVEL | LEGACY_FLAT_FIELDS).intersection(profile))
    hardware_profile = profile.get("hardware_profile")
    if isinstance(hardware_profile, dict):
        forbidden.extend(f"hardware_profile.{key}" for key in ("mac", "wifi_mac") if key in hardware_profile)
    if forbidden:
        raise ProfileError("location/non-hardware fields are not device-profile owned: " + ", ".join(forbidden))
    if _string(profile, "schema", "profile") != SCHEMA:
        raise ProfileError(f"profile.schema: expected {SCHEMA}")
    template = _string(profile, "template", "profile")
    if not SLUG_RE.fullmatch(template):
        raise ProfileError("profile.template: expected lowercase path-safe identifier")

    normalized = copy.deepcopy(profile)
    _validate_build(normalized)
    _validate_display_and_input(normalized)
    _validate_cpu_memory_storage(normalized)
    _validate_battery(normalized)
    _validate_sensors(normalized)
    _validate_cameras(normalized)
    _validate_misc(normalized)
    return normalized


def convert_file(path: pathlib.Path, out_dir: pathlib.Path, overwrite: bool) -> pathlib.Path:
    data = json.loads(path.read_text(encoding="utf-8"))
    normalized = normalize(data, path.name)
    output = out_dir / f"{normalized['template']}.json"
    if output.exists() and not overwrite:
        raise FileExistsError(f"exists: {output.name}; pass --overwrite")
    out_dir.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=out_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize and strictly validate Xenoid device profiles"
    )
    parser.add_argument("source", help="JSON file or directory containing device profiles")
    parser.add_argument("--out-dir", default="examples/fingerprints/imported")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    source = pathlib.Path(args.source).expanduser().resolve()
    output_directory = pathlib.Path(args.out_dir).expanduser().resolve()
    files = sorted(source.rglob("*.json")) if source.is_dir() else [source]
    written: list[str] = []
    for path in files:
        try:
            written.append(str(convert_file(path, output_directory, args.overwrite)))
        except Exception as exc:
            print(
                json.dumps({"ok": False, "file": path.name, "error": str(exc)}, ensure_ascii=False),
                file=sys.stderr,
            )
            return 1
    print(json.dumps({"ok": True, "count": len(written), "files": written}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
