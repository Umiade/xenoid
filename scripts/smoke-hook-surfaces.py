#!/usr/bin/env python3
"""Behavioral gate for production app-, sensor-, and system-layer surfaces."""
from __future__ import annotations

import ctypes
import json
import math
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

frida_js = (ROOT / "frida/scripts/xenoid-default.js").read_text()
ebpf_bpf = (ROOT / "native/xenoid-ebpf/xenoid_pathhide.bpf.c").read_text()
ebpf_loader = (ROOT / "native/xenoid-ebpf/loader.c").read_text()
zygote = (ROOT / "native/xenoid-zygote/xenoid_zygote.c").read_text()
cli = (ROOT / "src/xenoid/cli.py").read_text()
backend = (ROOT / "src/xenoid/backend.py").read_text()
sensor_profile = json.loads(
    (ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text()
)["sensors"]


class SensorSpec(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_int32),
        ("type", ctypes.c_int32),
        ("type_string", ctypes.c_char_p),
        ("name", ctypes.c_char_p),
        ("vendor", ctypes.c_char_p),
        ("version", ctypes.c_int32),
        ("maximum_range", ctypes.c_float),
        ("resolution", ctypes.c_float),
        ("power_ma", ctypes.c_float),
        ("minimum_delay_us", ctypes.c_int32),
        ("maximum_delay_us", ctypes.c_int32),
        ("flags", ctypes.c_int32),
    ]


def sensor_catalog_checks() -> tuple[dict[str, bool], str]:
    compiler = (
        shutil.which("c++")
        or shutil.which("clang++")
        or shutil.which("g++")
    )
    if compiler is None:
        return {"sensor_catalog_compiles": False}, "host C++ compiler not found"
    source = ROOT / "native/xenoid-sensorshal/sensor_catalog.cpp"
    with tempfile.TemporaryDirectory(prefix="xenoid-sensor-catalog-") as temporary:
        library = pathlib.Path(temporary) / (
            "libxenoid-sensors.dylib"
            if sys.platform == "darwin"
            else "libxenoid-sensors.so"
        )
        build = subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                "-dynamiclib" if sys.platform == "darwin" else "-shared",
                "-I",
                str(source.parent),
                str(source),
                "-o",
                str(library),
            ],
            text=True,
            capture_output=True,
        )
        if build.returncode != 0:
            return {
                "sensor_catalog_compiles": False
            }, f"{build.stdout}\n{build.stderr}".strip()
        native = ctypes.CDLL(str(library))
        catalog = native.xenoid_sensor_catalog
        catalog.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
        catalog.restype = ctypes.POINTER(SensorSpec)
        scalar_sample = native.xenoid_sensor_scalar_sample
        scalar_sample.argtypes = [
            ctypes.c_int32,
            ctypes.c_double,
            ctypes.POINTER(ctypes.c_float),
        ]
        scalar_sample.restype = ctypes.c_int
        period_valid = native.xenoid_sensor_period_valid
        period_valid.argtypes = [
            ctypes.c_int32,
            ctypes.c_int32,
            ctypes.c_int64,
            ctypes.c_int64,
        ]
        period_valid.restype = ctypes.c_int

        count = ctypes.c_size_t()
        pointer = catalog(ctypes.byref(count))
        actual = [pointer[index] for index in range(count.value)]
        expected_by_handle = {sensor["handle"]: sensor for sensor in sensor_profile}
        actual_by_handle = {sensor.handle: sensor for sensor in actual}

        def matches(sensor: SensorSpec, expected: dict[str, object]) -> bool:
            exact = (
                sensor.handle == expected["handle"]
                and sensor.type == expected["type"]
                and sensor.type_string.decode() == expected["typeString"]
                and sensor.name.decode() == expected["name"]
                and sensor.vendor.decode() == expected["vendor"]
                and sensor.version == expected["version"]
                and sensor.minimum_delay_us == expected["minimumDelayUs"]
                and sensor.maximum_delay_us == expected["maximumDelayUs"]
                and sensor.flags == expected["flags"]
            )
            floats = (
                (sensor.maximum_range, expected["maximumRange"]),
                (sensor.resolution, expected["resolution"]),
                (sensor.power_ma, expected["powerMa"]),
            )
            return exact and all(
                math.isclose(
                    actual_value,
                    float(expected_value),
                    rel_tol=1e-5,
                    abs_tol=1e-7,
                )
                for actual_value, expected_value in floats
            )

        names = {sensor.name.decode() for sensor in actual}
        types = {sensor.type_string.decode() for sensor in actual}
        required_names = {
            "LSM6DSR Accelerometer",
            "LSM6DSR Gyroscope",
            "MMC56X3X Magnetometer",
            "TMD3719 Proximity",
            "TMD3719 Light",
            "ICP10101 Pressure",
            "VD6282 Rear Light Sensor",
        }
        forbidden_markers = (
            "LSM6DSO",
            "MMC5602",
            "TMD3725",
            "BMP380",
            "Significant Motion",
            "UWB",
            "Flicker",
            "Temperature",
            "Gesture",
        )
        raw_pairs = ((1, 7), (2, 8), (3, 9))
        characteristic = lambda sensor: (
            sensor.maximum_range,
            sensor.resolution,
            sensor.power_ma,
            sensor.minimum_delay_us,
            sensor.maximum_delay_us,
        )
        fusion_handles = (10, 11, 13, 14, 15, 16, 17, 18)
        rear_values: list[float] = []
        rear_sample_ok = True
        for seconds in (0.0, 1.0, 10.0):
            value = ctypes.c_float()
            rear_sample_ok = rear_sample_ok and (
                scalar_sample(65545, seconds, ctypes.byref(value)) == 0
            )
            rear_values.append(value.value)
        rear_maximum = expected_by_handle[19]["maximumRange"]
        checks = {
            "sensor_catalog_compiles": True,
            "sensor_catalog_matches_profile": (
                len(actual) == len(sensor_profile)
                and set(actual_by_handle) == set(expected_by_handle)
                and all(
                    matches(actual_by_handle[handle], expected)
                    for handle, expected in expected_by_handle.items()
                )
            ),
            "sensor_handles_unique": len(actual_by_handle) == len(actual),
            "sensor_required_names": required_names.issubset(names),
            "sensor_forbidden_claims_absent": (
                "android.sensor.significant_motion" not in types
                and not any(
                    marker.lower() in name.lower()
                    for name in names
                    for marker in forbidden_markers
                )
            ),
            "sensor_private_rear_identity": (
                actual_by_handle.get(19) is not None
                and actual_by_handle[19].type == 65545
                and actual_by_handle[19].type_string.decode()
                == "com.google.sensor.rear_light"
            ),
            "sensor_raw_characteristics_match": all(
                characteristic(actual_by_handle[calibrated])
                == characteristic(actual_by_handle[uncalibrated])
                for calibrated, uncalibrated in raw_pairs
            ),
            "sensor_fusion_identity": all(
                actual_by_handle[handle].name.decode().startswith("CHRE ")
                and actual_by_handle[handle].vendor.decode() == "Google LLC"
                for handle in fusion_handles
            ),
            "sensor_rear_event_is_bounded_scalar": (
                rear_sample_ok
                and len({round(value, 4) for value in rear_values}) > 1
                and all(0.0 <= value <= float(rear_maximum) for value in rear_values)
            ),
            "sensor_unknown_private_event_rejected": (
                scalar_sample(
                    65546, 1.0, ctypes.byref(ctypes.c_float())
                )
                != 0
            ),
            "sensor_batch_bounds": (
                period_valid(5000, 200000, 5_000_000, 0) == 1
                and period_valid(5000, 200000, 200_000_000, 0) == 1
                and period_valid(5000, 200000, 4_999_999, 0) == 0
                and period_valid(5000, 200000, 200_000_001, 0) == 0
                and period_valid(0, 0, 1, 0) == 1
                and period_valid(0, 0, 0, 0) == 0
                and period_valid(5000, 200000, 5_000_000, -1) == 0
            ),
        }
        return checks, ""


sensor_checks, sensor_error = sensor_catalog_checks()
checks = {
    "frida_script_exists": len(frida_js) > 0,
    "frida_hooks_file_exists": "File.exists" in frida_js,
    "frida_hooks_runtime_exec": "Runtime" in frida_js and "exec" in frida_js,
    "frida_hooks_system_properties": "SystemProperties" in frida_js,
    "frida_no_fake_sensor_injection": (
        "Sensor.$new" not in frida_js
        and "sensorEvent" not in frida_js.replace(" ", "")
    ),
    **sensor_checks,
    "ebpf_bpf_source": "file_open" in ebpf_bpf,
    "ebpf_loader": len(ebpf_loader) > 0,
    "ebpf_scripts": (
        (ROOT / "scripts/build-ebpf.sh").exists()
        and (ROOT / "scripts/load-ebpf.sh").exists()
    ),
    "zygote_build_spoof": (
        "raven" in zygote
        or "TP1A.221005.002" in zygote
        or "ro.build" in zygote
    ),
    "cli_has_frida": (
        '"frida"' in cli
        or 'add_parser("frida"' in cli
        or "add_parser('frida'" in cli
    ),
    "cli_has_ebpf": (
        '"ebpf"' in cli
        or 'add_parser("ebpf"' in cli
        or "add_parser('ebpf'" in cli
    ),
    "cli_no_dead_zygisk_magisk": all(
        token not in cli
        for token in (
            "cmd_build_zygisk",
            "cmd_package_magisk",
            "cmd_hook_backend",
            "cmd_magisk_status",
            "cmd_magisk_install_module",
        )
    ),
    "backend_no_dead_magisk_hooks": all(
        token not in backend
        for token in (
            "hook_backend_status",
            "hook_backend_set",
            "magisk_status",
            "magisk_install_module",
        )
    ),
}
missing = [key for key, value in checks.items() if not value]
print(
    json.dumps(
        {
            "ok": not missing,
            "missing": missing,
            "checks": checks,
            **({"sensorError": sensor_error} if sensor_error else {}),
        },
        indent=2,
        sort_keys=True,
    )
)
raise SystemExit(0 if not missing else 1)
