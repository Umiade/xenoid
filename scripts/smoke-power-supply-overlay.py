#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = json.loads(
    (ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text()
)["battery"]
SOURCE = ROOT / "native/xenoid-hide/xenoid_power_supply.c"
INCLUDE = SOURCE.parent
FILE_COUNT = 14
VALUE_MAX = 768


class BatteryProfile(ctypes.Structure):
    _fields_ = [
        ("level", ctypes.c_long),
        ("scale", ctypes.c_long),
        ("voltage_mv", ctypes.c_long),
        ("temperature_deci_c", ctypes.c_long),
        ("status", ctypes.c_long),
        ("plugged", ctypes.c_long),
        ("health", ctypes.c_long),
        ("present", ctypes.c_long),
        ("technology", ctypes.c_char_p),
        ("capacity_mah", ctypes.c_long),
        ("minimum_capacity_mah", ctypes.c_long),
        ("charge_full_design_uah", ctypes.c_long),
        ("charge_full_uah", ctypes.c_long),
        ("charge_counter_uah", ctypes.c_long),
    ]


class BatteryFile(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("value", ctypes.c_char * VALUE_MAX),
    ]


def native_profile(**overrides: int | str) -> BatteryProfile:
    values: dict[str, int | str] = {
        "level": PROFILE["level"],
        "scale": PROFILE["scale"],
        "voltage": PROFILE["voltage"],
        "temperature": PROFILE["temperature"],
        "status": PROFILE["status"],
        "plugged": PROFILE["plugged"],
        "health": PROFILE["health"],
        "present": PROFILE["present"],
        "technology": PROFILE["technology"],
        "capacityMah": PROFILE["capacityMah"],
        "minimumCapacityMah": PROFILE["minimumCapacityMah"],
        "chargeFullDesignUah": PROFILE["chargeFullDesignUah"],
        "chargeFullUah": PROFILE["chargeFullUah"],
        "chargeCounterUah": PROFILE["chargeCounterUah"],
    }
    values.update(overrides)
    return BatteryProfile(
        int(values["level"]),
        int(values["scale"]),
        int(values["voltage"]),
        int(values["temperature"]),
        int(values["status"]),
        int(values["plugged"]),
        int(values["health"]),
        int(values["present"]),
        str(values["technology"]).encode(),
        int(values["capacityMah"]),
        int(values["minimumCapacityMah"]),
        int(values["chargeFullDesignUah"]),
        int(values["chargeFullUah"]),
        int(values["chargeCounterUah"]),
    )


compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
if compiler is None:
    print(json.dumps({"ok": False, "error": "host C compiler not found"}))
    raise SystemExit(1)

with tempfile.TemporaryDirectory(prefix="xenoid-battery-smoke-") as temporary:
    library = pathlib.Path(temporary) / (
        "libxenoid-battery.dylib" if sys.platform == "darwin" else "libxenoid-battery.so"
    )
    shared_flag = "-dynamiclib" if sys.platform == "darwin" else "-shared"
    build = subprocess.run(
        [
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            shared_flag,
            "-I",
            str(INCLUDE),
            str(SOURCE),
            "-o",
            str(library),
        ],
        text=True,
        capture_output=True,
    )
    if build.returncode != 0:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "battery renderer compilation failed",
                    "stdout": build.stdout,
                    "stderr": build.stderr,
                },
                indent=2,
            )
        )
        raise SystemExit(1)

    renderer = ctypes.CDLL(str(library), use_errno=True)
    render = renderer.xenoid_render_battery_files
    render.argtypes = [
        ctypes.POINTER(BatteryProfile),
        ctypes.POINTER(BatteryFile),
        ctypes.c_size_t,
    ]
    render.restype = ctypes.c_int
    files = (BatteryFile * FILE_COUNT)()
    canonical = native_profile()
    render_result = render(ctypes.byref(canonical), files, FILE_COUNT)
    rendered = {
        files[index].name.decode(): files[index].value.decode()
        for index in range(FILE_COUNT)
        if files[index].name
    }

required = {
    "capacity",
    "status",
    "health",
    "present",
    "temp",
    "voltage_now",
    "technology",
    "capacity_level",
    "charge_full_design",
    "charge_full",
    "charge_counter",
    "type",
    "online",
    "uevent",
}
uevent = dict(
    line.split("=", 1)
    for line in rendered.get("uevent", "").splitlines()
    if "=" in line
)
invalid_state = native_profile(status=2, plugged=0)
invalid_units = native_profile(chargeFullDesignUah=PROFILE["chargeFullDesignUah"] // 1000)
scratch = (BatteryFile * FILE_COUNT)()
checks = {
    "rendered": render_result == 0,
    "complete_directory": set(rendered) == required,
    "capacity_percent": rendered.get("capacity") == "83\n",
    "voltage_microvolts": rendered.get("voltage_now") == "4100000\n",
    "temperature_deci_celsius": rendered.get("temp") == "310\n",
    "status_mapping": rendered.get("status") == "Discharging\n",
    "health_mapping": rendered.get("health") == "Good\n",
    "technology_mapping": rendered.get("technology") == "Li-ion\n",
    "charge_full_design_microamp_hours": (
        rendered.get("charge_full_design") == "5003000\n"
    ),
    "charge_full_microamp_hours": rendered.get("charge_full") == "5003000\n",
    "charge_counter_microamp_hours": (
        rendered.get("charge_counter") == "4152490\n"
    ),
    "uevent_matches_leaf_values": (
        uevent.get("POWER_SUPPLY_CAPACITY") == rendered.get("capacity", "").strip()
        and uevent.get("POWER_SUPPLY_STATUS") == rendered.get("status", "").strip()
        and uevent.get("POWER_SUPPLY_HEALTH") == rendered.get("health", "").strip()
        and uevent.get("POWER_SUPPLY_CHARGE_FULL_DESIGN")
        == rendered.get("charge_full_design", "").strip()
        and uevent.get("POWER_SUPPLY_CHARGE_FULL")
        == rendered.get("charge_full", "").strip()
        and uevent.get("POWER_SUPPLY_CHARGE_COUNTER")
        == rendered.get("charge_counter", "").strip()
    ),
    "rejects_inconsistent_plug_state": (
        render(ctypes.byref(invalid_state), scratch, FILE_COUNT) != 0
    ),
    "rejects_wrong_capacity_units": (
        render(ctypes.byref(invalid_units), scratch, FILE_COUNT) != 0
    ),
}
out = {"ok": all(checks.values()), "checks": checks, "rendered": rendered}
print(json.dumps(out, indent=2))
raise SystemExit(0 if out["ok"] else 1)
