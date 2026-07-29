#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_power_supply" in src,
    "battery_capacity": "/sys/class/power_supply/battery/capacity" in src,
    "battery_voltage": "/sys/class/power_supply/battery/voltage_now" in src,
    "battery_temp": "/sys/class/power_supply/battery/temp" in src,
    "battery_status": "/sys/class/power_supply/battery/status" in src and "battery_status_text" in src,
    "battery_health": "/sys/class/power_supply/battery/health" in src and "battery_health_text" in src,
    "usb_online": "/sys/class/power_supply/usb/online" in src,
    "optional_mount": "overlay_text_optional" in src,
    "profile_files": all(x in src for x in ["battery_level", "battery_temperature", "battery_voltage", "battery_status", "battery_plugged", "battery_health", "battery_present"]),
    "apply_calls": "power_supply=ok" in src,
}
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
bat = profile.get("battery") or {}
for k in ["level", "scale", "voltage", "temperature", "status", "plugged", "health", "present"]:
    checks["template_battery_" + k] = k in bat
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
