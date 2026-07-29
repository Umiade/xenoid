#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_rtc_sysfs" in src,
    "rtc_name": "/sys/class/rtc/rtc0/name" in src and "rtc-pm8xxx" in src,
    "rtc_date_time": "/sys/class/rtc/rtc0/date" in src and "/sys/class/rtc/rtc0/time" in src,
    "rtc_epoch": "/sys/class/rtc/rtc0/since_epoch" in src and "1715040000" in src,
    "rtc_hctosys": "/sys/class/rtc/rtc0/hctosys" in src,
    "proc_driver_rtc": "/proc/driver/rtc" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "rtc_sysfs=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
