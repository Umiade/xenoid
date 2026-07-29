#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_cpu_sysfs_details" in src,
    "cpu0_max_freq": "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq" in src or "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" in src,
    "cpu0_min_freq": "cpuinfo_min_freq" in src,
    "scaling_cur_freq": "scaling_cur_freq" in src,
    "scaling_governor": "schedutil" in src,
    "topology_core_id": "topology/core_id" in src,
    "topology_package": "physical_package_id" in src,
    "siblings": "thread_siblings_list" in src and "core_siblings_list" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "cpu_sysfs_details=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
