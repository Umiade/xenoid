#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
checks = {
    "overlay_function": "overlay_random_sysctls" in src,
    "uuid": "/proc/sys/kernel/random/uuid" in src and "random_uuid" in src,
    "entropy": "/proc/sys/kernel/random/entropy_avail" in src and "4096" in src,
    "poolsize": "/proc/sys/kernel/random/poolsize" in src,
    "reseed": "urandom_min_reseed_secs" in src,
    "boot_id_still": "/proc/sys/kernel/random/boot_id" in src,
    "apply_calls": "random_sysctls=ok" in src,
    "daemon_random_uuid": "random_uuid" in daemon and "UUID.randomUUID" in daemon,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
