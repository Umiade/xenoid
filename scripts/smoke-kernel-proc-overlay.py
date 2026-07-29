#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_kernel_proc_misc" in src,
    "proc_uptime": "/proc/uptime" in src and "86400.00" in src,
    "proc_loadavg": "/proc/loadavg" in src,
    "proc_filesystems": "/proc/filesystems" in src and "f2fs" in src and "binder" in src,
    "proc_swaps": "/proc/swaps" in src,
    "kernel_osrelease": "/proc/sys/kernel/osrelease" in src and "android13" in src,
    "kernel_ostype": "/proc/sys/kernel/ostype" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "kernel_proc_misc=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
