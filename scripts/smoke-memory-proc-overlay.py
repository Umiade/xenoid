#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_memory_proc_details" in src,
    "vmstat": "/proc/vmstat" in src and "nr_free_pages" in src,
    "zoneinfo": "/proc/zoneinfo" in src and "Node 0, zone   Normal" in src,
    "buddyinfo": "/proc/buddyinfo" in src and "Node 0" in src,
    "pagetypeinfo": "/proc/pagetypeinfo" in src and "Page block order" in src,
    "single_node": "Node 1" not in src.split('overlay_memory_proc_details',1)[1].split('return fail',1)[0],
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "memory_proc_details=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
