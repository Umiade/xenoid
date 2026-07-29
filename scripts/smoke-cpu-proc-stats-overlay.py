#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_cpu_proc_stats" in src,
    "proc_stat": "/proc/stat" in src and "cpu7" in src and "cpu8" not in src.split('overlay_cpu_proc_stats',1)[1].split('return fail',1)[0],
    "softirqs": "/proc/softirqs" in src and "CPU7" in src,
    "schedstat": "/proc/schedstat" in src and "version 15" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "cpu_proc_stats=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
