#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "overlay_function": "overlay_proc_identity_tables" in src,
    "status_targets": "/proc/1/status" in src,
    "uid_gid_maps": "/proc/1/uid_map" in src and "/proc/1/gid_map" in src,
    "attr_current": "/proc/1/attr/current" in src and "u:r:init:s0" in src,
    "self_views_excluded_by_design": "/proc/{self,net}" in src,
    "tracer_zero": "TracerPid:\\t0" in src,
    "nspid_single": "NSpid:\\t1" in src,
    "cpu_allowed": "Cpus_allowed_list:\\t0-7" in src,
    "apply_calls": "proc_identity_tables=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
