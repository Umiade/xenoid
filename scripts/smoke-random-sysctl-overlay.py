#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()


def list_block(name: str) -> str:
    match = re.search(rf"static const char \*{name}\[\] = \{{(.*?)\}};", src, re.S)
    return match.group(1) if match else ""


UUID_PATH = "/proc/sys/kernel/random/uuid"
overlay = list_block("overlay_targets")
deprecated = list_block("deprecated_dynamic_targets")
checks = {
    "overlay_function": "overlay_random_sysctls" in src,
    "entropy": "/proc/sys/kernel/random/entropy_avail" in src and "4096" in src,
    "poolsize": "/proc/sys/kernel/random/poolsize" in src,
    "reseed": "urandom_min_reseed_secs" in src,
    "boot_id_still": "/proc/sys/kernel/random/boot_id" in src,
    "apply_calls": "random_sysctls=ok" in src,
    # The retired static-UUID bind mount must exist only as a cleanup-only
    # legacy target: present in deprecated_dynamic_targets, absent from the
    # creation lists, and unmounted by apply/cleanup/revert. A re-add to any
    # creation path or another reference (e.g. in overlay_random_sysctls)
    # fails this check.
    "retired_uuid_cleanup": UUID_PATH in deprecated
    and UUID_PATH not in overlay
    and src.count(UUID_PATH) == deprecated.count(UUID_PATH)
    and "cleanup_target_list(mi, deprecated_dynamic_targets)" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
