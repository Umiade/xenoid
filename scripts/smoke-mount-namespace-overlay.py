#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
checks = {
    "sidecar_marker": "target_marker_path" in src and "marker_mounted" in src and "mark_mounted" in src,
    "status_uses_resolved_mountinfo": "resolve_overlay_target(overlay_targets[i]" in src and "count_in_mountinfo(mi, t)" in src,
    "mountinfo_read_fails_closed": "static char *read_mountinfo(void)" in src
    and "if (!mi) return -1;" in src,
    "private_mount_failure_rolls_back": "if (mount(NULL, t, NULL, MS_PRIVATE, NULL) != 0)" in src
    and "umount2(t, MNT_DETACH)" in src,
    "overlay_function": "overlay_mount_namespace_texts" in src,
    "stale_marker_repair": "Stale-marker repair" in src,
    "self_views_excluded_by_design": "/proc/{self,net}" in src,
    "reader_relative_mounts": '"/proc/mounts"' not in src,
    "pid1_mountinfo": "/proc/1/mountinfo" in src and "/proc/1/cgroup" in src,
    "pid1_mounts": "/proc/1/mounts" in src and "/proc/1/mountstats" in src,
    "proc_cgroups": "/proc/cgroups" in src,
    "android_like_mounts": "/dev/block/dm-0" in src and "f2fs" in src,
    "no_bad_defaults": all(x not in src.split('overlay_mount_namespace_texts',1)[1].split('return fail',1)[0].lower() for x in ["docker", "containerd", "overlayfs", "upperdir", "lowerdir"]),
    "apply_calls": "mount_namespace=ok" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
