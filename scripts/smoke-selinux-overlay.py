#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_overlay.c").read_text()
hide = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/HideManager.java").read_text()
checks = {
    "overlay_function": "overlay_selinuxfs" in src,
    "enforce_target": "/sys/fs/selinux/enforce" in src and "selinux_enforce" in src,
    "policyvers_target": "/sys/fs/selinux/policyvers" in src and "33\\n" in src,
    "mls_target": "/sys/fs/selinux/mls" in src,
    "optional_mount": "overlay_text_optional" in src,
    "apply_calls": "selinuxfs=ok" in src,
    "hide_apply_reapplies_overlay": "xenoid-overlay-helper apply" in hide,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
