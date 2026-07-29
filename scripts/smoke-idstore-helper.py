#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys, re
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "native/xenoid-hide/xenoid_ssaid.c").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java").read_text()
checks = {
    "ssaid_file": "settings_ssaid.xml" in src,
    "secure_file": "settings_secure.xml" in src,
    "patch_secure_xml": "patch_secure_xml" in src,
    "patch_ssaid": "patch_ssaid" in src,
    "android_id_setting": "name=\\\"android_id\\\"" in src or "name='android_id'" in src,
    "daemon_calls_helper": "xenoid-ssaid" in daemon and "settings put secure android_id" in daemon,
    "lowercase_value": "lower16" in src,
}
out = {"ok": all(checks.values()), "checks": checks}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
