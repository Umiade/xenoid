#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = ROOT / "native/xenoid-input/xenoid_input.c"
text = src.read_text()
root_helper = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/RootHelper.java").read_text()
runtime_context = (ROOT / "scripts/make-runtime-context.sh").read_text()
checks = {
    "no_xenoid_device_name": "xenoid-uinput-touch" not in text,
    "profile_json_runtime_path": "profile_json_path" in text and "effective.json" in text,
    "realistic_default_name": "sec_touchscreen" in text,
    "status_command": "status" in text and "dev.input/v2" in text,
    "filters_minitouch_marker": "minitouch" in text and "sec_touchscreen" in text,
    "abs_mt_slot": "ABS_MT_SLOT" in text,
    "direct_touch_property": "INPUT_PROP_DIRECT" in text,
    "contact_axes": all(axis in text for axis in [
        "ABS_MT_TOUCH_MAJOR", "ABS_MT_TOUCH_MINOR", "ABS_MT_WIDTH_MAJOR", "ABS_MT_WIDTH_MINOR",
    ]),
    "pressure_axes": "ABS_PRESSURE" in text and "ABS_MT_PRESSURE" in text,
    "absolute_timing": "CLOCK_MONOTONIC" in text and "TIMER_ABSTIME" in text,
    "single_native_gesture_path": "htap" not in text and "hswipe" not in text,
    "daemon_requires_native": "execRootd(" in root_helper
        and "framework input fallback is disabled" in root_helper
        and "input tap " not in root_helper
        and "input swipe " not in root_helper,
    "persistent_native_service": "xenoid-input /system/bin/xenoid-input serve" in runtime_context
        and "COPY payload/xenoid-input /system/bin/xenoid-input" in runtime_context
        and "publish_event_node" in text
        and "persistentDevice" in text,
}
# Build source-level plus run binary status on host is not possible for Android ELF, but compile is covered by build all.
profile = json.loads((ROOT / "examples/fingerprints/pixel-husky-template.json").read_text())
for k in ["input_name","input_bustype","input_vendor","input_product","input_version","display_width","display_height","pressure_max","tracking_max"]:
    checks["template_" + k] = k in profile and profile[k] not in (None, "")
td = pathlib.Path(tempfile.mkdtemp(prefix="xenoid-input-template-"))
proc = subprocess.run([str(ROOT/"scripts/import-pixel-template.py"), str(ROOT/"examples/fingerprints/pixel-husky-template.json"), "--out-dir", str(td), "--overwrite"], text=True, capture_output=True, cwd=ROOT)
imported = next(td.glob("*.json"), None)
imported_data = json.loads(imported.read_text()) if imported and imported.exists() else {}
checks["import_preserves_input"] = proc.returncode == 0 and imported_data.get("input_name") == "sec_touchscreen" and isinstance(imported_data.get("input"), dict)
binp = ROOT / "native/xenoid-input/xenoid-input"
if binp.exists():
    import subprocess as _sp
    st = _sp.run(["strings", str(binp)], text=True, capture_output=True)
    bad = [x for x in ["xenoid-uinput-touch", "minitouch", "frida", "dev.xenoid.input", "xenoid-profile"] if x in st.stdout]
    checks["binary_no_static_markers"] = not bad
else:
    bad = []
out = {"ok": all(checks.values()), "checks": checks, "badStaticMarkers": bad, "imported": str(imported) if imported else None, "importStdout": proc.stdout, "importStderr": proc.stderr}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
