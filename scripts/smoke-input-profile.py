#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, re, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = ROOT / "native/xenoid-input/xenoid_input.c"
text = src.read_text()
checks = {
    "no_xenoid_device_name": "xenoid-uinput-touch" not in text,
    "profile_json_runtime_path": "profile_json_path" in text and "effective.json" in text,
    "realistic_default_name": "sec_touchscreen" in text,
    "status_command": "status" in text and "dev.input/v1" in text,
    "filters_minitouch_marker": "minitouch" in text and "sec_touchscreen" in text,
    "abs_mt_slot": "ABS_MT_SLOT" in text,
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
