#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
checks = {}
profile_path = ROOT / "examples/fingerprints/pixel-raven-android13.json"
profile = json.loads(profile_path.read_text())
input_profile = profile.get("input") or {}
display_profile = profile.get("display") or {}
checks["template_input_identity"] = (
    input_profile.get("name") == "sec_touchscreen"
    and input_profile.get("busType") == 24
    and input_profile.get("vendorId") == 0x04E8
    and input_profile.get("productId") == 0x6860
    and input_profile.get("version") == 0x0100
)
checks["template_input_axes"] = (
    input_profile.get("x") == {"minimum": 0, "maximum": display_profile.get("width") - 1}
    and input_profile.get("y") == {"minimum": 0, "maximum": display_profile.get("height") - 1}
    and input_profile.get("pressure") == {"minimum": 0, "maximum": 255}
    and input_profile.get("trackingId") == {"minimum": 0, "maximum": 31}
)
td = pathlib.Path(tempfile.mkdtemp(prefix="xenoid-input-template-"))
proc = subprocess.run([str(ROOT/"scripts/import-pixel-template.py"), str(profile_path), "--out-dir", str(td), "--overwrite"], text=True, capture_output=True, cwd=ROOT)
imported = next(td.glob("*.json"), None)
imported_data = json.loads(imported.read_text()) if imported and imported.exists() else {}
checks["import_preserves_input"] = proc.returncode == 0 and imported_data.get("input") == input_profile
out = {"ok": all(checks.values()), "checks": checks, "imported": str(imported) if imported else None, "importStdout": proc.stdout, "importStderr": proc.stderr}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
