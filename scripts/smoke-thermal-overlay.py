#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
checks = {}
profile = json.loads((ROOT / "examples/fingerprints/pixel-raven-android13.json").read_text())
thermal = profile.get("thermal") or {}
checks["template_thermal"] = bool(thermal.get("zone0", {}).get("type")) and "temp" in thermal.get("zone0", {})
td = pathlib.Path(tempfile.mkdtemp(prefix="xenoid-thermal-template-"))
proc = subprocess.run([str(ROOT/"scripts/import-pixel-template.py"), str(ROOT/"examples/fingerprints/pixel-raven-android13.json"), "--out-dir", str(td), "--overwrite"], text=True, capture_output=True, cwd=ROOT)
imported = next(td.glob("*.json"), None)
idata = json.loads(imported.read_text()) if imported and imported.exists() else {}
checks["import_preserves_thermal"] = proc.returncode == 0 and (idata.get("thermal") or {}).get("zone0", {}).get("type") == "skin" and (idata.get("thermal") or {}).get("zone0", {}).get("temp") == 32000
out = {"ok": all(checks.values()), "checks": checks, "imported": str(imported) if imported else None, "importStdout": proc.stdout, "importStderr": proc.stderr}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
