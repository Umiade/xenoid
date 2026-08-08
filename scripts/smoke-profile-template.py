#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
tpl = ROOT / "examples/fingerprints/pixel-husky-template.json"
profile = json.loads(tpl.read_text())
missing=[]
for k in ["brand","manufacturer","model","device","product","fingerprint","hardware","board","bootloader","tags","type","security_patch","first_api_level","sku","abi","abilist","abilist64","bionic_arch","dalvik_isa_arm64","dalvik_isa_arm"]:
    if not profile.get("build",{}).get(k): missing.append("build."+k)
# 64-only targets carry an empty but present 32-bit ABI list.
if "abilist32" not in profile.get("build",{}): missing.append("build.abilist32")
# Network/MAC identity is owned by the location layer; generic templates must
# not carry it (the daemon rejects such fields with location_identity_owned).
if "network" in profile or "wifi_mac" in profile.get("hardware_profile",{}): missing.append("network.present")
if not profile.get("sensors"): missing.append("sensors")
proc = subprocess.run([str(ROOT/"scripts/import-pixel-template.py"), str(tpl), "--out-dir", tempfile.mkdtemp(prefix="xenoid-template-"), "--overwrite"], text=True, capture_output=True, cwd=ROOT)
out={"ok": not missing and proc.returncode==0, "missing": missing, "importReturncode": proc.returncode, "importStdout": proc.stdout, "importStderr": proc.stderr}
print(json.dumps(out, indent=2))
sys.exit(0 if out["ok"] else 1)
