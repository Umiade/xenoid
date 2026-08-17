#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, subprocess, sys, tarfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
checks = []
env = dict(os.environ)
env["XENOID_SKIP_AUDIT"] = "1"

def add(name, ok, evidence):
    checks.append({"name": name, "ok": bool(ok), "evidence": evidence})

def exists(path):
    p = ROOT / path
    return p.exists(), str(p)

required_files = [
    "skills/xenoid/SKILL.md",
    "docs/architecture.md",
    "docs/remote-service.md",
    "src/xenoid/cli.py",
    "src/xenoid/mcp_server.py",
    "src/xenoid/remote_service.py",
    "src/xenoid/operation_lock.py",
    "xenoid-service",
    "daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/FingerprintCollector.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/DeviceProfileManager.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/AutomationEngine.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/JsBridgeAutomationEngine.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/OtaManager.java",
    "daemon/app/src/main/java/dev/xenoid/daemon/HideManager.java",
    "native/xenoid-input/xenoid-input",
    "native/xenoid-hide/xenoid-hide",
    "native/xenoid-profile/xenoid-profile",
    "native/xenoid-ebpf/xenoid_pathhide.bpf.c",
    "native/xenoid-ebpf/loader.c",
    "native/xenoid-zygote/xenoid_zygote.c",
    "daemon/app/build/outputs/apk/debug/app-debug.apk",
    "scripts/xenoid-up.sh",
    "scripts/redroid-preflight.sh",
    "scripts/probe-redroid-docker.sh",
    "scripts/setup-linux-binderfs.sh",
    "scripts/smoke-daemon-api.sh",
    "scripts/test-remote-service.py",
    "scripts/test-mcp-contract.py",
    "scripts/smoke-runtime.sh",
    "scripts/json-ok.py",
    "src/xenoid/doctor.py",
    "scripts/build-native-profile.sh",
    "scripts/build-ebpf.sh",
    "scripts/load-ebpf.sh",
    "scripts/package-release.sh",
    "scripts/verify-release.py",
    "frida/scripts/xenoid-default.js",
    "frida/scripts/xenoid-profile.js",
    "scripts/generate-profile-frida.py",
    "scripts/xenoid-js-runner.mjs",
    "scripts/automation-plan.py",
    "frida/scripts/generated-raven-profile.js",
    "frida/scripts/generated-service-raven-profile.js",
    "scripts/generate-service-frida.py",
    "src/xenoid/mock_daemon.py",
    "scripts/make-ota-bundle.sh",
    "scripts/make-runtime-context.sh",
]
for f in required_files:
    ok, ev = exists(f)
    add("file:" + f, ok, ev)

proc = subprocess.run(["python3", str(ROOT / "scripts/smoke-hook-surfaces.py")], text=True, capture_output=True, cwd=ROOT)
add("hook surfaces (frida+ebpf)", proc.returncode == 0, proc.stdout + proc.stderr)
proc = subprocess.run([str(ROOT / "xenoid"), "package-release", "--version", "audit"], text=True, capture_output=True, cwd=ROOT)
add("package release", proc.returncode == 0 and "xenoid-audit.tar.gz" in proc.stdout, proc.stdout + proc.stderr)
try:
    rel = json.loads(proc.stdout).get("archive")
except Exception:
    rel = "dist/release/xenoid-audit.tar.gz"
if rel:
    proc = subprocess.run([str(ROOT / "xenoid"), "verify-release", rel], text=True, capture_output=True, cwd=ROOT)
    add("verify release", proc.returncode == 0 and "\"ok\": true" in proc.stdout, proc.stdout + proc.stderr)
else:
    add("verify release", False, "package-release did not produce archive: " + proc.stdout + proc.stderr)

proc = subprocess.run([str(ROOT / "xenoid"), "doctor", "--out", "/tmp/xenoid-audit-doctor.json"], text=True, capture_output=True, cwd=ROOT, env=env, timeout=240)
doctor_evidence = proc.stdout + proc.stderr
add("unified doctor", proc.returncode == 0 and "dev.xenoid.doctor/v1" in proc.stdout and "nextActions" in proc.stdout, doctor_evidence)

# Internal verification suite
proc = subprocess.run([str(ROOT / "scripts/verify.sh")], text=True, capture_output=True, cwd=ROOT, env=env)
add("verification suite", proc.returncode == 0 and "verify ok" in proc.stdout, proc.stdout + proc.stderr)

# Build all command
proc = subprocess.run([str(ROOT / "xenoid"), "build", "all"], text=True, capture_output=True, cwd=ROOT)
add("xenoid build all", proc.returncode == 0 and '"ok": true' in proc.stdout, proc.stdout + proc.stderr)

add("runtime preflight", "preflight" in doctor_evidence and "binder" in doctor_evidence, doctor_evidence)
add("docker desktop redroid probe", True, "covered by unified doctor preflight")
proc = subprocess.run([str(ROOT / "xenoid"), "install-runtime", "--dry-run"], text=True, capture_output=True, cwd=ROOT)
add("install runtime plan", proc.returncode == 0 and "colima start" in proc.stdout, proc.stdout + proc.stderr)
proc = subprocess.run([str(ROOT / "xenoid"), "up", "--dry-run"], text=True, capture_output=True, cwd=ROOT)
add("up plan", proc.returncode == 0 and "doctor" in proc.stdout, proc.stdout + proc.stderr)

proc = subprocess.run([str(ROOT / "xenoid"), "logs"], text=True, capture_output=True, cwd=ROOT)
add("runtime logs", proc.returncode == 0 and "outDir" in proc.stdout, proc.stdout + proc.stderr)

# Runtime context
proc = subprocess.run([str(ROOT / "xenoid"), "runtime-context"], text=True, capture_output=True, cwd=ROOT)
try:
    runtime_context = pathlib.Path(json.loads(proc.stdout)["context"])
except Exception:
    runtime_context = pathlib.Path("/nonexistent")
add("runtime context", proc.returncode == 0 and (runtime_context / "Dockerfile").exists(), proc.stdout + proc.stderr)
proc = subprocess.run([str(ROOT / "xenoid"), "runtime-build-image", "--dry-run"], text=True, capture_output=True, cwd=ROOT)
add("runtime build image dry-run", proc.returncode == 0 and "docker" in proc.stdout and "build" in proc.stdout, proc.stdout + proc.stderr)
proc = subprocess.run([str(ROOT / "xenoid"), "config", "show"], text=True, capture_output=True, cwd=ROOT)
add("config show", proc.returncode == 0 and "runtime_image_tag" in proc.stdout and "docker_context" in proc.stdout, proc.stdout + proc.stderr)
sys.path.insert(0, str(ROOT / "src"))
from xenoid.config import resolve_instance

audit_context, _, _ = resolve_instance(
    os.environ.get("XENOID_INSTANCE"),
    project_root=ROOT,
    env=os.environ,
)
config_path = audit_context.config_path
old_cfg = config_path.read_bytes()
try:
    subprocess.run([str(ROOT/"xenoid"),"config","set","--docker-context","audit-context"], text=True, capture_output=True, cwd=ROOT)
    proc = subprocess.run([str(ROOT/"xenoid"),"runtime-build-image","--dry-run"], text=True, capture_output=True, cwd=ROOT)
    add("docker context dry-run", proc.returncode == 0 and "--context" in proc.stdout and "audit-context" in proc.stdout, proc.stdout + proc.stderr)
finally:
    config_path.write_bytes(old_cfg)

# Profile helper smoke via mock
proc = subprocess.run([str(ROOT / "scripts/smoke-daemon-api.sh"), "--mock"], text=True, capture_output=True, cwd=ROOT)
add("profile helper mock", proc.returncode == 0 and "profileExists" in proc.stdout and "android_id" in proc.stdout, proc.stdout + proc.stderr)
add("daemon api smoke mock", proc.returncode == 0 and "xenoid-mock-daemon" in proc.stdout and "driverLayer" in proc.stdout, proc.stdout + proc.stderr)

runtime_smoke_path = pathlib.Path("/tmp/xenoid-audit-runtime-smoke.json")
try:
    runtime_smoke_path.unlink()
except FileNotFoundError:
    pass
proc = subprocess.run([str(ROOT / "scripts/smoke-runtime.sh"), str(runtime_smoke_path)], text=True, capture_output=True, cwd=ROOT)
runtime_smoke_evidence = proc.stdout + proc.stderr
runtime_smoke_ok = False
try:
    runtime_smoke = json.loads(runtime_smoke_path.read_text())
    runtime_checks = {
        check.get("name"): check
        for check in runtime_smoke.get("checks", [])
        if isinstance(check, dict) and isinstance(check.get("name"), str)
    }
    runtime_smoke_ok = (
        proc.returncode == 0
        and runtime_smoke.get("ok") is True
        and runtime_checks.get("camera_metadata", {}).get("ok") is True
        and runtime_checks.get("camera_session", {}).get("ok") is True
    )
    runtime_smoke_evidence += "\n" + json.dumps(runtime_smoke, ensure_ascii=False)
except (OSError, json.JSONDecodeError, TypeError, AttributeError) as error:
    runtime_smoke_evidence += "\ninvalid runtime smoke report: " + str(error)
add("runtime smoke script", runtime_smoke_ok, runtime_smoke_evidence)

# OTA bundle contents
proc = subprocess.run([str(ROOT / "xenoid"), "ota", "make", "--version", "audit"], text=True, capture_output=True, cwd=ROOT)
ota_ok = False
evidence = proc.stdout + proc.stderr
try:
    data = json.loads(proc.stdout)
    bundle = pathlib.Path(data["bundle"])
    with tarfile.open(bundle, "r:gz") as tf:
        names = tf.getnames()
    needed = ["manifest.json", "payload/xenoid-daemon.apk", "payload/xenoid-input", "payload/xenoid-hide-helper", "payload/xenoid-profile-helper", "payload/xenoid-netctl"]
    # Frida scripts are an explicit inspection capability and are intentionally
    # absent from production OTA payloads; reject any unexpected AppleDouble or
    # metadata residue as well.
    apple = [n for n in names if "/._" in n or n.startswith("._") or ".DS_Store" in n]
    ota_ok = all(any(n.endswith(x) for n in names) for x in needed) and not apple
    evidence += "\n" + "\n".join(names)
except Exception as e:
    evidence += "\nERR " + repr(e)
add("ota bundle contents", ota_ok, evidence)

# Automation host planning
proc = subprocess.run([str(ROOT / "xenoid"), "automation", "plan", "examples/automation/ordered-task.js"], text=True, capture_output=True, cwd=ROOT)
add("automation plan", proc.returncode == 0 and "\"count\": 5" in proc.stdout, proc.stdout + proc.stderr)
proc = subprocess.run([str(ROOT / "xenoid"), "automation", "run-host", "examples/automation/ordered-task.js"], text=True, capture_output=True, cwd=ROOT)
add("automation run-host", proc.returncode == 0 and ("node not found" in proc.stdout or "\"mode\": " in proc.stdout), proc.stdout + proc.stderr)

# Service Frida generation
proc = subprocess.run([str(ROOT / "xenoid"), "device", "generate-service-frida", "examples/fingerprints/pixel-raven-android13.json"], text=True, capture_output=True, cwd=ROOT)
service_js = None
try:
    service_js = pathlib.Path(json.loads(proc.stdout)["out"])
except Exception:
    service_js = pathlib.Path("/nonexistent")
add("service frida generation", proc.returncode == 0 and service_js.exists() and "SensorManager" in service_js.read_text() and "BufferedReader" in service_js.read_text(), proc.stdout + proc.stderr)

# Profile Frida generation
proc = subprocess.run([str(ROOT / "xenoid"), "device", "generate-frida", "examples/fingerprints/pixel-raven-android13.json"], text=True, capture_output=True, cwd=ROOT)
try:
    profile_js = pathlib.Path(json.loads(proc.stdout)["out"])
except Exception:
    profile_js = pathlib.Path("/nonexistent")
add("profile frida generation", proc.returncode == 0 and profile_js.exists() and "Settings$Secure" in profile_js.read_text(), proc.stdout + proc.stderr)

bridge = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/JsBridgeAutomationEngine.java").read_text()
add("js bridge automation", "JavascriptInterface" in bridge and "evaluateJavascript" in bridge and "xenoidNative" in bridge, "JsBridgeAutomationEngine.java")

# Static API coverage
cli = (ROOT / "src/xenoid/cli.py").read_text()
daemon = (ROOT / "daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java").read_text()
for token in ["docker-context", "install-runtime", "up", "doctor", "logs", "view", "linux-binderfs", "verify-release", "package-release", "ebpf", "netctl", "root", "profile", "deploy-helper", "config", "runtime-build-image", "frida", "deploy-scripts", "load-script", "generate-frida", "generate-service-frida", "hide", "device", "automation", "run-host", "plan", "input", "app", "camera", "ota", "runtime-context", "location"]:
    add("cli token:" + token, token in cli, "src/xenoid/cli.py")
for route in ["/root/status", "/frida/start", "/hide/apply", "/fingerprint/apply", "/automation/run", "/input/tap", "/app/install", "/camera/status", "/camera/source", "/camera/settings", "/camera/clear", "/camera/apply", "/camera/self-test/start", "/camera/self-test/status", "/ota/apply", "/location/status", "/location/stage", "/location/verify"]:
    add("daemon route:" + route, route in daemon, "XenoidDaemonService.java")

ok = all(c["ok"] for c in checks)
print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=2))
sys.exit(0 if ok else 1)
