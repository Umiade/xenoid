#!/usr/bin/env bash
# GateRunner-owned, non-recursive microG runtime acceptance.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTANCE="${XENOID_INSTANCE:-default}"
if [[ "${1:-}" == "--instance" ]]; then
  [[ $# -eq 2 ]] || { echo "--instance requires a name" >&2; exit 2; }
  INSTANCE="$2"
  shift 2
fi
[[ $# -eq 0 ]] || { echo "unknown argument: $1" >&2; exit 2; }
exec python3 - "$ROOT" "$INSTANCE" <<'PY'
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
INSTANCE = sys.argv[2]
PACKAGE = "org.example.googleservicesruntimeprobe"
PROBE_SCHEMA = "dev.xenoid.google-services-probe/v2"
SMOKE_SCHEMA = "dev.xenoid.google-services-smoke/v2"
STATUS_SCHEMA = "dev.xenoid.google-services-status/v2"
RELEASE = "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
GOOGLE_CERT = "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"
MICROG_CERT = "9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GateFailure(Exception):
    pass


def log(message):
    sys.stderr.write(f"[google-services-gate] {message}\n")
    sys.stderr.flush()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest_json(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, *, timeout=300, check=True, cwd=ROOT):
    try:
        result = subprocess.run(
            [str(item) for item in command],
            cwd=str(cwd),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise GateFailure("command_timeout") from error
    if check and result.returncode != 0:
        argv_tail = " ".join(str(item) for item in command)[-120:]
        log(
            f"command exited {result.returncode}: {argv_tail}: "
            f"{(result.stderr or result.stdout or '')[-300:]}"
        )
        raise GateFailure("command_failed")
    return result


def json_output(result, code):
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise GateFailure(code) from error
    if not isinstance(value, dict):
        raise GateFailure(code)
    return value


def xenoid(*arguments, timeout=300, check=True):
    return run(
        [ROOT / "xenoid", "--instance", INSTANCE, *arguments],
        timeout=timeout,
        check=check,
    )


def xenoid_json(*arguments, timeout=300, check=True, code="xenoid_result_invalid"):
    return json_output(xenoid(*arguments, timeout=timeout, check=check), code)


def adb_shell(command, *, timeout=60):
    value = xenoid_json("adb", "shell", command, timeout=timeout, code="adb_result_invalid")
    if value.get("ok") is not True or not isinstance(value.get("stdout"), str):
        raise GateFailure("adb_command_failed")
    return value["stdout"]


def require_sha(value, code):
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise GateFailure(code)
    return value


def google_status():
    value = xenoid_json(
        "google-services", "status", "--require-runtime",
        timeout=240,
        code="google_status_invalid",
    )
    if (
        value.get("schema") != STATUS_SCHEMA
        or value.get("ok") is not True
        or value.get("ready") is not True
        or value.get("provider") != "microg"
        or value.get("release") != RELEASE
        or value.get("implementation") != "microg"
        or value.get("signatureModel") != "restricted-spoofing"
        or value.get("storeImplementation") != "google-play"
    ):
        raise GateFailure("google_runtime_not_ready")
    require_sha(value.get("specSha256"), "google_spec_invalid")
    runtime_identity = value.get("runtimeIdentity")
    binding = value.get("binding")
    components = value.get("effectiveComponents")
    live = value.get("live")
    if (
        not isinstance(runtime_identity, dict)
        or not isinstance(binding, dict)
        or binding.get("state") != "committed"
        or not isinstance(components, dict)
        or set(components) != {"gmsCore", "gsfProxy", "playStoreSeed"}
        or not isinstance(live, dict)
        or live.get("ok") is not True
    ):
        raise GateFailure("google_status_contract_mismatch")
    checks = live.get("checks")
    if not isinstance(checks, dict) or any(
        not isinstance(check, dict) or check.get("ok") is not True
        for check in checks.values()
    ):
        raise GateFailure("google_live_checks_failed")
    desired_input = require_sha(
        runtime_identity.get("desiredInputSha256"), "runtime_input_invalid")
    image_match = runtime_identity.get("imageMatch")
    container_input = runtime_identity.get("containerInputSha256")
    if (
        image_match not in {"exact", "daemon-only"}
        or image_match == "daemon-only" and container_input != desired_input
        or image_match == "exact" and container_input not in {None, desired_input}
        or runtime_identity.get("rootfsBootInputMatches") is not True
        or runtime_identity.get("labelsMatch") is not True
        or runtime_identity.get("commandMatch") is not True
    ):
        raise GateFailure("runtime_identity_mismatch")
    return value


def runtime_status():
    value = xenoid_json("status", timeout=180, code="runtime_status_invalid")
    identity = value.get("runtimeIdentity")
    if (
        value.get("ok") is not True
        or value.get("running") is not True
        or value.get("containerContractMatches") is not True
        or not isinstance(identity, dict)
    ):
        raise GateFailure("runtime_status_not_ready")
    for key in ("containerId", "imageId", "dataUuid"):
        if not isinstance(identity.get(key), str) or not identity[key]:
            raise GateFailure("runtime_status_identity_invalid")
    return value


def snapshot():
    runtime = runtime_status()
    google = google_status()
    identity = runtime["runtimeIdentity"]
    google_identity = google["runtimeIdentity"]
    if google_identity.get("containerImageSha256") != identity["imageId"]:
        raise GateFailure("runtime_image_identity_mismatch")
    return {
        "containerId": identity["containerId"],
        "dataUuid": identity["dataUuid"],
        "imageId": identity["imageId"],
        "binding": google["binding"],
        "bindingSha256": digest_json(google["binding"]),
        "runtimeInputSha256": require_sha(
            google_identity.get("desiredInputSha256"), "runtime_input_invalid"),
        "runtimeIdentity": google_identity,
        "effectiveComponents": google["effectiveComponents"],
        "effectiveComponentsSha256": digest_json(google["effectiveComponents"]),
        "google": google,
    }


def same_persistent_state(baseline, observed, code):
    for key in (
        "containerId", "dataUuid", "imageId", "bindingSha256",
        "runtimeInputSha256", "effectiveComponentsSha256",
    ):
        if observed[key] != baseline[key]:
            raise GateFailure(code)
    if observed["runtimeIdentity"] != baseline["runtimeIdentity"]:
        raise GateFailure(code)


def validate_noop_result(value):
    plan = value.get("plan")
    return bool(
        value.get("schema") == "dev.xenoid.convergence/v1"
        and value.get("ok") is True
        and value.get("dryRun") is False
        and isinstance(plan, dict)
        and plan.get("artifactTargets") == []
        and plan.get("imageAction") == "reuse-selected"
        and plan.get("runtimeAction") == "reuse"
        and plan.get("bootSeedAction") == "none"
        and plan.get("recreateReasons") == []
    )


def validate_restart_result(value):
    plan = value.get("plan")
    return bool(
        value.get("schema") == "dev.xenoid.convergence/v1"
        and value.get("ok") is True
        and value.get("dryRun") is False
        and isinstance(plan, dict)
        and plan.get("artifactTargets") == []
        and plan.get("imageAction") == "reuse-selected"
        and plan.get("runtimeAction") == "start"
        and plan.get("bootSeedAction") == "none"
        and plan.get("recreateReasons") == []
    )


def sdk_root():
    command = (
        'source "$1/scripts/android-sdk-root.sh"; '
        'xenoid_android_sdk_root'
    )
    result = run(["bash", "-c", command, "bash", str(ROOT)], timeout=30)
    path = Path(result.stdout.strip()).resolve()
    tools = path / "build-tools" / "35.0.0"
    platform = path / "platforms" / "android-35" / "android.jar"
    for name in ("aapt2", "zipalign", "apksigner"):
        if not (tools / name).is_file() or not os.access(tools / name, os.X_OK):
            raise GateFailure("android_build_tools_unavailable")
    if not platform.is_file() or shutil.which("keytool") is None:
        raise GateFailure("android_build_tools_unavailable")
    return tools, platform


def verify_imported_gmscore(tools):
    apk = ROOT / ".xenoid" / "artifacts" / "google-services" / RELEASE / "com.google.android.gms-250932030.apk"
    if not apk.is_file() or apk.is_symlink():
        raise GateFailure("gmscore_asset_unavailable")
    result = run([tools / "apksigner", "verify", "--print-certs", apk], timeout=180)
    matches = re.findall(
        r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]{64,95})", result.stdout)
    digests = {match.replace(":", "").lower() for match in matches}
    if digests != {MICROG_CERT}:
        raise GateFailure("gmscore_real_signature_mismatch")


def parse_probe_log(raw):
    for line in reversed(raw.splitlines()):
        if "{" not in line or "}" not in line:
            continue
        payload = line[line.index("{"):line.rindex("}") + 1]
        try:
            value = json.loads(payload)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("schema") == PROBE_SCHEMA:
            return value
    raise GateFailure("probe_result_unavailable")


def validate_probe(value):
    packages = value.get("packages")
    negative = value.get("negativeSignature")
    capabilities = value.get("capabilities")
    if (
        value.get("schema") != PROBE_SCHEMA
        or value.get("ok") is not True
        or value.get("provider") != "microg"
        or not isinstance(packages, dict)
        or not isinstance(negative, dict)
        or negative.get("unlistedPackageNotSpoofed") is not True
        or not isinstance(capabilities, dict)
    ):
        raise GateFailure("probe_contract_mismatch")
    expected = {
        "com.google.android.gms": (250932030, "0.3.15.250932", GOOGLE_CERT, True),
        "com.google.android.gsf": (8, "v0.1.0", MICROG_CERT, True),
        "com.android.vending": (83041710, None, GOOGLE_CERT, False),
    }
    for package, (minimum, version_name, signer, exact) in expected.items():
        record = packages.get(package)
        if not isinstance(record, dict) or record.get("ok") is not True:
            raise GateFailure("probe_component_mismatch")
        version_code = record.get("versionCode")
        if not isinstance(version_code, int) or isinstance(version_code, bool):
            raise GateFailure("probe_component_mismatch")
        if (exact and version_code != minimum) or (not exact and version_code < minimum):
            raise GateFailure("probe_component_mismatch")
        if version_name is not None and record.get("versionName") != version_name:
            raise GateFailure("probe_component_mismatch")
        if record.get("legacySignersSha256") != [signer]:
            raise GateFailure("probe_signature_mismatch")
        if record.get("signingInfoSha256") != [signer]:
            raise GateFailure("probe_signature_mismatch")
    fused = value.get("fusedProvider")
    if not isinstance(fused, dict) or fused.get("available") is not True:
        raise GateFailure("probe_fused_provider_unavailable")
    for name in ("playIntegrity", "deviceCertification", "drm", "antiCheat"):
        if capabilities.get(name) != {
            "scope": "application",
            "runtimeState": "unsupported",
            "releaseState": "unsupported",
            "evidence": "unsupported",
        }:
            raise GateFailure("probe_capability_contract_mismatch")


def run_probe(temp, baseline):
    build = run([ROOT / "tests" / "google-services-runtime-probe" / "build.sh"], timeout=600)
    lines = [line.strip() for line in build.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise GateFailure("probe_build_result_invalid")
    apk = Path(lines[0]).resolve()
    if not apk.is_file():
        raise GateFailure("probe_apk_unavailable")
    apk_digest = file_sha256(apk)
    xenoid("adb", "uninstall", PACKAGE, timeout=90, check=False)
    install = xenoid("adb", "install", "-r", apk, timeout=180)
    if json_output(install, "probe_install_result_invalid").get("ok") is not True:
        raise GateFailure("probe_install_failed")
    xenoid_json("adb", "shell", "logcat -c", timeout=60, code="logcat_reset_failed")
    launched = xenoid_json(
        "adb", "shell", f"am start -W -n {PACKAGE}/.ProbeActivity",
        timeout=90,
        code="probe_launch_invalid",
    )
    if launched.get("ok") is not True:
        raise GateFailure("probe_launch_failed")
    device = None
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        time.sleep(1.0)
        logcat = xenoid_json(
            "adb", "shell", "logcat -d -s XenoidGoogleServicesProbe:I",
            timeout=60,
            code="probe_logcat_invalid",
        )
        if logcat.get("ok") is not True or not isinstance(logcat.get("stdout"), str):
            continue
        try:
            device = parse_probe_log(logcat["stdout"])
            break
        except GateFailure:
            continue
    if device is None:
        raise GateFailure("probe_result_unavailable")
    validate_probe(device)
    result = dict(device)
    result.update({
        "instance": INSTANCE,
        "provider": "microg",
        "release": RELEASE,
        "specSha256": baseline["google"]["specSha256"],
        "package": PACKAGE,
        "apkSha256": apk_digest,
    })
    return result


def build_wrong_signer_apk(temp, tools, platform, version_code):
    source = temp / "wrong-signer"
    source.mkdir(mode=0o700)
    manifest = source / "AndroidManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        f'package="com.google.android.gms" android:versionCode="{version_code}" '
        'android:versionName="xenoid-wrong-signer">\n'
        '  <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="35" />\n'
        '  <application android:allowBackup="false" android:debuggable="false" android:hasCode="false" />\n'
        '</manifest>\n',
        encoding="utf-8",
    )
    unsigned = source / "unsigned.apk"
    aligned = source / "aligned.apk"
    signed = source / "wrong-signer.apk"
    keystore = source / "wrong-signer.keystore"
    run([tools / "aapt2", "link", "-o", unsigned, "-I", platform, "--manifest", manifest])
    run([tools / "zipalign", "-f", "4", unsigned, aligned])
    run([
        "keytool", "-genkeypair", "-noprompt", "-keystore", keystore,
        "-storepass", "android", "-keypass", "android", "-alias", "wrong",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
        "-dname", "CN=Xenoid Wrong Signer,O=Example,C=US",
    ])
    run([
        tools / "apksigner", "sign", "--ks", keystore,
        "--ks-pass", "pass:android", "--key-pass", "pass:android",
        "--out", signed, aligned,
    ])
    run([tools / "apksigner", "verify", signed])
    return signed


def reject_wrong_signer(temp, tools, platform, before):
    gms = before["effectiveComponents"].get("gmsCore")
    if not isinstance(gms, dict):
        raise GateFailure("effective_gmscore_unavailable")
    current_version = gms.get("versionCode")
    if not isinstance(current_version, int) or isinstance(current_version, bool):
        raise GateFailure("effective_gmscore_unavailable")
    if current_version >= 2147483646:
        raise GateFailure("effective_gmscore_version_unsupported")
    apk = build_wrong_signer_apk(temp, tools, platform, current_version + 1)
    result = xenoid("adb", "install", "-r", apk, timeout=180, check=False)
    if result.returncode == 0:
        raise GateFailure("different_signer_update_accepted")
    evidence = (result.stdout + "\n" + result.stderr).lower()
    markers = (
        "install_failed_update_incompatible",
        "install_failed_shared_user_incompatible",
        "signatures do not match",
        "signature mismatch",
        "update incompatible",
    )
    if not any(marker in evidence for marker in markers):
        raise GateFailure("different_signer_rejection_unproven")
    after = snapshot()
    before_gms = before["effectiveComponents"]["gmsCore"]
    after_gms = after["effectiveComponents"]["gmsCore"]
    unchanged = (
        before_gms.get("versionCode") == after_gms.get("versionCode")
        and before_gms.get("codePath") == after_gms.get("codePath")
        and before_gms.get("signerSha256") == after_gms.get("signerSha256")
    )
    if not unchanged:
        raise GateFailure("effective_gmscore_changed")
    return after, unchanged


def process_identity():
    output = adb_shell(
        'pid="$(pidof com.google.android.gms:persistent)"; '
        'case "$pid" in ""|*" "*) exit 9;; esac; cat "/proc/$pid/stat"',
        timeout=30,
    ).strip()
    try:
        pid = int(output.split(" ", 1)[0])
        start_ticks = int(output.rsplit(")", 1)[1].split()[19])
    except (IndexError, ValueError) as error:
        raise GateFailure("gmscore_process_identity_invalid") from error
    return pid, start_ticks


def verify_instrumentation_inactive(restart_started_at):
    status_result = xenoid("frida", "status", timeout=60, check=False)
    status = json_output(status_result, "frida_status_invalid")
    if (
        status.get("ok") is not False
        or status.get("rootdReachable") is not True
        or not isinstance(status.get("exit"), int)
        or status.get("exit") == 0
        or str(status.get("stdout") or "").strip()
    ):
        raise GateFailure("frida_status_active")
    command = (
        "if pidof frida-server .fs64 svc.bin >/dev/null 2>&1; then exit 21; fi; "
        "for path in /data/local/tmp/frida-server /data/local/tmp/.fs64 "
        "/data/local/tmp/re.frida.server /data/system/.core/svc.bin "
        "/data/local/tmp/xenoid-frida /data/local/tmp/xenoid-frida-scripts; do "
        "test ! -e $path || exit 22; done; printf inactive"
    )
    inactive = xenoid_json("root", "exec", command, timeout=60, code="frida_files_check_invalid")
    if inactive.get("ok") is not True or inactive.get("stdout") != "inactive":
        raise GateFailure("instrumentation_files_present")

    config = ROOT / ".xenoid" / "instances" / INSTANCE / "config.json"
    try:
        config_value = json.loads(config.read_text(encoding="utf-8"))
        instance_id = config_value["instance_id"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise GateFailure("instance_state_unavailable") from error
    if not isinstance(instance_id, str) or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            instance_id) is None:
        raise GateFailure("instance_state_invalid")
    state_root = Path.home() / ".xenoid" / "instances" / instance_id
    if not state_root.is_dir() or state_root.is_symlink():
        raise GateFailure("instance_state_unavailable")

    def timestamp(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            result = float(value)
            return result / 1000.0 if result > 100000000000.0 else result
        if isinstance(value, str):
            text = value.strip()
            if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", text):
                return timestamp(float(text))
            try:
                return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
        return None

    stopped = []
    seen = 0
    for directory, directories, files in os.walk(state_root, followlinks=False):
        directories[:] = [name for name in directories if not (Path(directory) / name).is_symlink()]
        for name in files:
            lowered = name.lower()
            if "frida" not in lowered and "instrument" not in lowered:
                continue
            seen += 1
            if seen > 256:
                raise GateFailure("instrumentation_state_unbounded")
            path = Path(directory) / name
            try:
                if path.is_symlink() or path.stat().st_size > 256 * 1024:
                    raise GateFailure("instrumentation_state_invalid")
                document = json.loads(path.read_text(encoding="utf-8"))
            except GateFailure:
                raise
            except (OSError, ValueError) as error:
                raise GateFailure("instrumentation_state_invalid") from error
            pending = [document]
            while pending:
                item = pending.pop()
                if isinstance(item, dict):
                    for key, value in item.items():
                        key_text = str(key).lower()
                        if "stop" in key_text and ("at" in key_text or "time" in key_text):
                            if value is None or value == "":
                                continue
                            parsed = timestamp(value)
                            if parsed is None:
                                raise GateFailure("instrumentation_state_invalid")
                            stopped.append(parsed)
                        elif isinstance(value, (dict, list)):
                            pending.append(value)
                elif isinstance(item, list):
                    pending.extend(value for value in item if isinstance(value, (dict, list)))
    if stopped and max(stopped) > restart_started_at:
        raise GateFailure("runtime_epoch_precedes_instrumentation_stop")


def empty_report():
    return {
        "schema": SMOKE_SCHEMA,
        "ok": False,
        "instance": INSTANCE,
        "provider": "microg",
        "release": RELEASE,
        "specSha256": None,
        "runtimeInputSha256": None,
        "probe": None,
        "processStability": {
            "gmsCoreStable": False,
            "playStoreState": "failed",
            "noAnr": False,
            "noCrashLoop": False,
        },
        "negativeSignature": {
            "unlistedPackageNotSpoofed": False,
            "differentSignerUpdateRejected": False,
            "effectiveGmsCoreUnchanged": False,
        },
        "noOpPasses": [],
        "instrumentationInactive": False,
        "error": "google_services_gate_failed",
    }


def execute(temp):
    log("checking the selected microG runtime")
    tools, platform = sdk_root()
    baseline = snapshot()
    verify_imported_gmscore(tools)
    no_op_passes = []
    for number in (1, 2):
        log(f"running no-op convergence pass {number}")
        result = xenoid_json(
            "up", "--skip-build", timeout=7200, code="convergence_result_invalid")
        if not validate_noop_result(result):
            raise GateFailure("convergence_not_noop")
        observed = snapshot()
        same_persistent_state(baseline, observed, "convergence_identity_changed")
        no_op_passes.append({
            "pass": True,
            "containerId": observed["containerId"],
            "dataUuid": observed["dataUuid"],
            "bindingSha256": observed["bindingSha256"],
            "runtimeInputSha256": observed["runtimeInputSha256"],
            "imageId": observed["imageId"],
            "effectiveComponentsSha256": observed["effectiveComponentsSha256"],
            "noBuild": True,
            "noRecreate": True,
        })

    log("running stop/start persistence pass")
    restart_started_at = time.time()
    stopped = xenoid_json("stop", timeout=300, code="stop_result_invalid")
    if stopped.get("ok") is not True:
        raise GateFailure("runtime_stop_failed")
    restarted = xenoid_json(
        "up", "--skip-build", timeout=7200, code="restart_result_invalid")
    if not validate_restart_result(restarted):
        raise GateFailure("runtime_restart_not_persistent")
    post_restart = snapshot()
    same_persistent_state(baseline, post_restart, "restart_identity_changed")
    verify_instrumentation_inactive(restart_started_at)

    log("running the non-debuggable application probe")
    probe = run_probe(temp, post_restart)
    unlisted = probe["negativeSignature"]["unlistedPackageNotSpoofed"] is True

    log("proving a different-signer GmsCore update is rejected")
    post_rejection, unchanged = reject_wrong_signer(temp, tools, platform, post_restart)
    same_persistent_state(post_restart, post_rejection, "negative_update_changed_runtime")

    log("checking provider process stability")
    first = process_identity()
    time.sleep(5.0)
    second = process_identity()
    direct_stable = first == second
    google = google_status()
    live = google["live"]
    checks = live["checks"]
    process_check = checks.get("processStability")
    components = google["effectiveComponents"]
    play_state = components.get("playStoreSeed", {}).get("processState")
    if (
        not direct_stable
        or not isinstance(process_check, dict)
        or process_check.get("ok") is not True
        or play_state not in {"stable", "dormant"}
    ):
        raise GateFailure("provider_process_unstable")

    return {
        "schema": SMOKE_SCHEMA,
        "ok": True,
        "instance": INSTANCE,
        "provider": "microg",
        "release": RELEASE,
        "specSha256": post_restart["google"]["specSha256"],
        "runtimeInputSha256": post_restart["runtimeInputSha256"],
        "probe": probe,
        "processStability": {
            "gmsCoreStable": True,
            "playStoreState": play_state,
            "noAnr": True,
            "noCrashLoop": True,
        },
        "negativeSignature": {
            "unlistedPackageNotSpoofed": unlisted,
            "differentSignerUpdateRejected": True,
            "effectiveGmsCoreUnchanged": unchanged,
        },
        "noOpPasses": no_op_passes,
        "instrumentationInactive": True,
        "error": None,
    }


report = empty_report()
exit_code = 1
with tempfile.TemporaryDirectory(prefix="xenoid-google-services-gate-") as temporary:
    temp = Path(temporary)
    try:
        report = execute(temp)
        exit_code = 0
    except GateFailure as error:
        report["error"] = str(error)
        log(f"failed: {error}")
    except Exception as error:
        report["error"] = "google_services_gate_internal_error"
        log(f"failed: {error.__class__.__name__}")
    finally:
        try:
            xenoid("adb", "uninstall", PACKAGE, timeout=90, check=False)
        except Exception:
            pass

expected_keys = {
    "schema", "ok", "instance", "provider", "release", "specSha256",
    "runtimeInputSha256", "probe", "processStability", "negativeSignature",
    "noOpPasses", "instrumentationInactive", "error",
}
if set(report) != expected_keys:
    report = empty_report()
    report["error"] = "google_services_gate_result_invalid"
    exit_code = 1
sys.stdout.write(canonical(report) + "\n")
sys.stdout.flush()
raise SystemExit(exit_code)
PY
