#!/usr/bin/env bash
# Build the complete artifact/runtime-image closure twice without Docker cache,
# then prove that the verified content tag is reused on the next normal build.
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
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
INSTANCE = sys.argv[2]
SCHEMA = "dev.xenoid.google-reproducibility/v1"
RELEASE = "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReproFailure(Exception):
    pass


def log(message):
    sys.stderr.write(f"[google-reproducibility] {message}\n")
    sys.stderr.flush()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def run(command, *, timeout=7200, check=True):
    try:
        result = subprocess.run(
            [str(item) for item in command],
            cwd=str(ROOT),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ReproFailure("command_timeout") from error
    if check and result.returncode != 0:
        raise ReproFailure("command_failed")
    return result


def parse_document(result, code):
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise ReproFailure(code) from error
    if not isinstance(value, dict):
        raise ReproFailure(code)
    return value


def xenoid(*arguments, timeout=7200, check=True):
    return run(
        [ROOT / "xenoid", "--instance", INSTANCE, *arguments],
        timeout=timeout,
        check=check,
    )


def xenoid_json(*arguments, timeout=7200, check=True, code="xenoid_result_invalid"):
    return parse_document(
        xenoid(*arguments, timeout=timeout, check=check), code)


def require_sha(value, code):
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ReproFailure(code)
    return value


def empty_report():
    return {
        "schema": SCHEMA,
        "ok": False,
        "artifactManifestSha256A": None,
        "artifactManifestSha256B": None,
        "contextManifestSha256A": None,
        "contextManifestSha256B": None,
        "inputSha256A": None,
        "inputSha256B": None,
        "bootInputSha256A": None,
        "bootInputSha256B": None,
        "imageIdA": None,
        "imageIdB": None,
        "contentTagReused": False,
        "error": "google_reproducibility_failed",
    }


def configured_docker():
    config_path = ROOT / ".xenoid" / "instances" / INSTANCE / "config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReproFailure("instance_config_unavailable") from error
    if (
        not isinstance(config, dict)
        or config.get("google_services_provider") != "microg"
        or config.get("google_services_release") != RELEASE
    ):
        raise ReproFailure("microg_provider_not_selected")
    context = config.get("docker_context")
    if context is None:
        context = ""
    if not isinstance(context, str) or "\x00" in context or len(context) > 128:
        raise ReproFailure("docker_context_invalid")
    command = ["docker"]
    if context.strip():
        command.extend(["--context", context.strip()])
    probe = run([*command, "version", "--format", "{{.Server.Version}}"], timeout=60)
    if not probe.stdout.strip():
        raise ReproFailure("docker_engine_unavailable")
    return command


def build_artifact_closure(label):
    log(f"building clean artifact closure {label}")
    value = xenoid_json(
        "build", "all", "--force",
        timeout=7200,
        code="artifact_build_result_invalid",
    )
    manifest = require_sha(value.get("manifestSha256"), "artifact_manifest_invalid")
    targets = value.get("targets")
    if (
        value.get("schema") != "dev.xenoid.artifacts/v1"
        or value.get("ok") is not True
        or value.get("status") != "passed"
        or not isinstance(targets, dict)
        or not targets
        or any(
            not isinstance(record, dict)
            or record.get("status") not in {"built", "reused"}
            for record in targets.values()
        )
    ):
        raise ReproFailure("artifact_build_failed")
    return manifest


def desired_input():
    value = xenoid_json(
        "runtime-build-image", "--dry-run",
        timeout=900,
        code="runtime_input_result_invalid",
    )
    if value.get("ok") is not True or value.get("dryRun") is not True:
        raise ReproFailure("runtime_input_invalid")
    for key in ("inputSha256", "bootInputSha256", "artifactManifestSha256"):
        require_sha(value.get(key), "runtime_input_invalid")
    tag = value.get("derivedTag")
    if (
        not isinstance(tag, str)
        or not tag
        or len(tag) > 255
        or any(character.isspace() for character in tag)
    ):
        raise ReproFailure("runtime_content_tag_invalid")
    return value


def record_path(input_sha):
    require_sha(input_sha, "runtime_input_invalid")
    return ROOT / ".xenoid" / "cache" / "runtime-images" / f"{input_sha}.json"


def remove_record(input_sha):
    path = record_path(input_sha)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ReproFailure("runtime_image_record_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ReproFailure("runtime_image_record_invalid")
    path.unlink()


def remove_content_tag(docker, tag):
    inspected = run([*docker, "image", "inspect", tag], timeout=60, check=False)
    if inspected.returncode != 0:
        return
    removed = run([*docker, "image", "rm", tag], timeout=300, check=False)
    if removed.returncode != 0:
        raise ReproFailure("runtime_content_tag_prune_failed")
    remaining = run([*docker, "image", "inspect", tag], timeout=60, check=False)
    if remaining.returncode == 0:
        raise ReproFailure("runtime_content_tag_prune_failed")


def release_owned_container(docker):
    """Stop and remove the instance's owned container when it pins the tag.

    The runtime image content tag cannot be pruned while a container
    references it. The instance data volume is untouched; a later
    ``up --skip-build`` recreates the container from the reused image.
    """
    status = xenoid_json("status", timeout=120, code="runtime_status_invalid")
    instance = status.get("instance")
    container_id = instance.get("container") if isinstance(instance, dict) else None
    if not isinstance(container_id, str) or not container_id:
        return
    inspect = run(
        [*docker, "container", "inspect", container_id, "--format", "{{json .Config.Labels}}"],
        timeout=60,
        check=False,
    )
    if inspect.returncode != 0:
        return
    try:
        labels = json.loads(inspect.stdout or "{}")
    except ValueError:
        labels = {}
    if not isinstance(labels, dict) or not labels.get("dev.xenoid.owner"):
        raise ReproFailure("runtime_container_ownership_invalid")
    xenoid_json("stop", timeout=600, code="runtime_stop_invalid")
    removed = run([*docker, "container", "rm", container_id], timeout=300, check=False)
    if removed.returncode != 0:
        raise ReproFailure("runtime_container_remove_failed")


def clean_runtime_build_state(docker, desired):
    remove_content_tag(docker, desired["derivedTag"])
    remove_record(desired["inputSha256"])


def load_record(input_sha):
    path = record_path(input_sha)
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 1024 * 1024
        ):
            raise ReproFailure("runtime_image_record_invalid")
        value = json.loads(path.read_text(encoding="ascii"))
    except ReproFailure:
        raise
    except (OSError, ValueError, UnicodeError) as error:
        raise ReproFailure("runtime_image_record_invalid") from error
    if not isinstance(value, dict) or value.get("inputSha256") != input_sha:
        raise ReproFailure("runtime_image_record_invalid")
    for key in (
        "artifactManifestSha256", "contextManifestSha256", "inputSha256",
        "bootInputSha256",
    ):
        require_sha(value.get(key), "runtime_image_record_invalid")
    if IMAGE_ID.fullmatch(str(value.get("imageId") or "")) is None:
        raise ReproFailure("runtime_image_record_invalid")
    return value


def build_runtime_image(label, desired):
    log(f"building clean runtime image {label}")
    value = xenoid_json(
        "runtime-build-image",
        timeout=7200,
        code="runtime_image_build_result_invalid",
    )
    if (
        value.get("schema") != "dev.xenoid.runtime-image/v1"
        or value.get("ok") is not True
        or value.get("reused") is not False
        or value.get("inputSha256") != desired["inputSha256"]
        or value.get("bootInputSha256") != desired["bootInputSha256"]
        or value.get("derivedTag") != desired["derivedTag"]
        or IMAGE_ID.fullmatch(str(value.get("imageId") or "")) is None
    ):
        raise ReproFailure("runtime_image_clean_build_unproven")
    record = load_record(desired["inputSha256"])
    if (
        record["imageId"] != value["imageId"]
        or record["bootInputSha256"] != value["bootInputSha256"]
        or record["artifactManifestSha256"] != desired["artifactManifestSha256"]
    ):
        raise ReproFailure("runtime_image_record_mismatch")
    return record


def execute():
    docker = configured_docker()
    release_owned_container(docker)

    build_artifact_closure("A")
    desired_a = desired_input()
    clean_runtime_build_state(docker, desired_a)
    record_a = build_runtime_image("A", desired_a)

    build_artifact_closure("B")
    desired_b = desired_input()
    clean_runtime_build_state(docker, desired_b)
    record_b = build_runtime_image("B", desired_b)

    pairs = (
        (record_a["artifactManifestSha256"], record_b["artifactManifestSha256"]),
        (record_a["contextManifestSha256"], record_b["contextManifestSha256"]),
        (record_a["inputSha256"], record_b["inputSha256"]),
        (record_a["bootInputSha256"], record_b["bootInputSha256"]),
        (record_a["imageId"], record_b["imageId"]),
    )
    if any(left != right for left, right in pairs):
        raise ReproFailure("runtime_image_not_reproducible")

    log("proving verified content-tag reuse")
    reused = xenoid_json(
        "runtime-build-image",
        timeout=900,
        code="runtime_image_reuse_result_invalid",
    )
    content_reused = bool(
        reused.get("schema") == "dev.xenoid.runtime-image/v1"
        and reused.get("ok") is True
        and reused.get("reused") is True
        and reused.get("inputSha256") == record_b["inputSha256"]
        and reused.get("bootInputSha256") == record_b["bootInputSha256"]
        and reused.get("imageId") == record_b["imageId"]
        and reused.get("derivedTag") == record_b["derivedTag"]
    )
    if not content_reused:
        raise ReproFailure("runtime_content_tag_reuse_unproven")

    log("restoring the selected runtime")
    restored = xenoid_json("up", "--skip-build", timeout=7200, code="runtime_restore_invalid")
    if restored.get("ok") is not True:
        raise ReproFailure("runtime_restore_failed")

    return {
        "schema": SCHEMA,
        "ok": True,
        "artifactManifestSha256A": record_a["artifactManifestSha256"],
        "artifactManifestSha256B": record_b["artifactManifestSha256"],
        "contextManifestSha256A": record_a["contextManifestSha256"],
        "contextManifestSha256B": record_b["contextManifestSha256"],
        "inputSha256A": record_a["inputSha256"],
        "inputSha256B": record_b["inputSha256"],
        "bootInputSha256A": record_a["bootInputSha256"],
        "bootInputSha256B": record_b["bootInputSha256"],
        "imageIdA": record_a["imageId"],
        "imageIdB": record_b["imageId"],
        "contentTagReused": True,
        "error": None,
    }


report = empty_report()
exit_code = 1
try:
    report = execute()
    exit_code = 0
except ReproFailure as error:
    report["error"] = str(error)
    log(f"failed: {error}")
except Exception as error:
    report["error"] = "google_reproducibility_internal_error"
    log(f"failed: {error.__class__.__name__}")
if exit_code != 0:
    # A failed clean-build attempt may have removed only the content tag and
    # private record. Best-effort restoration leaves the selected instance
    # usable without weakening the failed gate result.
    try:
        xenoid("runtime-build-image", timeout=7200, check=False)
    except Exception:
        pass

expected_keys = {
    "schema", "ok", "artifactManifestSha256A", "artifactManifestSha256B",
    "contextManifestSha256A", "contextManifestSha256B", "inputSha256A",
    "inputSha256B", "bootInputSha256A", "bootInputSha256B", "imageIdA",
    "imageIdB", "contentTagReused", "error",
}
if set(report) != expected_keys:
    report = empty_report()
    report["error"] = "google_reproducibility_result_invalid"
    exit_code = 1
sys.stdout.write(canonical(report) + "\n")
sys.stdout.flush()
raise SystemExit(exit_code)
PY
