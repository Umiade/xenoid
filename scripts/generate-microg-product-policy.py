#!/usr/bin/env python3
"""Generate the canonical Xenoid microG product policy files.

This script is the sole owner of the four microG product-policy files staged
into the Google-services runtime context:

- /system/product/etc/permissions/privapp-permissions-xenoid-microg.xml
- /system/product/etc/default-permissions/default-permissions-xenoid-microg.xml
- /system/product/etc/sysconfig/xenoid-microg.xml
- /system/product/etc/microg.xml

Every input is pinned in the v2 release metadata ``productPolicy`` section and
verified before any output is written. The generator performs no network
access. Output bytes are canonical: UTF-8/LF, sorted entries, sorted
attributes, mode 0644, and zero mtime, so two clean runs are byte-identical.

The aapt2 tool identity is provenance, not a single-binary pin: Google ships
distinct aapt2 binaries per host platform, and Xenoid supports macOS and Linux
ARM64 production hosts. The pinned ``aapt2-35.0.0`` identity is the canonical
provenance document below; the local binary must match one registered
platform identity, and the pinned framework/API-33 data plus byte-exact
canonical outputs remain the hard equality gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from xenoid.google_services import (  # noqa: E402
    GOOGLE_RELEASE_SCHEMA_V2,
    MICROG_PLAY_RELEASE,
    asset_paths,
    load_release_spec,
)

POLICY_MANIFEST_SCHEMA = "dev.xenoid.microg-product-policy/v1"
API33_PERMISSIONS_SCHEMA = "dev.xenoid.android-permissions/v1"

GENERATOR_PATH = "scripts/generate-microg-product-policy.py"
UPSTREAM_PREFIX = "runtime/redroid/microg-policy/upstream"
UPSTREAM_PRIVAPP = f"{UPSTREAM_PREFIX}/privapp-permissions-com.google.android.gms.xml"
UPSTREAM_DEFAULT = f"{UPSTREAM_PREFIX}/default-permissions-com.google.android.gms.xml"
UPSTREAM_SYSCONFIG = f"{UPSTREAM_PREFIX}/sysconfig-com.google.android.gms.xml"
UPSTREAM_MICROG = f"{UPSTREAM_PREFIX}/microg.xml"
API33_PERMISSIONS_PATH = "runtime/redroid/microg-policy/policy-inputs/api33-permissions.json"
API33_PERMISSIONS_LOGICAL = "policy-inputs/api33-permissions.json"
FRAMEWORK_RES_LOGICAL = "policy-inputs/framework-res.apk"
AAPT2_LOGICAL = "tools/aapt2-35.0.0"
MTG_PRIVAPP_MEMBER = "system/product/etc/permissions/privapp-permissions-google-product.xml"
MTG_DEFAULT_MEMBER = "system/product/etc/default-permissions/default-permissions-google.xml"

OUTPUT_PRIVAPP = "/system/product/etc/permissions/privapp-permissions-xenoid-microg.xml"
OUTPUT_DEFAULT = "/system/product/etc/default-permissions/default-permissions-xenoid-microg.xml"
OUTPUT_SYSCONFIG = "/system/product/etc/sysconfig/xenoid-microg.xml"
OUTPUT_MICROG = "/system/product/etc/microg.xml"

# Registered Google-distributed aapt2 35.0.0 build-tools binary identities.
AAPT2_PROVENANCE = {
    "darwin-arm64": "729a6a8deba828992c50cb448d4ef3947003ec5a0d1deead7534897c8fc3486f",
    "linux-x86_64": "d1096e11aba9c974644369ee3c50d239acac3f3428ffa928e5b9c14dfb7a57de",
    "version": "35.0.0",
}

GMSCORE_PRIVAPP_ALLOWLIST = (
    "android.permission.CHANGE_DEVICE_IDLE_TEMP_WHITELIST",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.INSTALL_LOCATION_PROVIDER",
    "android.permission.LOCATION_HARDWARE",
    "android.permission.MANAGE_USB",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.NETWORK_SCAN",
    "android.permission.READ_CONTACTS",
    "android.permission.START_ACTIVITIES_FROM_BACKGROUND",
    "android.permission.UPDATE_APP_OPS_STATS",
    "android.permission.UPDATE_DEVICE_STATS",
    "android.permission.WATCH_APPOPS",
    "android.permission.INTERACT_ACROSS_PROFILES",
    "android.permission.INTERACT_ACROSS_USERS",
)

GMSCORE_DEFAULT_ALLOWLIST = (
    "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.SYSTEM_ALERT_WINDOW",
)

# Store power/rollback/app-link policy and the implicit broadcasts required by
# checkin/gservices/C2DM. These mirror the exact com.android.vending and
# broadcast entries of the verified MindTheGapps sysconfig policy and are owned
# by this generator; no other sysconfig entries are emitted.
SYSCONFIG_STORE_ENTRIES = (
    ("allow-in-power-save-except-idle", "package", "com.android.vending"),
    ("app-link", "package", "com.android.vending"),
    ("rollback-whitelisted-app", "package", "com.android.vending"),
)
SYSCONFIG_BROADCASTS = (
    "com.google.android.checkin.CHECKIN_COMPLETE",
    "com.google.gservices.intent.action.GSERVICES_CHANGED",
    "com.google.android.c2dm.intent.RECEIVE",
)

MICROG_FLIPS = {
    "checkin_enable_service": "true",
    "gcm_enable_mcs_service": "true",
}

_ALLOWED_ROOTS = {"permissions", "exceptions", "config", "map"}


class PolicyError(Exception):
    """Stable microG product-policy generation failure."""


def _fail(message: str) -> None:
    raise PolicyError(message)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        _fail(f"unsafe policy input: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _aapt2_provenance_sha256() -> str:
    return _sha256_bytes(_canonical_json(AAPT2_PROVENANCE) + b"\n")


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _serialize_element(tag: str, attrs: Mapping[str, str], children: list[str], depth: int) -> list[str]:
    indent = "  " * depth
    attr_text = "".join(
        f' {name}="{_xml_escape(value)}"'
        for name, value in sorted(attrs.items(), key=lambda pair: pair[0].encode("utf-8"))
    )
    if not children:
        return [f"{indent}<{tag}{attr_text} />"]
    lines = [f"{indent}<{tag}{attr_text}>"]
    for child in children:
        lines.append(child)
    lines.append(f"{indent}</{tag}>")
    return lines


def _serialize_document(root: str, children: list[list[str]]) -> bytes:
    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    lines.extend(_serialize_element(root, {}, [line for child in children for line in child], 0))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _entry_sort_key(tag: str, attrs: Mapping[str, str]) -> tuple[bytes, bytes]:
    for field in ("name", "package", "action"):
        if field in attrs:
            return tag.encode("utf-8"), attrs[field].encode("utf-8")
    return tag.encode("utf-8"), b""


def _leaf(tag: str, attrs: Mapping[str, str], depth: int = 2) -> tuple[tuple[bytes, bytes], list[str]]:
    return _entry_sort_key(tag, attrs), _serialize_element(tag, attrs, [], depth)


def _block(tag: str, attrs: Mapping[str, str], children: list[list[str]]) -> tuple[tuple[bytes, bytes], list[str]]:
    flat = [line for child in children for line in child]
    return _entry_sort_key(tag, attrs), _serialize_element(tag, attrs, flat, 1)


def _parse_xml_bytes(payload: bytes, *, expected_root: str) -> ET.Element:
    if b"<!DOCTYPE" in raw_upper(payload) or b"<!ENTITY" in raw_upper(payload):
        _fail("policy input uses a forbidden DTD/entity declaration")
    try:
        root = ET.fromstring(payload.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        _fail(f"invalid policy input XML: {exc}")
    if root.tag != expected_root or expected_root not in _ALLOWED_ROOTS:
        _fail("unexpected policy input root element")
    if "{" in root.tag:
        _fail("policy input must not use namespaces")
    return root


def raw_upper(payload: bytes) -> bytes:
    return payload.upper()


def _child_elements(root: ET.Element, tag: str) -> list[ET.Element]:
    result = []
    for child in root:
        if not isinstance(child.tag, str):
            _fail("unexpected non-element policy content")
        if "{" in child.tag or child.tag != tag:
            _fail(f"unexpected policy element: {child.tag}")
        result.append(child)
    return result


def _exact_attrs(element: ET.Element, allowed: set[str], required: set[str]) -> dict[str, str]:
    attrs = {str(key): str(value) for key, value in element.attrib.items()}
    if not required.issubset(attrs) or not set(attrs).issubset(allowed):
        _fail("unexpected policy element attributes")
    if element.text and element.text.strip():
        _fail("unexpected policy element text")
    return attrs


def _load_api33_permissions(path: Path, framework_sha: str) -> dict[str, int]:
    try:
        doc = json.loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError) as exc:
        _fail(f"invalid API 33 permission inventory: {exc}")
    if not isinstance(doc, Mapping) or set(doc) != {"schema", "frameworkResSha256", "aapt2Sha256", "permissions"}:
        _fail("invalid API 33 permission inventory keys")
    if doc["schema"] != API33_PERMISSIONS_SCHEMA:
        _fail("unsupported API 33 permission inventory schema")
    if doc["frameworkResSha256"] != framework_sha:
        _fail("API 33 permission inventory does not match the extracted framework")
    if doc["aapt2Sha256"] != _aapt2_provenance_sha256():
        _fail("API 33 permission inventory tool provenance mismatch")
    records = doc["permissions"]
    if not isinstance(records, list) or not records:
        _fail("invalid API 33 permission inventory entries")
    result: dict[str, int] = {}
    previous: Optional[bytes] = None
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {"name", "protectionLevel"}:
            _fail("invalid API 33 permission entry")
        name = record["name"]
        level = record["protectionLevel"]
        if not isinstance(name, str) or not isinstance(level, int) or isinstance(level, bool) or level < 0:
            _fail("invalid API 33 permission entry values")
        encoded = name.encode("utf-8")
        if previous is not None and encoded <= previous:
            _fail("API 33 permission inventory is not bytewise sorted")
        previous = encoded
        result[name] = level
    return result


def _requested_permissions(aapt2: Path, apk: Path) -> set[str]:
    try:
        completed = _run([str(aapt2), "dump", "badging", str(apk)])
    except OSError as exc:
        _fail(f"unable to inspect the pinned GmsCore APK: {exc}")
    requested = set()
    for line in completed.splitlines():
        if line.startswith("uses-permission: name='"):
            requested.add(line.split("'", 2)[1])
    if not requested:
        _fail("pinned GmsCore APK exposes no requested permissions")
    return requested


def _run(command: list[str]) -> str:
    import subprocess

    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        _fail(f"policy tool invocation failed: {Path(command[0]).name}")
    return completed.stdout


def _is_signature_privileged(level: int) -> bool:
    return (level & 0xF) == 2 and (level & 0x10) != 0


def _build_privapp(upstream_root: ET.Element, vending_block: list[ET.Element], api33: Mapping[str, int], requested: set[str]) -> bytes:
    blocks = _child_elements(upstream_root, "privapp-permissions")
    if len(blocks) != 1 or _exact_attrs(blocks[0], {"package"}, {"package"})["package"] != "com.google.android.gms":
        _fail("unexpected upstream GmsCore privapp block")
    candidates = []
    for permission in _child_elements(blocks[0], "permission"):
        attrs = _exact_attrs(permission, {"name"}, {"name"})
        candidates.append(attrs["name"])
    allowlist = set(GMSCORE_PRIVAPP_ALLOWLIST)
    if not set(candidates).issuperset(allowlist):
        _fail("upstream GmsCore privapp candidates changed")
    for name in sorted(requested):
        level = api33.get(name)
        if level is not None and _is_signature_privileged(level) and name not in allowlist:
            _fail(f"pinned GmsCore APK requests an unlisted signature|privileged permission: {name}")
    emit = sorted(
        (name for name in allowlist if name in api33 and name in requested),
        key=lambda item: item.encode("utf-8"),
    )
    if "android.permission.FAKE_PACKAGE_SIGNATURE" in emit:
        _fail("FAKE_PACKAGE_SIGNATURE must never be granted")
    gms_children = [_leaf("permission", {"name": name})[1] for name in emit]
    vending_children = []
    for permission in vending_block:
        attrs = _exact_attrs(permission, {"name"}, {"name"})
        vending_children.append(_leaf("permission", attrs)[1])
    ordered = sorted(
        [
            _block("privapp-permissions", {"package": "com.android.vending"}, vending_children),
            _block("privapp-permissions", {"package": "com.google.android.gms"}, gms_children),
        ],
        key=lambda pair: pair[0],
    )
    return _serialize_document("permissions", [child for _, child in ordered])


def _build_default(upstream_root: ET.Element, vending_blocks: list[ET.Element], api33: Mapping[str, int], requested: set[str]) -> bytes:
    blocks = _child_elements(upstream_root, "exception")
    if len(blocks) != 1 or _exact_attrs(blocks[0], {"package"}, {"package"})["package"] != "com.google.android.gms":
        _fail("unexpected upstream GmsCore default-permission block")
    allowlist = set(GMSCORE_DEFAULT_ALLOWLIST)
    children = []
    emitted: set[str] = set()
    for permission in _child_elements(blocks[0], "permission"):
        attrs = _exact_attrs(permission, {"name", "fixed", "whitelisted"}, {"name"})
        name = attrs["name"]
        if name in allowlist and name in api33 and name in requested:
            emitted.add(name)
            children.append(_leaf("permission", attrs)[1])
    if not emitted or not emitted.issubset(allowlist):
        _fail("GmsCore default-permission filter produced an invalid entry set")
    gms_block = _block("exception", {"package": "com.google.android.gms"}, children)
    ordered = [gms_block]
    for block in vending_blocks:
        attrs = _exact_attrs(block, {"package", "sha256-cert-digest"}, {"package"})
        retained = []
        for permission in _child_elements(block, "permission"):
            retained.append(_leaf("permission", _exact_attrs(permission, {"name", "fixed", "whitelisted"}, {"name"}))[1])
        ordered.append(_block("exception", attrs, retained))
    ordered.sort(key=lambda pair: pair[0])
    return _serialize_document("exceptions", [child for _, child in ordered])


def _build_sysconfig(upstream_root: ET.Element) -> bytes:
    entries = []
    seen = set()
    for child in upstream_root:
        if not isinstance(child.tag, str) or child.tag not in {"allow-in-power-save", "allow-in-data-usage-save", "allow-unthrottled-location"}:
            _fail("unexpected upstream sysconfig entry")
        attrs = _exact_attrs(child, {"package"}, {"package"})
        if attrs["package"] != "com.google.android.gms":
            _fail("unexpected upstream sysconfig package")
        seen.add(child.tag)
        entries.append(_leaf(child.tag, attrs, 1))
    if seen != {"allow-in-power-save", "allow-in-data-usage-save", "allow-unthrottled-location"}:
        _fail("upstream sysconfig GmsCore entries changed")
    for tag, field, value in SYSCONFIG_STORE_ENTRIES:
        entries.append(_leaf(tag, {field: value}, 1))
    for action in SYSCONFIG_BROADCASTS:
        entries.append(_leaf("allow-implicit-broadcast", {"action": action}, 1))
    ordered = sorted(entries, key=lambda pair: pair[0])
    keys = [pair[0] for pair in ordered]
    if len(set(keys)) != len(keys):
        _fail("duplicate sysconfig entry")
    return _serialize_document("config", [child for _, child in ordered])


def _build_microg(upstream_root: ET.Element) -> bytes:
    entries = []
    seen = set()
    for child in _child_elements(upstream_root, "boolean"):
        attrs = _exact_attrs(child, {"name", "value"}, {"name", "value"})
        name = attrs["name"]
        if name in seen:
            _fail("duplicate microG preference")
        seen.add(name)
        if attrs["value"] not in {"true", "false"}:
            _fail("invalid microG preference value")
        value = MICROG_FLIPS.get(name, attrs["value"])
        if name in MICROG_FLIPS and attrs["value"] != "false":
            _fail("upstream microG service toggle changed")
        entries.append(_leaf("boolean", {"name": name, "value": value}, 1))
    if not set(MICROG_FLIPS).issubset(seen):
        _fail("upstream microG service toggles are missing")
    ordered = sorted(entries, key=lambda pair: pair[0])
    return _serialize_document("map", [child for _, child in ordered])


def _extract_mtg_block(root: ET.Element, block_tag: str, package: str) -> list[ET.Element]:
    result = []
    for block in _child_elements(root, block_tag):
        if block.attrib.get("package") != package:
            continue
        _exact_attrs(block, {"package", "sha256-cert-digest"}, {"package"})
        result.append(block)
    return result


def _write_output(output_root: Path, runtime_path: str, payload: bytes) -> str:
    relative = runtime_path.lstrip("/")
    target = output_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fchmod(descriptor, 0o644)
        os.utime(descriptor, ns=(0, 0))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _sha256_bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--framework-res", required=True)
    parser.add_argument("--aapt2", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    framework_res = Path(args.framework_res).resolve()
    aapt2 = Path(args.aapt2).resolve()
    output_dir = Path(args.output_dir).resolve()
    manifest_path = Path(args.manifest).resolve()

    spec = load_release_spec(project_root, MICROG_PLAY_RELEASE)
    if spec.schema != GOOGLE_RELEASE_SCHEMA_V2:
        _fail("microG product policy requires the v2 composite release")
    policy = spec.product_policy

    assets = asset_paths(project_root, spec)
    source_spec = load_release_spec(project_root, "MindTheGapps-13.0.0-arm64-20231025_200931")
    source_zip_path = asset_paths(project_root, source_spec)["archive"]

    framework_sha = _sha256_file(framework_res)
    aapt2_sha = _sha256_file(aapt2)
    if aapt2_sha not in {AAPT2_PROVENANCE["darwin-arm64"], AAPT2_PROVENANCE["linux-x86_64"]}:
        _fail("aapt2 binary is not a registered build-tools 35.0.0 identity")

    input_hashes: dict[str, str] = {
        GENERATOR_PATH: _sha256_file(project_root / GENERATOR_PATH),
        str(spec.component("gmsCore")["sourcePath"]): _sha256_file(assets["gmsCore"]),
        UPSTREAM_PRIVAPP: _sha256_file(project_root / UPSTREAM_PRIVAPP),
        UPSTREAM_DEFAULT: _sha256_file(project_root / UPSTREAM_DEFAULT),
        UPSTREAM_SYSCONFIG: _sha256_file(project_root / UPSTREAM_SYSCONFIG),
        UPSTREAM_MICROG: _sha256_file(project_root / UPSTREAM_MICROG),
        API33_PERMISSIONS_LOGICAL: _sha256_file(project_root / API33_PERMISSIONS_PATH),
        FRAMEWORK_RES_LOGICAL: framework_sha,
        AAPT2_LOGICAL: _aapt2_provenance_sha256(),
    }
    with zipfile.ZipFile(source_zip_path) as bundle:
        for member in (MTG_PRIVAPP_MEMBER, MTG_DEFAULT_MEMBER):
            input_hashes[member] = _sha256_bytes(bundle.read(member))

    expected_inputs = {str(item["path"]): str(item["sha256"]) for item in policy["inputs"]}
    if input_hashes != expected_inputs:
        _fail("microG product policy inputs do not match the pinned release metadata")

    api33 = _load_api33_permissions(project_root / API33_PERMISSIONS_PATH, framework_sha)
    requested = _requested_permissions(aapt2, assets["gmsCore"])

    upstream_privapp = _parse_xml_bytes((project_root / UPSTREAM_PRIVAPP).read_bytes(), expected_root="permissions")
    upstream_default = _parse_xml_bytes((project_root / UPSTREAM_DEFAULT).read_bytes(), expected_root="exceptions")
    upstream_sysconfig = _parse_xml_bytes((project_root / UPSTREAM_SYSCONFIG).read_bytes(), expected_root="config")
    upstream_microg = _parse_xml_bytes((project_root / UPSTREAM_MICROG).read_bytes(), expected_root="map")
    with zipfile.ZipFile(source_zip_path) as bundle:
        mtg_privapp = _parse_xml_bytes(bundle.read(MTG_PRIVAPP_MEMBER), expected_root="permissions")
        mtg_default = _parse_xml_bytes(bundle.read(MTG_DEFAULT_MEMBER), expected_root="exceptions")

    vending_privapp = _extract_mtg_block(mtg_privapp, "privapp-permissions", "com.android.vending")
    if len(vending_privapp) != 1:
        _fail("verified MindTheGapps privapp policy must contain exactly one com.android.vending block")
    vending_default = _extract_mtg_block(mtg_default, "exception", "com.android.vending")

    outputs = {
        OUTPUT_PRIVAPP: _build_privapp(upstream_privapp, list(_child_elements(vending_privapp[0], "permission")), api33, requested),
        OUTPUT_DEFAULT: _build_default(upstream_default, vending_default, api33, requested),
        OUTPUT_SYSCONFIG: _build_sysconfig(upstream_sysconfig),
        OUTPUT_MICROG: _build_microg(upstream_microg),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    output_hashes: dict[str, str] = {}
    for runtime_path in sorted(outputs, key=lambda item: item.encode("utf-8")):
        output_hashes[runtime_path] = _write_output(output_dir, runtime_path, outputs[runtime_path])

    manifest = {
        "schema": POLICY_MANIFEST_SCHEMA,
        "inputs": [{"path": path, "sha256": input_hashes[path]} for path in sorted(input_hashes, key=lambda item: item.encode("utf-8"))],
        "outputs": [{"path": path, "sha256": output_hashes[path]} for path in sorted(output_hashes, key=lambda item: item.encode("utf-8"))],
    }
    expected_outputs = {str(item["path"]): str(item["sha256"]) for item in policy["outputs"]}
    if output_hashes != expected_outputs:
        _fail("microG product policy outputs do not match the pinned release metadata")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(_canonical_json(manifest) + b"\n")
    os.chmod(manifest_path, 0o644)
    os.utime(manifest_path, ns=(0, 0))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as exc:
        print(f"microg_product_policy_invalid: {exc}", file=sys.stderr)
        raise SystemExit(1)
