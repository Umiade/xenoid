#!/usr/bin/env python3
"""Synthetic contract tests for the optional pinned Google runtime."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.config import InstanceError, new_instance_config
from xenoid.google_services import (
    StageHandle,
    MINDTHEGAPPS_RELEASE,
    PROVIDER_MINDTHEGAPPS,
    PROVIDER_NONE,
    GoogleServicesError,
    _copy_regular_source,
    _parse_pem,
    _safe_member_name,
    binding_matches,
    disabled_runtime_spec_fingerprint,
    expected_binding_identity,
    load_release_spec,
    registered_metadata_files,
    transition_decision,
    verify_context_copy,
)

INSTANCE_ID = "11111111-2222-4333-8444-555555555555"


def expect_error(code: str, function, *args, **kwargs) -> None:
    try:
        function(*args, **kwargs)
    except (GoogleServicesError, InstanceError) as error:
        assert error.code == code, (error.code, code)
        return
    raise AssertionError(f"expected {code}")


def test_registry_and_metadata() -> None:
    registered = registered_metadata_files()
    expected_path = (
        "data/google-services/"
        "mindthegapps-13.0.0-arm64-20231025_200931.json"
    )
    assert set(registered) == {expected_path}
    payload = (ROOT / expected_path).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == registered[expected_path]
    spec = load_release_spec(ROOT)
    assert spec.provider == PROVIDER_MINDTHEGAPPS
    assert spec.release == MINDTHEGAPPS_RELEASE
    assert spec.android["release"] == "13.0.0"
    assert spec.android["api"] == 33
    assert spec.android["archiveArch"] == "arm64"
    assert spec.android["runtimeAbis"] == ["arm64-v8a"]
    assert spec.android["targetProduct"] == "raven"
    assert sum(1 for row in spec.apks if row["selected"]) == 17
    assert {row["package"] for row in spec.apks if row["selected"]} >= {
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
    }
    assert spec.data_compatibility_fingerprint == spec.fingerprint
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        destination = root / expected_path
        destination.parent.mkdir(parents=True)
        destination.write_bytes(payload + b"\n")
        expect_error("google_services_spec_mismatch", load_release_spec, root)


def test_config_pairs() -> None:
    default = new_instance_config("test", INSTANCE_ID)
    assert default.google_services_provider == PROVIDER_NONE
    assert default.google_services_release == PROVIDER_NONE
    enabled = new_instance_config(
        "test",
        INSTANCE_ID,
        {
            "google_services_provider": PROVIDER_MINDTHEGAPPS,
            "google_services_release": MINDTHEGAPPS_RELEASE,
        },
    )
    assert enabled.google_services_provider == PROVIDER_MINDTHEGAPPS
    assert enabled.google_services_release == MINDTHEGAPPS_RELEASE
    for provider, release in (
        (PROVIDER_MINDTHEGAPPS, PROVIDER_NONE),
        (PROVIDER_NONE, MINDTHEGAPPS_RELEASE),
        ("other", "latest"),
    ):
        expect_error(
            "google_services_spec_mismatch",
            new_instance_config,
            "test",
            INSTANCE_ID,
            {
                "google_services_provider": provider,
                "google_services_release": release,
            },
        )


def test_archive_path_rules() -> None:
    assert _safe_member_name("system/product/priv-app/GmsCore/GmsCore.apk") == (
        "system",
        "product",
        "priv-app",
        "GmsCore",
        "GmsCore.apk",
    )
    for unsafe in (
        "",
        "/absolute",
        "../escape",
        "system/../escape",
        "system//escape",
        "system\\escape",
        "system/./escape",
        "nul\x00name",
        "e\u0301/name",
        "a/" + "b" * 256,
        "a" * 1025,
    ):
        expect_error("google_services_asset_invalid", _safe_member_name, unsafe)


def test_certificate_rules() -> None:
    der = b"synthetic certificate bytes"
    encoded = base64.b64encode(der).decode("ascii")
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + encoded
        + "\n-----END CERTIFICATE-----\n"
    ).encode("ascii")
    assert _parse_pem(pem, hashlib.sha256(der).hexdigest()) == der
    expect_error(
        "google_services_asset_invalid",
        _parse_pem,
        pem,
        "0" * 64,
    )
    expect_error(
        "google_services_asset_invalid",
        _parse_pem,
        pem + pem,
        hashlib.sha256(der).hexdigest(),
    )
    expect_error(
        "google_services_asset_invalid",
        _parse_pem,
        b"x" * (16 * 1024 + 1),
        hashlib.sha256(der).hexdigest(),
    )


def test_safe_source_copy() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        source = root / "source.bin"
        source.write_bytes(b"pinned payload")
        destination = root / "destination.bin"
        size, digest = _copy_regular_source(source, destination)
        assert size == len(b"pinned payload")
        assert digest == hashlib.sha256(b"pinned payload").hexdigest()
        assert destination.read_bytes() == b"pinned payload"
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        link = root / "source-link.bin"
        link.symlink_to(source)
        expect_error(
            "google_services_asset_invalid",
            _copy_regular_source,
            link,
            root / "linked-copy.bin",
        )



def test_binding_transitions() -> None:
    spec = load_release_spec(ROOT)
    identity = expected_binding_identity(spec)
    pending = {**identity, "state": "pending", "source": "explicit"}
    committed = {**identity, "state": "committed", "source": "explicit"}
    assert binding_matches(pending, spec)
    assert transition_decision(
        spec,
        None,
        freshness_known=True,
        fresh=True,
        legacy_actual_none=False,
    )["transition"] == "fresh"
    assert transition_decision(
        spec,
        pending,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )["transition"] == "resume"
    assert transition_decision(
        spec,
        committed,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )["transition"] == "reuse"
    expect_error(
        "google_services_freshness_unknown",
        transition_decision,
        spec,
        None,
        freshness_known=False,
        fresh=False,
        legacy_actual_none=False,
    )
    expect_error(
        "google_services_new_instance_required",
        transition_decision,
        spec,
        None,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    disabled_identity = expected_binding_identity(None)
    assert disabled_identity["specSha256"] == disabled_runtime_spec_fingerprint()
    disabled = {**disabled_identity, "state": "committed", "source": "explicit"}
    expect_error(
        "google_services_new_instance_required",
        transition_decision,
        spec,
        disabled,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    expect_error(
        "google_services_new_instance_required",
        transition_decision,
        None,
        committed,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    assert transition_decision(
        None,
        None,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=True,
    )["transition"] == "legacy-none"


def test_canonical_runtime_context_copy() -> None:
    spec = load_release_spec(ROOT)
    payload = b"synthetic canonical Google payload"
    relative = "system/product/priv-app/Synthetic/Synthetic.apk"
    directories = (
        "system",
        "system/product",
        "system/product/priv-app",
        "system/product/priv-app/Synthetic",
    )
    with tempfile.TemporaryDirectory(prefix="xenoid-google-context-contract-") as raw:
        context = Path(raw)
        payload_root = context / "payload" / "google-services"
        target = payload_root / relative
        target.parent.mkdir(parents=True)
        target.write_bytes(payload)
        target.chmod(0o644)
        props = context / "payload" / "props" / "system_build.prop"
        props.parent.mkdir(parents=True)
        props.write_text(
            f"ro.setupwizard.mode={spec.android['setupWizardMode']}\n",
            encoding="utf-8",
        )
        dockerfile = context / "Dockerfile"
        dockerfile.write_text(
            "\n".join(
                (
                    f'{key}="{value}"'
                    for key, value in sorted(spec.labels.items())
                )
            )
            + "\nCOPY --chown=0:0 payload/google-services/ /\n"
            + "COPY payload/xenoid-daemon.apk /data/local/tmp/xenoid-daemon.apk\n",
            encoding="utf-8",
        )
        for path in (
            context,
            context / "payload",
            payload_root,
            *(payload_root / directory for directory in directories),
            props.parent,
        ):
            path.chmod(0o755)
            os.utime(path, (0, 0), follow_symlinks=False)
        for path in (target, props, dockerfile):
            path.chmod(0o644)
            os.utime(path, (0, 0), follow_symlinks=False)

        entries = []
        for path in sorted(
            (candidate for candidate in context.rglob("*") if candidate.name != "context-manifest.json"),
            key=lambda candidate: candidate.relative_to(context).as_posix().encode("utf-8"),
        ):
            relative_path = path.relative_to(context).as_posix()
            if path.is_dir():
                entries.append(
                    {
                        "path": relative_path,
                        "type": "directory",
                        "mode": "0755",
                        "size": 0,
                        "sha256": None,
                    }
                )
            else:
                data = path.read_bytes()
                entries.append(
                    {
                        "path": relative_path,
                        "type": "file",
                        "mode": "0644",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
        manifest = {
            "schema": "dev.xenoid.runtime-context/v1",
            "entries": entries,
        }
        (context / "context-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (context / "context-manifest.json").chmod(0o644)
        os.utime(context / "context-manifest.json", (0, 0), follow_symlinks=False)

        stage = StageHandle(
            root=context,
            tree=payload_root,
            token="0" * 32,
            file_manifest={
                relative: {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                    "mode": 0o644,
                    "mtimeUtc": 1695111058,
                }
            },
            directory_manifest={
                directory: {"mode": 0o755, "mtimeUtc": 1695111058}
                for directory in directories
            },
            metadata_digest="1" * 64,
        )
        result = verify_context_copy(context, spec, stage)
        assert result["ok"] is True
        assert int(target.stat().st_mtime) == 0
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


def main() -> int:
    test_registry_and_metadata()
    test_config_pairs()
    test_archive_path_rules()
    test_certificate_rules()
    test_safe_source_copy()
    test_binding_transitions()
    test_canonical_runtime_context_copy()
    print("google services synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
