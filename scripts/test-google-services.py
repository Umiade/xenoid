#!/usr/bin/env python3
"""Synthetic contract tests for the optional pinned Google runtime."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.config import InstanceError, new_instance_config
from xenoid.google_services import (
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


def main() -> int:
    test_registry_and_metadata()
    test_config_pairs()
    test_archive_path_rules()
    test_certificate_rules()
    test_safe_source_copy()
    test_binding_transitions()
    print("google services synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
