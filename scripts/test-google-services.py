#!/usr/bin/env python3
"""Runtime-free synthetic contracts for the pinned Google services providers."""
from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
from dataclasses import replace
import io
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Mapping
from unittest import mock
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xenoid.config import InstanceError, initialize_instance, new_instance_config  # noqa: E402
from xenoid import google_services as gs  # noqa: E402


INSTANCE_ID = "11111111-2222-4333-8444-555555555555"
EXPECTED_MICROG_FINGERPRINT = "f569d2ca6dbe1c49a7443ab26c49242a793072dff48143cce9b46a8f381defb1"


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def expect_error(code: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> InstanceError:
    try:
        function(*args, **kwargs)
    except (gs.GoogleServicesError, InstanceError) as error:
        assert error.code == code, (error.code, code)
        return error
    raise AssertionError(f"expected {code}")


def test_registry_and_metadata() -> None:
    registered = gs.registered_metadata_files()
    v1_path = "data/google-services/mindthegapps-13.0.0-arm64-20231025_200931.json"
    v2_path = "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json"
    assert set(registered) == {v1_path, v2_path}
    for relative, pinned_digest in registered.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == pinned_digest

    retired = gs.load_release_spec(ROOT, gs.MINDTHEGAPPS_RELEASE)
    assert retired.schema == gs.GOOGLE_RELEASE_SCHEMA_V1
    assert retired.provider == gs.PROVIDER_MINDTHEGAPPS
    assert retired.release == gs.MINDTHEGAPPS_RELEASE
    assert retired.availability == gs.AVAILABILITY_RETIRED_SOURCE
    assert retired.android["release"] == "13.0.0"
    assert retired.android["api"] == 33
    assert retired.android["archiveArch"] == "arm64"
    assert retired.android["runtimeAbis"] == ["arm64-v8a"]
    assert retired.android["targetProduct"] == "raven"
    assert sum(1 for row in retired.apks if row["selected"]) == 17
    assert {row["package"] for row in retired.apks if row["selected"]} >= {
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
    }
    assert retired.data_compatibility_fingerprint == retired.fingerprint

    production = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    assert production.schema == gs.GOOGLE_RELEASE_SCHEMA_V2
    assert production.provider == gs.PROVIDER_MICROG
    assert production.availability == gs.AVAILABILITY_PRODUCTION
    assert production.metadata_sha256 == registered[v2_path]
    assert production.fingerprint == EXPECTED_MICROG_FINGERPRINT
    assert gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE).fingerprint == production.fingerprint
    assert production.data_compatibility_fingerprint == production.fingerprint
    assert [component["id"] for component in production.components] == [
        "gmsCore",
        "gsfProxy",
        "playStoreSeed",
    ]
    assert production.android["setupWizardMode"] == "UNCHANGED"
    assert gs.registered_releases(selectable_only=True) == (gs.MICROG_PLAY_RELEASE,)
    registry = {item["release"]: item for item in gs.registry_public()}
    assert registry[gs.MINDTHEGAPPS_RELEASE]["availability"] == gs.AVAILABILITY_RETIRED_SOURCE
    assert registry[gs.MICROG_PLAY_RELEASE]["availability"] == gs.AVAILABILITY_PRODUCTION

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        destination = root / v1_path
        destination.parent.mkdir(parents=True)
        destination.write_bytes((ROOT / v1_path).read_bytes() + b"\n")
        expect_error("google_services_spec_mismatch", gs.load_release_spec, root, gs.MINDTHEGAPPS_RELEASE)


def test_v2_metadata_exact_keys() -> None:
    source = json.loads(
        (ROOT / "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json").read_bytes()
    )
    assert gs._validate_release_metadata(copy.deepcopy(source), gs.MICROG_PLAY_RELEASE) == source

    def extra_top(value: dict[str, Any]) -> None:
        value["unexpected"] = True

    def missing_top(value: dict[str, Any]) -> None:
        del value["sources"]

    def extra_android(value: dict[str, Any]) -> None:
        value["android"]["unexpected"] = True

    def missing_android(value: dict[str, Any]) -> None:
        del value["android"]["api"]

    def extra_source(value: dict[str, Any]) -> None:
        value["sources"]["microg"]["unexpected"] = True

    def missing_source(value: dict[str, Any]) -> None:
        del value["sources"]["mindthegapps"]["metadataSha256"]

    def extra_component(value: dict[str, Any]) -> None:
        value["components"][0]["unexpected"] = True

    def missing_component(value: dict[str, Any]) -> None:
        del value["components"][1]["versionCode"]

    def extra_signature(value: dict[str, Any]) -> None:
        value["signaturePolicy"]["unexpected"] = True

    def missing_signature(value: dict[str, Any]) -> None:
        del value["signaturePolicy"]["fakeSignerSha256"]

    def extra_policy_record(value: dict[str, Any]) -> None:
        value["productPolicy"]["outputs"][0]["unexpected"] = True

    def missing_policy_record(value: dict[str, Any]) -> None:
        del value["productPolicy"]["inputs"][0]["sha256"]

    def extra_core_package(value: dict[str, Any]) -> None:
        value["runtimeRequirements"]["corePackages"][0]["unexpected"] = True

    def missing_core_package(value: dict[str, Any]) -> None:
        del value["runtimeRequirements"]["corePackages"][2]["privileged"]

    mutations = (
        extra_top,
        missing_top,
        extra_android,
        missing_android,
        extra_source,
        missing_source,
        extra_component,
        missing_component,
        extra_signature,
        missing_signature,
        extra_policy_record,
        missing_policy_record,
        extra_core_package,
        missing_core_package,
    )
    for mutate in mutations:
        candidate = copy.deepcopy(source)
        mutate(candidate)
        expect_error(
            "google_services_spec_mismatch",
            gs._validate_release_metadata,
            candidate,
            gs.MICROG_PLAY_RELEASE,
        )
    unknown = copy.deepcopy(source)
    unknown["schema"] = "dev.xenoid.google-release/v999"
    expect_error(
        "google_services_spec_mismatch",
        gs._validate_release_metadata,
        unknown,
        gs.MICROG_PLAY_RELEASE,
    )


def test_config_pairs_and_retired_resolution() -> None:
    default = new_instance_config("test", INSTANCE_ID)
    assert default.google_services_provider == gs.PROVIDER_MICROG
    assert default.google_services_release == gs.MICROG_PLAY_RELEASE
    assert default.auto_build_runtime_image is True
    for provider, release in (
        (gs.PROVIDER_NONE, gs.PROVIDER_NONE),
        (gs.PROVIDER_MICROG, gs.MICROG_PLAY_RELEASE),
        (gs.PROVIDER_MINDTHEGAPPS, gs.MINDTHEGAPPS_RELEASE),
    ):
        configured = new_instance_config(
            "test",
            INSTANCE_ID,
            {
                "google_services_provider": provider,
                "google_services_release": release,
            },
        )
        assert (configured.google_services_provider, configured.google_services_release) == (provider, release)

    for provider, release in (
        (gs.PROVIDER_MICROG, gs.PROVIDER_NONE),
        (gs.PROVIDER_MINDTHEGAPPS, gs.PROVIDER_NONE),
        (gs.PROVIDER_NONE, gs.MICROG_PLAY_RELEASE),
        (gs.PROVIDER_NONE, gs.MINDTHEGAPPS_RELEASE),
        (gs.PROVIDER_MINDTHEGAPPS, gs.MICROG_PLAY_RELEASE),
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

    retired = new_instance_config(
        "test",
        INSTANCE_ID,
        {
            "google_services_provider": gs.PROVIDER_MINDTHEGAPPS,
            "google_services_release": gs.MINDTHEGAPPS_RELEASE,
            "auto_build_runtime_image": True,
        },
    )
    expect_error(
        "google_services_release_retired",
        gs.resolve_google_runtime_spec,
        SimpleNamespace(project_root=ROOT),
        retired,
        "contract",
        require_assets=False,
    )
    assert gs.MINDTHEGAPPS_RELEASE not in gs.registered_releases(selectable_only=True)



def test_initialize_defaults_and_explicit_disable() -> None:
    with tempfile.TemporaryDirectory(prefix="xenoid-init-contract-") as temporary:
        root = Path(temporary) / "project"
        state = Path(temporary) / "state"
        (root / "src" / "xenoid").mkdir(parents=True)
        template = ROOT / "examples" / "config-macos-colima.json"

        _, default_cfg, _ = initialize_instance(
            "default-gms",
            project_root=root,
            state_home=state,
            template_path=template,
        )
        assert (
            default_cfg.google_services_provider,
            default_cfg.google_services_release,
        ) == (gs.PROVIDER_MICROG, gs.MICROG_PLAY_RELEASE)

        no_google = {
            "google_services_provider": gs.PROVIDER_NONE,
            "google_services_release": gs.PROVIDER_NONE,
        }
        _, disabled_cfg, _ = initialize_instance(
            "no-gms",
            project_root=root,
            state_home=state,
            template_path=template,
            overrides=no_google,
        )
        assert (
            disabled_cfg.google_services_provider,
            disabled_cfg.google_services_release,
        ) == (gs.PROVIDER_NONE, gs.PROVIDER_NONE)

        _, cloned_disabled, _ = initialize_instance(
            "cloned-no-gms",
            project_root=root,
            state_home=state,
            from_instance="default-gms",
            overrides=no_google,
        )
        assert (
            cloned_disabled.google_services_provider,
            cloned_disabled.google_services_release,
        ) == (gs.PROVIDER_NONE, gs.PROVIDER_NONE)

def test_archive_path_rules() -> None:
    assert gs._safe_member_name("system/product/priv-app/GmsCore/GmsCore.apk") == (
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
        expect_error("google_services_asset_invalid", gs._safe_member_name, unsafe)


def test_certificate_rules() -> None:
    der = b"synthetic certificate bytes"
    encoded = base64.b64encode(der).decode("ascii")
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + encoded
        + "\n-----END CERTIFICATE-----\n"
    ).encode("ascii")
    assert gs._parse_pem(pem, hashlib.sha256(der).hexdigest()) == der
    expect_error("google_services_asset_invalid", gs._parse_pem, pem, "0" * 64)
    expect_error(
        "google_services_asset_invalid",
        gs._parse_pem,
        pem + pem,
        hashlib.sha256(der).hexdigest(),
    )
    expect_error(
        "google_services_asset_invalid",
        gs._parse_pem,
        b"x" * (16 * 1024 + 1),
        hashlib.sha256(der).hexdigest(),
    )


def test_safe_source_copy() -> None:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        source = root / "source.bin"
        source.write_bytes(b"pinned payload")
        destination = root / "destination.bin"
        size, digest = gs._copy_regular_source(source, destination)
        assert size == len(b"pinned payload")
        assert digest == hashlib.sha256(b"pinned payload").hexdigest()
        assert destination.read_bytes() == b"pinned payload"
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        link = root / "source-link.bin"
        link.symlink_to(source)
        expect_error(
            "google_services_asset_invalid",
            gs._copy_regular_source,
            link,
            root / "linked-copy.bin",

        )

class FakeDownloadResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        final_url: str = "https://release-assets.githubusercontent.com/pinned",
        status: int = 200,
    ):
        self._stream = io.BytesIO(payload)
        self._final_url = final_url
        self._status = status
        self.headers = {"Content-Length": str(len(payload))}

    def __enter__(self) -> "FakeDownloadResponse":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def geturl(self) -> str:
        return self._final_url

    def getcode(self) -> int:
        return self._status

    def read(self, size: int) -> bytes:
        return self._stream.read(size)


def test_pinned_asset_download() -> None:
    payload = b"pinned automatic download payload\n"
    digest = hashlib.sha256(payload).hexdigest()
    with tempfile.TemporaryDirectory(prefix="xenoid-download-contract-") as raw:
        root = Path(raw)
        destination = root / "asset.bin"
        with mock.patch.object(
            gs.urllib.request,
            "urlopen",
            return_value=FakeDownloadResponse(payload),
        ):
            gs._download_pinned_asset(
                gs.MICROG_GMSCORE_DOWNLOAD_URL,
                destination,
                expected_size=len(payload),
                expected_sha256=digest,
            )
        assert destination.read_bytes() == payload
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600

        mismatch = root / "mismatch.bin"
        with mock.patch.object(
            gs.urllib.request,
            "urlopen",
            return_value=FakeDownloadResponse(payload),
        ):
            expect_error(
                "google_services_asset_download_failed",
                gs._download_pinned_asset,
                gs.MICROG_GMSCORE_DOWNLOAD_URL,
                mismatch,
                expected_size=len(payload),
                expected_sha256="0" * 64,
            )
        assert not mismatch.exists()

        downgraded = root / "downgraded.bin"
        with mock.patch.object(
            gs.urllib.request,
            "urlopen",
            return_value=FakeDownloadResponse(
                payload,
                final_url="http://release-assets.githubusercontent.com/pinned",
            ),
        ):
            expect_error(
                "google_services_asset_download_failed",
                gs._download_pinned_asset,
                gs.MICROG_GMSCORE_DOWNLOAD_URL,
                downgraded,
                expected_size=len(payload),
                expected_sha256=digest,
            )
        assert not downgraded.exists()

        existing = root / "existing.bin"
        existing.write_bytes(b"operator data")
        with mock.patch.object(
            gs.urllib.request,
            "urlopen",
            return_value=FakeDownloadResponse(payload),
        ):
            expect_error(
                "google_services_asset_download_failed",
                gs._download_pinned_asset,
                gs.MICROG_GMSCORE_DOWNLOAD_URL,
                existing,
                expected_size=len(payload),
                expected_sha256=digest,
            )
        assert existing.read_bytes() == b"operator data"


def test_automatic_asset_acquisition_flow() -> None:
    spec = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    source_spec = gs.load_release_spec(ROOT, gs.MINDTHEGAPPS_RELEASE)
    with tempfile.TemporaryDirectory(
        prefix="xenoid-acquisition-contract-"
    ) as raw:
        root = Path(raw)

        def fake_download(
            _url: str,
            destination: Path,
            **_: Any,
        ) -> None:
            destination.write_bytes(b"downloaded")
            destination.chmod(0o600)

        with (
            mock.patch.object(
                gs,
                "_asset_set_ready",
                side_effect=(False, False, False, False),
            ),
            mock.patch.object(
                gs,
                "load_release_spec",
                return_value=source_spec,
            ),
            mock.patch.object(
                gs,
                "_download_pinned_asset",
                side_effect=fake_download,
            ) as download,
            mock.patch.object(gs, "import_mindthegapps") as import_mtg,
            mock.patch.object(gs, "import_microg") as import_microg,
            mock.patch.object(gs, "quick_validate_assets"),
        ):
            result = gs.ensure_google_services_assets(root, spec)

        assert result["ok"] is True
        assert result["downloaded"] is True
        assert download.call_count == 4
        urls = [call.args[0] for call in download.call_args_list]
        assert str(source_spec.metadata["source"]["zipUrl"]) in urls
        assert str(source_spec.metadata["source"]["certificateUrl"]) in urls
        assert gs.MICROG_GMSCORE_DOWNLOAD_URL in urls
        assert gs.MICROG_GSFPROXY_DOWNLOAD_URL in urls
        import_mtg.assert_called_once()
        import_microg.assert_called_once()
        parent = root / ".xenoid" / "artifacts" / "google-services"
        assert not list(parent.glob(".acquire-*"))



def synthetic_v2_spec() -> tuple[gs.ReleaseSpec, dict[str, bytes], dict[str, bytes]]:
    base = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    metadata = copy.deepcopy(dict(base.metadata))
    component_payloads = {
        "gmsCore": b"synthetic official microG GmsCore bytes\n",
        "gsfProxy": b"synthetic official GsfProxy bytes\n",
        "playStoreSeed": b"synthetic Google-signed Phonesky seed bytes\n",
    }
    for component in metadata["components"]:
        payload = component_payloads[component["id"]]
        component["size"] = len(payload)
        component["sha256"] = hashlib.sha256(payload).hexdigest()
    policy_payloads: dict[str, bytes] = {}
    for record in metadata["productPolicy"]["outputs"]:
        relative = str(record["path"]).lstrip("/")
        payload = (f"<synthetic-policy path={relative!r} />\n").encode("utf-8")
        policy_payloads[relative] = payload
        record["sha256"] = hashlib.sha256(payload).hexdigest()
    fingerprint = hashlib.sha256(canonical_json(metadata)).hexdigest()
    return (
        replace(
            base,
            metadata=metadata,
            fingerprint=fingerprint,
            data_compatibility_fingerprint=fingerprint,
        ),
        component_payloads,
        policy_payloads,
    )


def synthetic_source_dependency(spec: gs.ReleaseSpec) -> dict[str, Any]:
    return {
        "release": gs.MINDTHEGAPPS_RELEASE,
        "metadataSha256": gs.load_release_spec(ROOT, gs.MINDTHEGAPPS_RELEASE).metadata_sha256,
        "importManifestSha256": "a" * 64,
        "archivePath": gs.PHONESKY_ARCHIVE_PATH,
        "memberSha256": str(spec.component("playStoreSeed")["sha256"]),
    }


@contextmanager
def v2_asset_fixture() -> Iterator[tuple[Path, gs.ReleaseSpec, dict[str, bytes], Path, dict[str, Any]]]:
    spec, component_payloads, _ = synthetic_v2_spec()
    dependency = synthetic_source_dependency(spec)
    with tempfile.TemporaryDirectory(prefix="xenoid-google-assets-contract-") as raw:
        root = Path(raw)
        directory = gs.asset_directory(root, spec.release)
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
        paths = gs.asset_paths(root, spec)
        for component_id in ("gmsCore", "gsfProxy"):
            paths[component_id].write_bytes(component_payloads[component_id])
            paths[component_id].chmod(0o600)
        with mock.patch.object(gs, "_mindthegapps_source_dependency", return_value=dependency):
            manifest = gs._expected_import_manifest_v2(root, spec)
        paths["manifest"].write_bytes(canonical_json(manifest))
        paths["manifest"].chmod(0o600)
        with mock.patch.object(gs, "_mindthegapps_source_dependency", return_value=dependency):
            yield root, spec, component_payloads, directory, manifest


def rewrite_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    path.write_bytes(canonical_json(manifest))
    path.chmod(0o600)


def expect_v2_asset_failure(mutate: Callable[[Path, gs.ReleaseSpec, dict[str, bytes], Path, dict[str, Any]], None]) -> None:
    with v2_asset_fixture() as fixture:
        root, spec, component_payloads, directory, manifest = fixture
        mutate(root, spec, component_payloads, directory, manifest)
        expect_error("google_services_asset_invalid", gs.quick_validate_assets, root, spec)


def test_v2_quick_asset_validation() -> None:
    with v2_asset_fixture() as fixture:
        root, spec, component_payloads, _, _ = fixture
        result = gs.quick_validate_assets(root, spec)
        assert result["ok"] is True
        assert result["componentSizes"] == {
            "gmsCore": len(component_payloads["gmsCore"]),
            "gsfProxy": len(component_payloads["gsfProxy"]),
        }
    spec, _, _ = synthetic_v2_spec()
    with tempfile.TemporaryDirectory(prefix="xenoid-google-assets-missing-contract-") as raw:
        expect_error("google_services_assets_missing", gs.quick_validate_assets, Path(raw), spec)


    def missing_component(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        gs.asset_paths(root, spec)["gmsCore"].unlink()

    def wrong_component_name(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        gs.asset_paths(root, spec)["gsfProxy"].rename(gs.asset_directory(root, spec.release) / "wrong-gsfproxy.apk")

    def extra_component(_root: Path, _spec: gs.ReleaseSpec, _payloads: dict[str, bytes], directory: Path, _manifest: dict[str, Any]) -> None:
        extra = directory / "unexpected-component.apk"
        extra.write_bytes(b"unexpected")
        extra.chmod(0o600)

    def size_mismatch(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        path = gs.asset_paths(root, spec)["gmsCore"]
        path.write_bytes(path.read_bytes() + b"x")
        path.chmod(0o600)

    def hash_mismatch(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        path = gs.asset_paths(root, spec)["gsfProxy"]
        payload = bytearray(path.read_bytes())
        payload[0] ^= 1
        path.write_bytes(payload)
        path.chmod(0o600)

    def unsafe_directory(_root: Path, _spec: gs.ReleaseSpec, _payloads: dict[str, bytes], directory: Path, _manifest: dict[str, Any]) -> None:
        directory.chmod(0o755)

    def unsafe_file(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        gs.asset_paths(root, spec)["gmsCore"].chmod(0o644)

    def unsafe_file_symlink(root: Path, spec: gs.ReleaseSpec, *_: Any) -> None:
        path = gs.asset_paths(root, spec)["gmsCore"]
        path.unlink()
        target = root / "outside-gmscore.apk"
        target.write_bytes(b"outside")
        target.chmod(0o600)
        path.symlink_to(target)

    def unsafe_directory_symlink(_root: Path, spec: gs.ReleaseSpec, _payloads: dict[str, bytes], directory: Path, _manifest: dict[str, Any]) -> None:
        target = directory.parent / f"{spec.release}.real"
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)


    for mutate in (
        missing_component,
        wrong_component_name,
        extra_component,
        size_mismatch,
        hash_mismatch,
        unsafe_directory,
        unsafe_file,
        unsafe_file_symlink,
        unsafe_directory_symlink,
    ):
        expect_v2_asset_failure(mutate)

    for field, wrong in (
        ("release", "wrong-source-release"),
        ("importManifestSha256", "b" * 64),
        ("memberSha256", "c" * 64),
    ):
        def source_mismatch(
            root: Path,
            spec: gs.ReleaseSpec,
            _payloads: dict[str, bytes],
            _directory: Path,
            manifest: dict[str, Any],
            field: str = field,
            wrong: str = wrong,
        ) -> None:
            candidate = copy.deepcopy(manifest)
            candidate["sourceDependencies"][0][field] = wrong
            rewrite_manifest(gs.asset_paths(root, spec)["manifest"], candidate)

        expect_v2_asset_failure(source_mismatch)


def test_import_microg_filename_validation() -> None:
    for gmscore_name, gsfproxy_name in (
        ("wrong-gmscore.apk", gs.MICROG_GSFPROXY_BASENAME),
        (gs.MICROG_GMSCORE_BASENAME, "wrong-gsfproxy.apk"),
    ):
        with tempfile.TemporaryDirectory(prefix="xenoid-google-import-name-contract-") as raw:
            root = Path(raw)
            expect_error(
                "google_services_asset_invalid",
                gs.import_microg,
                root,
                root / gmscore_name,
                root / gsfproxy_name,
            )
            assert not gs.asset_directory(root, gs.MICROG_PLAY_RELEASE).exists()
            assert not (root / ".xenoid").exists()


def test_binding_transitions() -> None:
    spec = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    identity = gs.expected_binding_identity(spec)
    assert (identity["provider"], identity["release"]) == (gs.PROVIDER_MICROG, gs.MICROG_PLAY_RELEASE)
    pending = {**identity, "state": "pending", "source": "explicit"}
    committed = {**identity, "state": "committed", "source": "explicit"}
    assert gs.binding_matches(pending, spec)
    assert gs.transition_decision(
        spec,
        None,
        freshness_known=True,
        fresh=True,
        legacy_actual_none=False,
    )["transition"] == "fresh"
    assert gs.transition_decision(
        spec,
        pending,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )["transition"] == "resume"
    assert gs.transition_decision(
        spec,
        committed,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )["transition"] == "reuse"
    expect_error(
        "google_services_freshness_unknown",
        gs.transition_decision,
        spec,
        None,
        freshness_known=False,
        fresh=False,
        legacy_actual_none=False,
    )
    expect_error(
        "google_services_new_instance_required",
        gs.transition_decision,
        spec,
        None,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    disabled_identity = gs.expected_binding_identity(None)
    assert disabled_identity["specSha256"] == gs.disabled_runtime_spec_fingerprint()
    disabled = {**disabled_identity, "state": "committed", "source": "explicit"}
    expect_error(
        "google_services_new_instance_required",
        gs.transition_decision,
        spec,
        disabled,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    expect_error(
        "google_services_new_instance_required",
        gs.transition_decision,
        None,
        committed,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=False,
    )
    assert gs.transition_decision(
        None,
        None,
        freshness_known=True,
        fresh=False,
        legacy_actual_none=True,
    )["transition"] == "legacy-none"


def set_tree_metadata(root: Path) -> None:
    candidates = [root, *root.rglob("*")]
    for path in sorted((item for item in candidates if item.is_dir()), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o755)
        os.utime(path, ns=(0, 0), follow_symlinks=False)
    for path in (item for item in candidates if item.is_file()):
        path.chmod(0o644)
        os.utime(path, ns=(0, 0), follow_symlinks=False)


def write_context_manifest(context: Path) -> None:
    entries = []
    for path in sorted(
        (candidate for candidate in context.rglob("*") if candidate.name != "context-manifest.json"),
        key=lambda candidate: candidate.relative_to(context).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(context).as_posix()
        if path.is_dir():
            entries.append({"path": relative, "type": "directory", "mode": "0755", "size": 0, "sha256": None})
        else:
            payload = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": "0644",
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    manifest = {"schema": "dev.xenoid.runtime-context/v1", "entries": entries}
    target = context / "context-manifest.json"
    target.write_bytes(canonical_json(manifest))
    target.chmod(0o644)
    os.utime(target, ns=(0, 0), follow_symlinks=False)


def test_canonical_v2_runtime_context_copy() -> None:
    spec, component_payloads, policy_payloads = synthetic_v2_spec()
    files: dict[str, bytes] = {
        str(spec.component(component_id)["runtimePath"]).lstrip("/"): component_payloads[component_id]
        for component_id in ("gmsCore", "gsfProxy", "playStoreSeed")
    }
    files.update(policy_payloads)
    expected_components = {
        "system/product/priv-app/GmsCore/GmsCore.apk",
        "system/product/priv-app/GsfProxy/GsfProxy.apk",
        "system/product/priv-app/Phonesky/Phonesky.apk",
    }
    expected_policy = {str(item["path"]).lstrip("/") for item in spec.product_policy["outputs"]}
    assert {path for path in files if path.endswith(".apk")} == expected_components
    assert set(policy_payloads) == expected_policy
    assert len(files) == 7
    assert all("SetupWizard" not in path and "GoogleServicesFramework" not in path for path in files)

    directories: set[str] = set()
    for relative in files:
        parts = relative.split("/")[:-1]
        directories.update("/".join(parts[:length]) for length in range(1, len(parts) + 1))

    with tempfile.TemporaryDirectory(prefix="xenoid-google-context-contract-") as raw:
        context = Path(raw)
        payload_root = context / "payload" / "google-services"
        for relative, payload in files.items():
            target = payload_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        props = context / "payload" / "props" / "system_build.prop"
        props.parent.mkdir(parents=True)
        props.write_text("ro.product.xenoid.google_provider=microg\n", encoding="utf-8")
        dockerfile = context / "Dockerfile"
        label_lines = [f'LABEL {key}="{value}"' for key, value in sorted(spec.labels.items())]
        docker_text = (
            "\n".join(label_lines)
            + "\nCOPY --chown=0:0 payload/google-services/ /\n"
            + "COPY payload/xenoid-daemon.apk /data/local/tmp/xenoid-daemon.apk\n"
        )
        dockerfile.write_text(docker_text, encoding="utf-8")
        set_tree_metadata(context)
        write_context_manifest(context)

        stage = gs.StageHandle(
            root=context,
            tree=payload_root,
            token="0" * 32,
            file_manifest={
                relative: {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                    "mode": 0o644,
                    "mtimeUtc": 0,
                }
                for relative, payload in files.items()
            },
            directory_manifest={relative: {"mode": 0o755, "mtimeUtc": 0} for relative in directories},
            metadata_digest="1" * 64,
        )
        result = gs.verify_context_copy(context, spec, stage)
        assert result == {
            "ok": True,
            "specSha256": spec.fingerprint,
            "stageMetadataSha256": "1" * 64,
            "files": 7,
        }
        for relative in files:
            target = payload_root / relative
            assert target.stat().st_mtime_ns == 0
            assert stat.S_IMODE(target.stat().st_mode) == 0o644

        props.write_text("ro.setupwizard.mode=UNCHANGED\n", encoding="utf-8")
        props.chmod(0o644)
        os.utime(props, ns=(0, 0), follow_symlinks=False)
        expect_error("google_services_asset_invalid", gs.verify_context_copy, context, spec, stage)
        props.write_text("ro.product.xenoid.google_provider=microg\n", encoding="utf-8")
        props.chmod(0o644)
        os.utime(props, ns=(0, 0), follow_symlinks=False)

        dockerfile.write_text(docker_text + "COPY --chown=0:0 payload/google-services/ /\n", encoding="utf-8")
        expect_error("google_services_asset_invalid", gs.verify_context_copy, context, spec, stage)
        key, value = next(iter(spec.labels.items()))
        dockerfile.write_text(docker_text.replace(f'{key}="{value}"', f'{key}="wrong"'), encoding="utf-8")
        expect_error("google_services_asset_invalid", gs.verify_context_copy, context, spec, stage)
        dockerfile.write_text(docker_text, encoding="utf-8")

        legacy = payload_root / "system/product/priv-app/SetupWizard/SetupWizard.apk"
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b"legacy payload must not be accepted")
        legacy.chmod(0o644)
        os.utime(legacy, ns=(0, 0), follow_symlinks=False)
        legacy.parent.chmod(0o755)
        os.utime(legacy.parent, ns=(0, 0), follow_symlinks=False)
        expect_error("google_services_asset_invalid", gs.verify_context_copy, context, spec, stage)


def _acceptance_validator_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "validate_google_services_release_acceptance",
        ROOT / "scripts" / "validate-google-services-release-acceptance.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identity_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    spec_sha = hashlib.sha256(b"spec").hexdigest()
    runtime_input = hashlib.sha256(b"runtime-input").hexdigest()
    image_id = "sha256:" + hashlib.sha256(b"image").hexdigest()
    data_uuid = "11111111-2222-4333-8444-555555555555"
    binding_sha = hashlib.sha256(b"binding").hexdigest()
    components_sha = hashlib.sha256(b"components").hexdigest()
    evidence = {
        "specSha256": spec_sha,
        "runtimeInputSha256": runtime_input,
        "imageId": image_id,
        "freshData": {"dataUuid": data_uuid},
    }
    pass_item = {
        "pass": True,
        "containerId": "ab" * 32,
        "dataUuid": data_uuid,
        "bindingSha256": binding_sha,
        "runtimeInputSha256": runtime_input,
        "imageId": image_id,
        "effectiveComponentsSha256": components_sha,
        "noBuild": True,
        "noRecreate": True,
    }
    smoke = {
        "specSha256": spec_sha,
        "runtimeInputSha256": runtime_input,
        "noOpPasses": [dict(pass_item), dict(pass_item)],
    }
    repro = {
        "inputSha256A": runtime_input,
        "inputSha256B": runtime_input,
        "imageIdA": image_id,
        "imageIdB": image_id,
    }
    return evidence, smoke, repro


def test_release_acceptance_identity_bindings() -> None:
    validator = _acceptance_validator_module()
    evidence, smoke, repro = _identity_fixture()
    validator._validate_identity_bindings(evidence, smoke, repro)

    def expect_mismatch(mutate: Callable[[], None]) -> None:
        nonlocal evidence, smoke, repro
        evidence, smoke, repro = _identity_fixture()
        mutate()
        try:
            validator._validate_identity_bindings(evidence, smoke, repro)
        except validator.AcceptanceError:
            return
        raise AssertionError("identity mismatch accepted")

    def set_smoke(field: str, value: Any) -> None:
        smoke["specSha256" if field == "spec" else "runtimeInputSha256"] = value

    expect_mismatch(lambda: set_smoke("spec", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: set_smoke("runtime", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: repro.__setitem__("inputSha256B", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: repro.__setitem__("imageIdA", "sha256:" + hashlib.sha256(b"other").hexdigest()))

    def mutate_noop(field: str, value: Any) -> None:
        smoke["noOpPasses"][1][field] = value

    expect_mismatch(lambda: mutate_noop("runtimeInputSha256", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: mutate_noop("imageId", "sha256:" + hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: mutate_noop("dataUuid", "99999999-9999-4999-8999-999999999999"))
    expect_mismatch(lambda: mutate_noop("containerId", "cd" * 32))
    expect_mismatch(lambda: mutate_noop("bindingSha256", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: mutate_noop("effectiveComponentsSha256", hashlib.sha256(b"other").hexdigest()))
    expect_mismatch(lambda: smoke.__setitem__("noOpPasses", smoke["noOpPasses"][:1]))


def main() -> int:
    test_registry_and_metadata()
    test_release_acceptance_identity_bindings()
    test_v2_metadata_exact_keys()
    test_config_pairs_and_retired_resolution()
    test_initialize_defaults_and_explicit_disable()
    test_archive_path_rules()
    test_certificate_rules()
    test_safe_source_copy()
    test_pinned_asset_download()
    test_automatic_asset_acquisition_flow()
    test_v2_quick_asset_validation()
    test_import_microg_filename_validation()
    test_binding_transitions()
    test_canonical_v2_runtime_context_copy()
    print("google services synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
