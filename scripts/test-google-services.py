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
import re
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
from xenoid import backend as backend_module  # noqa: E402
from xenoid import cli as xenoid_cli  # noqa: E402
from xenoid import daemon_client as daemon_client_module  # noqa: E402


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
    store = object.__new__(gs.GoogleBindingStore)
    store.context = SimpleNamespace(instance_id=INSTANCE_ID)
    store.load = lambda: committed
    first_gsf = store.regeneration_gsf_android_id("1" * 32)
    assert first_gsf == store.regeneration_gsf_android_id("1" * 32)
    assert first_gsf != store.regeneration_gsf_android_id("2" * 32)
    assert first_gsf.isdigit() and 0 < int(first_gsf) <= (1 << 63) - 1
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



def test_google_identity_response_contract() -> None:
    digest = hashlib.sha256(b"identity").hexdigest()
    good = {
        "ok": True,
        "schema": daemon_client_module.GOOGLE_IDENTITY_SCHEMA,
        "advertisingIdSha256": digest,
        "gsfAndroidIdPresent": True,
        "gsfAndroidIdSha256": digest,
        "offlineSeeded": True,
    }
    assert daemon_client_module._validated_google_identity(good) == good
    absent = {
        **good,
        "gsfAndroidIdPresent": False,
        "gsfAndroidIdSha256": None,
        "offlineSeeded": False,
    }
    assert daemon_client_module._validated_google_identity(absent) == absent
    malformed = {**good, "advertisingIdSha256": "not-a-digest"}
    assert daemon_client_module._validated_google_identity(malformed)["error"] == (
        "daemon_response_invalid"
    )
    malformed_seed = {**good, "offlineSeeded": "true"}
    assert daemon_client_module._validated_google_identity(malformed_seed)["error"] == (
        "daemon_response_invalid"
    )
    inconsistent_seed = {
        **good,
        "gsfAndroidIdPresent": False,
        "gsfAndroidIdSha256": None,
    }
    assert daemon_client_module._validated_google_identity(inconsistent_seed)["error"] == (
        "daemon_response_invalid"
    )
    unsafe = {
        "ok": False,
        "schema": daemon_client_module.GOOGLE_IDENTITY_SCHEMA,
        "error": "secret: leaked",
    }
    assert daemon_client_module._validated_google_identity(unsafe)["error"] == (
        "daemon_response_invalid"
    )

def test_runtime_google_identity_rotation_contract() -> None:
    target = "123456789012345678"
    old_ad = hashlib.sha256(b"old-ad").hexdigest()
    new_ad = hashlib.sha256(b"new-ad").hexdigest()
    empty_ad = hashlib.sha256(
        b"00000000-0000-0000-0000-000000000000"
    ).hexdigest()
    old_gsf = hashlib.sha256(b"old-gsf").hexdigest()
    new_gsf = hashlib.sha256(target.encode("ascii")).hexdigest()
    response = {
        "ok": True,
        "advertisingIdSha256": new_ad,
        "gsfAndroidIdSha256": new_gsf,
        "offlineSeeded": True,
    }
    current = {
        "response": {
            "ok": True,
            "advertisingIdSha256": old_ad,
            "gsfAndroidIdSha256": old_gsf,
            "offlineSeeded": False,
        }
    }
    seeded_marker = {"present": False}
    activated: list[str] = []
    healed: list[float] = []

    def activate(value: str, timeout: float) -> dict[str, Any]:
        activated.append(value)
        current["response"] = dict(response)
        seeded_marker["present"] = True
        return dict(response)

    def status(timeout: float) -> dict[str, Any]:
        healed.append(timeout)
        return {
            **current["response"],
            "offlineSeeded": seeded_marker["present"],
        }

    client = SimpleNamespace(
        google_identity_status=status,
        google_identity_activate=activate,
        google_identity_inspect=lambda timeout: {
            **current["response"],
            "offlineSeeded": seeded_marker["present"],
        },
    )
    manager = SimpleNamespace(
        cfg=SimpleNamespace(google_services_provider=gs.PROVIDER_MICROG),
        context=object(),
        lease=object(),
        daemon_client=lambda timeout: client,
        _offline_google_identity_seeded=lambda: seeded_marker["present"],
    )
    state = {
        "transactionId": "3" * 32,
        "before": {
            "advertisingIdDigest": old_ad,
            "gsfAndroidIdDigest": old_gsf,
        },
    }
    binding = {"state": "committed"}
    store = SimpleNamespace(
        load=lambda: dict(binding),
        regeneration_gsf_android_id=lambda transaction: target,
    )
    with (
        mock.patch.object(xenoid_cli, "GoogleBindingStore", return_value=store),
        mock.patch.object(
            xenoid_cli, "resolve_google_runtime_spec", return_value=object()
        ),
        mock.patch.object(xenoid_cli, "binding_matches", return_value=True) as matches,
    ):
        preflight = xenoid_cli._regeneration_google_preflight(
            manager, state["transactionId"]
        )
        rotated = xenoid_cli._regeneration_google_identity(
            manager, state, activate=True
        )
        observed = xenoid_cli._regeneration_google_identity(
            manager, state, activate=False
        )
        resumed = xenoid_cli._regeneration_google_identity(
            manager, state, activate=True
        )

        # Crash after provider DB commit but before marker replacement: matching
        # digests are not durable proof.  Passive inspection rejects; activation
        # must run again and idempotently republish/read back the marker.
        current["response"] = dict(response)
        seeded_marker["present"] = False
        unpublished = xenoid_cli._regeneration_google_identity(
            manager, state, activate=False
        )
        republished = xenoid_cli._regeneration_google_identity(
            manager, state, activate=True
        )

        current["response"]["advertisingIdSha256"] = empty_ad
        limited = xenoid_cli._regeneration_google_identity(
            manager, state, activate=False
        )
        current["response"]["advertisingIdSha256"] = old_ad
        unchanged = xenoid_cli._regeneration_google_identity(
            manager, state, activate=False
        )

        binding["state"] = "pending"
        pending_preflight = xenoid_cli._regeneration_google_preflight(
            manager, state["transactionId"]
        )
        binding["state"] = "committed"
        matches.return_value = False
        incompatible_preflight = xenoid_cli._regeneration_google_preflight(
            manager, state["transactionId"]
        )

    assert preflight == {"ok": True}
    assert healed == [60.0]
    assert activated == [target, target]
    assert rotated["ok"] is True and observed["ok"] is True and resumed["ok"] is True
    assert republished["ok"] is True
    assert unpublished == {
        "ok": False,
        "error": "google_identity_rotation_unverified",
    }
    assert target not in json.dumps(rotated)
    for rejected in (limited, unchanged):
        assert rejected == {
            "ok": False,
            "error": "google_identity_rotation_unverified",
        }
    assert pending_preflight == {
        "ok": False,
        "error": "google_services_runtime_not_ready",
    }
    assert incompatible_preflight == {
        "ok": False,
        "error": "google_services_new_instance_required",
    }

    manager.cfg.google_services_provider = gs.PROVIDER_NONE
    skipped = xenoid_cli._regeneration_google_identity(
        manager, state, activate=True
    )
    assert skipped["ok"] is True and skipped["skipped"] is True
    skipped_preflight = xenoid_cli._regeneration_google_preflight(
        manager, state["transactionId"]
    )
    assert skipped_preflight["ok"] is True and skipped_preflight["skipped"] is True

    manager.cfg.google_services_provider = gs.PROVIDER_MINDTHEGAPPS
    unsupported = xenoid_cli._regeneration_google_identity(
        manager, state, activate=True
    )
    assert unsupported == {
        "ok": False,
        "error": "google_identity_rotation_unsupported",
    }
    unsupported_preflight = xenoid_cli._regeneration_google_preflight(
        manager, state["transactionId"]
    )
    assert unsupported_preflight == unsupported


def test_offline_identity_downgrades_cloud_messaging() -> None:
    online = backend_module._google_identity_capability_model(
        gs.PROVIDER_MICROG,
        "ready",
        offline_identity_seeded=False,
    )
    offline = backend_module._google_identity_capability_model(
        gs.PROVIDER_MICROG,
        "ready",
        offline_identity_seeded=True,
    )
    assert "cloudMessaging" in online["requiredCapabilities"]
    assert "cloudMessaging" not in offline["requiredCapabilities"]
    assert offline["capabilities"]["cloudMessaging"] == {
        "scope": "runtime-release",
        "runtimeState": "unsupported",
        "releaseState": "unsupported",
        "evidence": "offline-checkin-disabled",
    }

    manager = object.__new__(backend_module.RuntimeManager)
    observed_processes: list[str] = []

    def process_identity(process: str) -> tuple[int, int]:
        observed_processes.append(process)
        return (123, 456)

    manager._microg_process_identity = process_identity
    manager._microg_exit_history = lambda packages, deadline: {
        "ok": True,
        "code": None,
        "detail": None,
    }
    stability = manager._microg_process_stability({}, 0.0)
    assert stability["ok"] is True
    assert observed_processes[:2] == [
        "com.google.android.gms",
        "com.google.android.gms",
    ]


def _java_string_literal_bytes(source: str) -> int:
    tokens = re.findall(r'"(?:\\.|[^"\\])*"', source)
    return sum(len(json.loads(token).encode("utf-8")) for token in tokens)


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def test_microg_identity_seed_is_offline() -> None:
    root_source = (
        ROOT
        / "daemon/app/src/main/java/dev/xenoid/daemon/RootHelper.java"
    ).read_text(encoding="utf-8")
    method = root_source.split(
        "static Map<String,Object> seedGoogleIdentity", 1
    )[1].split("private static Map<String,Object> execRootd", 1)[0]
    manager_source = (
        ROOT
        / "daemon/app/src/main/java/dev/xenoid/daemon/GoogleIdentityManager.java"
    ).read_text(encoding="utf-8")
    service_source = (
        ROOT
        / "daemon/app/src/main/java/dev/xenoid/daemon/XenoidDaemonService.java"
    ).read_text(encoding="utf-8")


    # The activation guard proves the exact immutable factory asset, not merely
    # that some package named com.google.android.gms happens to live under /system.
    pinned = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE).component("gmsCore")
    assert str(pinned["runtimePath"]) in root_source
    assert str(pinned["sha256"]) in root_source
    assert r"[ \"$pa\" = 'package:" in root_source
    assert "UPDATED_SYSTEM_APP" in root_source
    assert "sha256sum $pa" in root_source
    assert method.index("pinnedSurfacePredicate()") < method.index(
        '+ "precheck;"'
    ) < method.index("am force-stop com.google.android.gms")
    assert method.count("am force-stop com.google.android.gms") == 1

    # All relevant paths are classified before force-stop.  Database/main/backup/
    # sidecar files must be non-symlink regular nlink==1 files owned only by the
    # package uid or root (root permits crash-created SQLite recovery state).
    pre_force = method[: method.index("am force-stop com.google.android.gms")]
    assert "/data/local/tmp/xenoid-profile" in pre_force
    assert r'stat -c %u:%g:%a $x)\" = 0:0:700' in pre_force
    for suffix in ("$b", "$b-journal", "$b-wal", "$b-shm"):
        assert suffix in pre_force
    for path in ("$q", "$qb", "$c", "$cb", "$qt", "$ct", "$m", "$t"):
        assert path in pre_force
    assert 'String command = "set -eu;umask 077;"' in method
    assert r'[ ! -L \"$1\" ]&&[ -f \"$1\" ]' in pre_force
    assert r'stat -c %h \"$1\"' in pre_force
    assert r'\"$o\" = \"$u:$g\"' in pre_force and r'\"$o\" = 0:0' in pre_force
    assert r'stat -c %h:%u:%g:%a $f)\" = 1:0:0:600' in pre_force
    marker_probe = root_source.split(
        "static Map<String,Object> offlineGoogleIdentitySeeded", 1
    )[1].split("static Map<String,Object> seedGoogleIdentity", 1)[0]
    assert "Long.parseLong(lines[1])" in marker_probe
    assert "google_identity_seed_state_invalid" in marker_probe

    # A killed root sqlite transaction may leave root-owned sidecars.  Resume first
    # asks sqlite to recover the hot journal, then removes inert sidecars and runs
    # the idempotent seed transaction; it never unlinks a hot journal first.
    recover = method.index(
        "/system/bin/sqlite3 $b 'PRAGMA wal_checkpoint(TRUNCATE);PRAGMA user_version;'"
    )
    cleanup = method.index("rm -f $b-journal $b-wal $b-shm", recover)
    transaction = method.index("/system/bin/sqlite3 $b ", cleanup)
    assert recover < cleanup < transaction
    assert method.index("BEGIN IMMEDIATE") < method.index("COMMIT;")
    assert "CREATE TABLE IF NOT EXISTS main" in method
    assert "PRAGMA user_version=3" in method
    assert "DELETE FROM overrides WHERE name='android_id'" in method
    assert "PRAGMA wal_checkpoint(TRUNCATE)" in method

    # Android treats .bak as authoritative.  Generate the new disabled prefs from
    # the backup when present, then publish a target-valued backup before replacing
    # the main file.  At every crash point restoration yields the new target; only
    # after the main and directory are durable is the target backup removed.
    assert "r=$q;[ ! -f $qb ]||r=$qb" in method
    put = method.split('put(){', 1)[1].split('};"', 1)[0]
    assert put.index("sync -f $a") < put.index("cp -p $a $k")
    assert put.index("mv -f $k $n.bak") < put.index(
        "sync -f $s"
    ) < put.index("mv -f $a $n") < put.index("sync -f $n")
    assert put.index("sync -f $n") < put.index("rm -f $n.bak") < put.rindex(
        "sync -f $s"
    )
    assert method.index("put $qt $q $ct") < method.index("put $ct $c $qt")
    assert "checkin_enable_service" in method
    assert "value=\\\"false\\\"" in method
    assert all(
        forbidden not in method
        for forbidden in (
            "CheckinService",
            "PushRegisterService",
            "checkin.googleapis.com",
            "curl ",
            "wget ",
        )
    )

    # Durable completion is the exact GSF marker at this protected location.  It
    # is staged root:root 0600, fsynced, atomically renamed, directory-fsynced, and
    # content/mode read back.  Re-running activate republishes it unconditionally.
    assert "m=$x/gsf_android_id;t=$m.tmp" in method
    assert method.index("chown 0:0 $t;chmod 600 $t") < method.index(
        "sync -f $t"
    ) < method.index("mv -f $t $m;sync -f $x")
    assert r'stat -c %h:%u:%g:%a $m)\" = 1:0:0:600' in method
    assert '$(cat $m)' in method

    # The generated rootd request must remain under MAX_COMMAND_BYTES=4096 even at
    # the maximum 19-digit target.  This computes its exact runtime length from the
    # Java literal fragments plus the dynamic concatenations.
    worst_gsf = "9" * 19
    checkin = (
        "<?xml version='1.0' encoding='utf-8'?><map>"
        f'<long name="androidId" value="{worst_gsf}" />'
        '<string name="digest">1-929a0dca0eee55513280171a8585da7dcd3700f8</string>'
        '<long name="lastCheckin" value="0" />'
        '<long name="securityToken" value="0" />'
        '<string name="versionInfo"></string>'
        '<string name="deviceDataVersionInfo"></string></map>'
    )
    sql = (
        "BEGIN IMMEDIATE;"
        "CREATE TABLE IF NOT EXISTS main (name TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE IF NOT EXISTS overrides (name TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE IF NOT EXISTS saved_system (name TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE IF NOT EXISTS saved_secure (name TEXT PRIMARY KEY, value TEXT);"
        "PRAGMA user_version=3;"
        "DELETE FROM overrides WHERE name='android_id';"
        "INSERT OR REPLACE INTO main(name,value) VALUES('android_id','"
        f"{worst_gsf}');COMMIT;PRAGMA wal_checkpoint(TRUNCATE);"
    )
    command_expression = method.split("String command = ", 1)[1].split(
        "return execRootd(command", 1
    )[0]
    literal_bytes = _java_string_literal_bytes(command_expression)
    predicate = root_source.split(
        "private static String pinnedSurfacePredicate()", 1
    )[1].split("private static boolean rootdTransportFailure", 1)[0]
    # Two path interpolations and one digest interpolation are the predicate's
    # only non-literal pieces.
    predicate_bytes = _java_string_literal_bytes(predicate)
    predicate_bytes += 2 * len(str(pinned["runtimePath"]).encode("utf-8"))
    predicate_bytes += len(str(pinned["sha256"]).encode("ascii"))
    command_bytes = literal_bytes + predicate_bytes
    command_bytes += len(_shell_quote(checkin).encode("utf-8"))
    command_bytes += len(_shell_quote(sql).encode("utf-8"))
    command_bytes += command_expression.count("shellQuote(gsfAndroidId)") * len(
        _shell_quote(worst_gsf).encode("ascii")
    )
    assert command_bytes <= 4096, command_bytes

    # GAID is an opaque live microG postcondition, not a pretend persisted target:
    # upstream exposes no exact setter.  Every offline-seeded status/construction/
    # rebind clears the global limit and rejects zero.  GSF remains exact by marker.
    assert "MemoryAdvertisingIdConfiguration" in manager_source
    assert "no exact-ID setter" in manager_source
    assert "/gaid" not in manager_source.lower()
    assert "private final Object opLock" in manager_source
    assert manager_source.count("synchronized (opLock)") == 3
    assert "newSingleThreadExecutor" in manager_source
    assert "BinderConnection implements ServiceConnection, IBinder.DeathRecipient" in manager_source
    assert "bindGeneration != generation" in manager_source
    assert "compareAndSet(false, true)" in manager_source
    assert "MAX_COMMAND_BYTES = 4096" in root_source
    assert "activeConnection = null" in manager_source
    observe = manager_source.split(
        "private Map<String, Object> observe", 1
    )[1].split("private void scheduleHeal", 1)[0]
    assert observe.index("googleProviderSurface") < observe.index(
        "awaitAdvertisingBinder"
    ) < observe.index("setAdTrackingLimitedGlobally(binder, false)")
    inspect = manager_source.split("Map<String, Object> inspect()", 1)[1].split(
        "Map<String, Object> activate", 1
    )[0]
    assert "advertisingBinder" in inspect
    assert "isBinderAlive()" in inspect and "pingBinder()" in inspect
    assert "RootHelper.offlineGoogleIdentitySeeded()" in inspect
    assert "RootHelper.googleProviderSurface()" in inspect
    assert "seededGsf.equals(gsfAndroidId)" in inspect
    for forbidden in (
        "awaitAdvertisingBinder",
        "bindService",
        "seedGoogleIdentity",
        "resetAdvertisingId",
        "setAdTrackingLimitedGlobally",
        "invalidateGoogleServicesCaches",
    ):
        assert forbidden not in inspect
    assert "seededGsf.equals(gsfAndroidId)" in manager_source
    assert "notifyChange(GSERVICES, null)" in manager_source
    assert "com.google.gservices.intent.action.GSERVICES_CHANGED" in manager_source
    assert 'result.put("offlineSeeded", offlineSeeded)' in manager_source
    activate_source = manager_source.split("Map<String, Object> activate", 1)[1].split(
        "private boolean invalidateGoogleServicesCaches", 1
    )[0]
    assert activate_source.index("googleProviderSurface()") < activate_source.index(
        "disconnect();"
    ) < activate_source.index("seedGoogleIdentity(gsfAndroidId)")
    assert "RootHelper.ensureGoogleRuntime()" not in manager_source

    # Daemon recreation constructs a fresh manager (which schedules serialized
    # heal), service teardown closes the binder registration, and activate accepts
    # only the single strict SimpleJson-compatible string field.
    assert "googleIdentityManager = new GoogleIdentityManager(this)" in service_source
    assert "if (googleIdentity != null) googleIdentity.close()" in service_source
    route = service_source.split("private Map<String, Object> routeGoogleIdentity", 1)[1]
    assert 'request.keySet().equals(Collections.singleton("gsfAndroidId"))' in route
    assert 'request.get("gsfAndroidId") instanceof String' in route
    assert '"schema", GoogleIdentityManager.SCHEMA' in route
    assert '"/google-identity/inspect".equals(path)' in route
    assert "return manager.inspect()" in route
    assert '"error", "google_identity_unavailable"' in route




def test_apk_signer_history_uses_bounded_runner() -> None:
    observed: dict[str, Any] = {}

    def runner(
        command: list[str],
        *,
        capture: bool,
        timeout: float,
    ) -> SimpleNamespace:
        observed.update(command=command, capture=capture, timeout=timeout)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "Signer #1 certificate SHA-256 digest: "
                + "a" * 64
                + "\nSource Stamp Signer certificate SHA-256 digest: "
                + "c" * 64
                + "\n"
            ),
        )

    manager = object.__new__(backend_module.RuntimeManager)
    with (
        mock.patch.object(backend_module, "which", return_value="/apksigner"),
        mock.patch.object(backend_module, "run", side_effect=runner),
    ):
        history = manager._apk_signer_history(b"apk")
    assert history == ["a" * 64]
    assert observed["capture"] is True
    assert observed["timeout"] == 120

def test_updated_system_component_uses_public_flag() -> None:
    spec = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    component = next(
        item for item in spec.components if item["id"] == "playStoreSeed"
    )
    pinned_history = list(component["signingCertificateHistorySha256"])
    manager = object.__new__(backend_module.RuntimeManager)

    def adb_shell(args: list[str], *, timeout: float) -> str:
        if args[:2] == ["pm", "path"]:
            return "package:/data/app/com.android.vending/base.apk\n"
        if args[:4] == ["pm", "list", "packages", "-e"]:
            return "package:com.android.vending\n"
        if args[:2] == ["dumpsys", "package"]:
            return (
                f"  versionCode={int(component['versionCode']) + 1} minSdk=21 targetSdk=33\n"
                "  versionName=updated\n"
                "  flags=[ SYSTEM HAS_CODE UPDATED_SYSTEM_APP ]\n"
                "  privateFlags=[ PRIVILEGED PRODUCT ]\n"
            )
        raise AssertionError(args)

    rotated_signer = "b" * 64
    manager._adb_shell_text = adb_shell
    manager._adb_read_file_bytes = lambda *args, **kwargs: b"signed-apk"
    manager._apk_signer_history = lambda apk: [rotated_signer]
    record = manager._microg_component_record(spec, component)
    assert record["ok"] is True
    assert record["updatedSystemApp"] is True
    assert record["signerSha256"] == rotated_signer
    assert record["signerSha256"] != pinned_history[0]

def test_google_signature_policy_uses_live_image() -> None:
    image_id = "sha256:" + "1" * 64
    records: dict[tuple[str, str], dict[str, Any]] = {
        ("container", "xenoid-android-test"): {"Image": image_id},
        ("image", image_id): {
            "Id": image_id,
            "Config": {
                "Labels": {
                    "dev.xenoid.runtime_schema": "1",
                    "dev.xenoid.runtime_input_sha256": "2" * 64,
                    "dev.xenoid.runtime_boot_input_sha256": "3" * 64,
                    "google.provider": "microg",
                }
            },
        },
    }
    calls: list[tuple[str, str]] = []

    def inspect(kind: str, name: str) -> tuple[dict[str, Any], None]:
        calls.append((kind, name))
        return records.get((kind, name), {}), None

    manager = SimpleNamespace(
        lease=SimpleNamespace(container_name="xenoid-android-test"),
        _inspect_docker_object=inspect,
        _container_has_lease_owner=lambda container: bool(container),
        _google_label_values=lambda: ("google.provider",),
    )
    manager._google_live_runtime_image = lambda value: (
        xenoid_cli.RuntimeManager._google_live_runtime_image(manager, value)
    )
    spec = SimpleNamespace(labels={"google.provider": "microg"})
    matcher = xenoid_cli.RuntimeManager._google_signature_runtime_image_matches
    assert matcher(manager, spec) is True
    assert calls == [
        ("container", "xenoid-android-test"),
        ("image", image_id),
    ]
    records[("image", image_id)]["Config"]["Labels"]["google.provider"] = "other"
    assert matcher(manager, spec) is False


def test_google_status_accepts_verified_live_image_without_source_assets() -> None:
    spec = gs.load_release_spec(ROOT, gs.MICROG_PLAY_RELEASE)
    image_id = "sha256:" + "1" * 64
    rootfs_id = "sha256:" + "4" * 64
    input_digest = "2" * 64
    boot_digest = "3" * 64
    image_labels = {
        backend_module._RUNTIME_SCHEMA_LABEL: "1",
        backend_module._RUNTIME_INPUT_LABEL: input_digest,
        backend_module._RUNTIME_BOOT_INPUT_LABEL: boot_digest,
        **spec.labels,
    }
    runtime_image = {
        "Id": image_id,
        "Config": {"Labels": image_labels},
    }
    container = {
        "Id": "5" * 64,
        "Image": image_id,
        "State": {"Running": True},
        "Config": {"Cmd": ["boot"], "Labels": {}},
    }
    rootfs_image = {
        "Id": rootfs_id,
        "Config": {"Labels": image_labels},
    }

    def selected_runtime_image(**_kwargs: Any) -> dict[str, Any]:
        raise gs.GoogleServicesError(
            "google_services_assets_missing",
            "source assets unavailable",
        )

    def inspect(kind: str, name: str) -> tuple[dict[str, Any], None]:
        if kind == "container":
            return container, None
        if kind == "volume":
            return {"Mountpoint": "/volume"}, None
        if kind == "image" and name == rootfs_id:
            return rootfs_image, None
        return {}, None

    manager = SimpleNamespace(
        cfg=SimpleNamespace(
            google_services_provider=gs.PROVIDER_MICROG,
            google_services_release=gs.MICROG_PLAY_RELEASE,
        ),
        context=SimpleNamespace(project_root=ROOT, instance_name="test"),
        lease=SimpleNamespace(
            container_name="xenoid-android-test",
            volume_name="xenoid-data-test",
        ),
        google_runtime_spec=lambda *_args, **_kwargs: spec,
        selected_runtime_image=selected_runtime_image,
        _google_live_runtime_image=lambda _spec: (
            {
                "imageId": image_id,
                "derivedTag": image_id,
                "inputSha256": input_digest,
                "bootInputSha256": boot_digest,
            },
            runtime_image,
        ),
        _inspect_docker_object=inspect,
        _container_has_lease_owner=lambda _container: True,
        _managed_container_labels_match=lambda _labels: True,
        _android_boot_command=lambda: ["boot"],
        _volume_matches_lease=lambda _volume: True,
        _engine_host_shell=lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=rootfs_id + "\n",
        ),
        google_services_bootstrap_gate=lambda _spec: {
            "ok": True,
            "error": None,
            "checks": {},
            "components": {},
        },
        _offline_google_identity_seeded=lambda: False,
    )
    binding = {"state": "committed"}
    with (
        mock.patch.object(
            backend_module,
            "quick_validate_assets",
            side_effect=gs.GoogleServicesError(
                "google_services_assets_missing",
                "source assets unavailable",
            ),
        ),
        mock.patch.object(
            backend_module,
            "GoogleBindingStore",
            return_value=SimpleNamespace(load=lambda: binding),
        ),
        mock.patch.object(backend_module, "binding_matches", return_value=True),
        mock.patch.object(backend_module, "public_binding", return_value=binding),
    ):
        status = backend_module.RuntimeManager.google_services_status(
            manager,
            require_runtime=True,
        )
    assert status["ok"] is True
    assert status["ready"] is True
    assert status["hostReady"] is True
    assert status["error"] is None
    assert status["runtimeIdentity"]["imageMatch"] == "live-image"


def test_regeneration_snapshot_uses_passive_inspect_only() -> None:
    digest_ad = hashlib.sha256(b"ad").hexdigest()
    digest_gsf = hashlib.sha256(b"gsf").hexdigest()
    container_id = "1" * 64
    image_id = "sha256:" + "2" * 64
    image_input = "3" * 64
    image_boot_input = "4" * 64
    container_identity_epoch = backend_module.container_epoch(container_id)
    manager = object.__new__(backend_module.RuntimeManager)
    manager.context = SimpleNamespace(
        state_root=Path("/nonexistent"), instance_id=INSTANCE_ID
    )
    manager.lease = object()
    manager.cfg = SimpleNamespace(google_services_provider=gs.PROVIDER_MICROG)
    manager.ensure_instance_lease = lambda: None
    manager._owned_container_record = lambda: (
        {"Id": container_id, "Image": image_id, "State": {"Running": True}},
        None,
    )
    manager._inspect_docker_object = lambda kind, name: (
        {
            "Id": image_id,
            "Config": {
                "Labels": {
                    backend_module._RUNTIME_SCHEMA_LABEL: "1",
                    backend_module._RUNTIME_INPUT_LABEL: image_input,
                    backend_module._RUNTIME_BOOT_INPUT_LABEL: image_boot_input,
                }
            },
        },
        None,
    )
    manager._container_matches_lease = lambda *args, **kwargs: True
    manager.docker_exec = lambda *args, **kwargs: {"ok": True, "stdout": ""}
    manager.shared_protection_status = lambda: {
        "ok": True,
        "engineId": "AA:BB:CC:DD",
        "expectedDigest": "5" * 64,
    }
    manager._regeneration_digest = lambda value: "d" * 64
    observed: list[tuple[str, Any]] = []

    class PassiveClient:
        def bootstrap_status(self, timeout: float) -> dict[str, Any]:
            observed.append(("bootstrap", timeout))
            return {"ok": True, "runtimeEpoch": "c" * 64}

        def google_identity_inspect(self, timeout: float) -> dict[str, Any]:
            observed.append(("inspect", timeout))
            return {
                "ok": True,
                "schema": daemon_client_module.GOOGLE_IDENTITY_SCHEMA,
                "advertisingIdSha256": digest_ad,
                "gsfAndroidIdPresent": True,
                "gsfAndroidIdSha256": digest_gsf,
                "offlineSeeded": True,
            }

        def google_identity_status(self, timeout: float) -> dict[str, Any]:
            raise AssertionError("snapshot must not call the repairing status path")

        def google_identity_activate(self, value: str, timeout: float) -> dict[str, Any]:
            raise AssertionError("snapshot must never activate or publish")

    manager.daemon_client = lambda timeout: PassiveClient()
    binding = {
        "provider": gs.PROVIDER_MICROG,
        "release": gs.MICROG_PLAY_RELEASE,
        "specSha256": "e" * 64,
        "dataCompatibilitySha256": "f" * 64,
    }
    import xenoid.location as location_module

    with (
        mock.patch.object(
            backend_module,
            "stable_identity_digest",
            return_value="s" * 64,
        ),
        mock.patch.object(
            backend_module,
            "DeviceIdentityStore",
            return_value=SimpleNamespace(
                load=lambda: {
                    "stable": {},
                    "active": {
                        "bootId": "boot-1",
                        "containerEpoch": container_identity_epoch,
                    },
                }
            ),
        ),
        mock.patch.object(
            location_module,
            "LocationStateStore",
            return_value=SimpleNamespace(
                load=lambda: {
                    "simEpoch": 1,
                    "active": {"profileDigest": "0" * 64, "simEpoch": 1},
                }
            ),
        ),
        mock.patch.object(
            backend_module,
            "GoogleBindingStore",
            return_value=SimpleNamespace(load=lambda: dict(binding)),
        ),
    ):
        snapshot = manager.regeneration_snapshot()
    assert observed == [("bootstrap", 15.0), ("inspect", 60.0)]
    assert snapshot["advertisingIdDigest"] == digest_ad
    assert snapshot["gsfAndroidIdDigest"] == digest_gsf
    assert snapshot["protectionEngineId"] == "AA:BB:CC:DD"
    assert snapshot["protectionExpectedDigest"] == "5" * 64


def main() -> int:
    test_registry_and_metadata()
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
    test_runtime_google_identity_rotation_contract()
    test_offline_identity_downgrades_cloud_messaging()
    test_regeneration_snapshot_uses_passive_inspect_only()
    test_microg_identity_seed_is_offline()
    test_apk_signer_history_uses_bounded_runner()
    test_updated_system_component_uses_public_flag()
    test_google_signature_policy_uses_live_image()
    test_google_identity_response_contract()
    test_canonical_v2_runtime_context_copy()
    print("google services synthetic tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
