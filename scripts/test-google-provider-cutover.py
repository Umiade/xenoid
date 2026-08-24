#!/usr/bin/env python3
"""Fail-closed runtime-free contract for the Google provider cutover."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SCHEMA = "dev.xenoid.google-provider-cutover/v1"
MICROG_RELEASE = "microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0"
MINDTHEGAPPS_RELEASE = "MindTheGapps-13.0.0-arm64-20231025_200931"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Contract:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def require(self, condition: Any, label: str) -> None:
        if not condition:
            self.failures.append(label)

    def run(self, label: str, check: Callable[[], None]) -> None:
        try:
            check()
        except Exception as exc:  # The gate reports bounded classifications, never a traceback.
            self.failures.append(f"{label}:{type(exc).__name__}")


def canonical_document(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def subparser(parent: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
    for action in parent._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and name in choices:
            candidate = choices[name]
            if isinstance(candidate, argparse.ArgumentParser):
                return candidate
    raise AssertionError(f"missing parser {name}")


def argument(parser: argparse.ArgumentParser, destination: str) -> argparse.Action:
    for action in parser._actions:
        if action.dest == destination:
            return action
    raise AssertionError(f"missing argument {destination}")


def regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def retired_claim_near_mindthegapps(text: str) -> bool:
    lowered = text.casefold()
    markers = ("retired-source", "retired source", "retired", "\u9000\u5f79", "\u4ec5\u4f5c\u4e3a\u6765\u6e90", "\u4ec5\u7528\u4f5c\u6765\u6e90")
    for match in re.finditer("mindthegapps", lowered):
        window = lowered[max(0, match.start() - 240) : match.end() + 240]
        if any(marker in window for marker in markers):
            return True
    return False


def production_registry_checks(contract: Contract, gs: Any, config: Any) -> None:
    contract.require(getattr(gs, "PROVIDER_MICROG", None) == "microg", "registry.provider-microg")
    contract.require(getattr(gs, "MICROG_PLAY_RELEASE", None) == MICROG_RELEASE, "registry.release-microg")
    contract.require(getattr(gs, "AVAILABILITY_PRODUCTION", None) == "production", "registry.availability-production")
    contract.require(getattr(gs, "AVAILABILITY_RETIRED_SOURCE", None) == "retired-source", "registry.availability-retired")
    contract.require(tuple(gs.registered_releases(selectable_only=True)) == (MICROG_RELEASE,), "registry.selectable-only-production")
    contract.require(set(gs.registered_releases()) == {MICROG_RELEASE, MINDTHEGAPPS_RELEASE}, "registry.release-inventory")
    contract.require(gs.release_availability(MICROG_RELEASE) == "production", "registry.microg-production")
    contract.require(gs.release_availability(MINDTHEGAPPS_RELEASE) == "retired-source", "registry.mtg-retired")
    public = {item.get("release"): item for item in gs.registry_public() if isinstance(item, Mapping)}
    contract.require(public.get(MICROG_RELEASE, {}).get("availability") == "production", "registry.public-microg")
    contract.require(public.get(MINDTHEGAPPS_RELEASE, {}).get("availability") == "retired-source", "registry.public-mtg")

    instance_id = "11111111-2222-4333-8444-555555555555"
    default_cfg = config.new_instance_config("cutover", instance_id)
    contract.require(
        (
            default_cfg.google_services_provider,
            default_cfg.google_services_release,
        )
        == ("microg", MICROG_RELEASE),
        "config.microg-default",
    )
    contract.require(
        default_cfg.auto_build_runtime_image is True,
        "config.default-auto-build",
    )
    none_cfg = config.new_instance_config(
        "cutover",
        instance_id,
        {
            "google_services_provider": "none",
            "google_services_release": "none",
        },
    )
    contract.require(
        (none_cfg.google_services_provider, none_cfg.google_services_release)
        == ("none", "none"),
        "config.explicit-none-pair",
    )
    retired_cfg = config.new_instance_config(
        "cutover",
        instance_id,
        {"google_services_provider": "mindthegapps", "google_services_release": MINDTHEGAPPS_RELEASE},
    )
    contract.require(
        (retired_cfg.google_services_provider, retired_cfg.google_services_release)
        == ("mindthegapps", MINDTHEGAPPS_RELEASE),
        "config.retired-observable",
    )


def production_cli_checks(contract: Contract, cli: Any) -> None:
    parser = cli.build_parser()
    google = subparser(parser, "google-services")
    import_microg = subparser(google, "import-microg")
    contract.require(argument(import_microg, "gmscore") is not None, "cli.import-microg-gmscore")
    contract.require(argument(import_microg, "gsfproxy") is not None, "cli.import-microg-gsfproxy")
    enable = subparser(google, "enable")
    release = argument(enable, "release")
    contract.require(release.default == MICROG_RELEASE, "cli.enable-default")
    contract.require(tuple(release.choices or ()) == (MICROG_RELEASE,), "cli.enable-choices")
    init = subparser(parser, "init")
    no_google = argument(init, "no_google_services")
    contract.require(
        no_google is not None and no_google.default is False,
        "cli.init-explicit-disable",
    )
    up_source = inspect.getsource(cli.cmd_up)
    acquisition_source = inspect.getsource(cli._prepare_google_assets_for_up)
    contract.require(
        "_prepare_google_assets_for_up(args)" in up_source
        and "ensure_google_services_assets" in acquisition_source,
        "cli.up-automatic-acquisition",
    )
    install_runtime = (
        ROOT / "scripts/install-macos-runtime.sh"
    ).read_text(encoding="utf-8")
    contract.require(
        "./xenoid init" not in install_runtime
        and "XENOID_INSTANCE=default" not in install_runtime,
        "install-runtime.no-implicit-init",
    )


def production_mcp_checks(contract: Contract, mcp_server: Any) -> None:
    google_names = {
        "xenoid_google_services_status",
        "xenoid_google_services_enable",
        "xenoid_google_services_disable",
    }
    catalog = {item.get("name"): item for item in mcp_server.tools() if isinstance(item, Mapping)}
    actual_google = {name for name in catalog if isinstance(name, str) and name.startswith("xenoid_google_services_")}
    contract.require(actual_google == google_names, "mcp.google-tool-inventory")
    contract.require(getattr(mcp_server, "MICROG_PLAY_RELEASE", None) == MICROG_RELEASE, "mcp.default-release-constant")
    source = " ".join(inspect.getsource(mcp_server._google_services_result).split())
    contract.require("release=release or MICROG_PLAY_RELEASE" in source, "mcp.default-release-behavior")
    enable_schema = catalog.get("xenoid_google_services_enable", {}).get("inputSchema", {})
    contract.require(
        set(enable_schema.get("properties", {})) == {"release"},
        "mcp.enable-schema",
    )


def production_remote_checks(contract: Contract, remote_service: Any) -> None:
    expected = {
        "xenoid_google_services_status": {"requireRuntime"},
        "xenoid_google_services_enable": {"release"},
        "xenoid_google_services_disable": set(),
    }
    policies = remote_service.REMOTE_TOOL_POLICIES
    for name, properties in expected.items():
        policy = policies.get(name)
        contract.require(policy is not None, f"remote.{name}.present")
        if policy is not None:
            contract.require(set(policy.schema_properties or ()) == properties, f"remote.{name}.properties")
            contract.require("provider" not in set(policy.schema_properties or ()), f"remote.{name}.no-provider-literal")


def production_runtime_image_checks(contract: Contract, runtime_image: Any) -> None:
    source = inspect.getsource(runtime_image.RuntimeImageBuilder._google_inputs)
    for marker in (
        "GOOGLE_RELEASE_SCHEMA_V2",
        "asset_paths",
        "componentSetSha256",
        "providerSchema",
        "importManifestSha256",
        "sourceImportManifestSha256",
        "playStoreSeedSha256",
        "signaturePolicySha256",
        "productPolicySha256",
    ):
        contract.require(marker in source, f"runtime-image.v2-{marker}")


def production_shell_checks(contract: Contract) -> None:
    rootfs = (ROOT / "scripts/make-rootfs-image.sh").read_text(encoding="utf-8")
    context = (ROOT / "scripts/make-runtime-context.sh").read_text(encoding="utf-8")
    contract.require(
        '"$GOOGLE_PROVIDER" == "microg"' in rootfs,
        "rootfs.microg-enum",
    )
    contract.require("googleProvider" in rootfs and '"$GOOGLE_PROVIDER"' in rootfs, "rootfs.provider-identity")
    contract.require("--google-provider" in context and '"$_services_provider"' in context, "runtime-context.services-provider")
    contract.require('[[ "$GOOGLE_PROVIDER" == "microg" ]]' in context, "runtime-context.microg-branch")


def production_gate_checks(contract: Contract, gates: Any) -> None:
    catalog = {item.name: item for item in gates.GATE_CATALOG}
    required = {
        "google-runtime",
        "google-reproducibility",
        "google-provider-cutover-contract",
        "google-release-acceptance",
        "release-google",
    }
    contract.require(required <= set(catalog), "gates.production-inventory")
    if "google-runtime" in catalog:
        contract.require(
            catalog["google-runtime"].command == ("scripts/smoke-google-services-gate.sh",),
            "gates.runtime-command",
        )
    if "google-reproducibility" in catalog:
        contract.require(
            catalog["google-reproducibility"].command == ("scripts/smoke-google-services-reproducibility.sh",),
            "gates.repro-command",
        )
        contract.require(
            catalog["google-reproducibility"].dependencies
            == ("runtime-image-contract", "google-provider-cutover-contract"),
            "gates.repro-dependencies",
        )
    if "google-provider-cutover-contract" in catalog:
        contract.require(
            catalog["google-provider-cutover-contract"].command
            == ("{python}", "scripts/test-google-provider-cutover.py"),
            "gates.cutover-command",
        )
    if "google-release-acceptance" in catalog:
        acceptance = catalog["google-release-acceptance"]
        contract.require(
            acceptance.command == ("{python}", "scripts/validate-google-services-release-acceptance.py"),
            "gates.acceptance-command",
        )
        contract.require(
            acceptance.dependencies
            == ("google-runtime", "google-reproducibility", "google-provider-cutover-contract"),
            "gates.acceptance-dependencies",
        )
        contract.require(
            acceptance.cacheable is False
            and acceptance.sensitive is True
            and acceptance.runtime_free is False
            and acceptance.mutating is False
            and acceptance.privileged is True,
            "gates.acceptance-policy",
        )
    if "release-google" in catalog:
        contract.require(
            catalog["release-google"].dependencies
            == ("static", "release-source-contract", "google-provider-cutover-contract", "google-release-acceptance"),
            "gates.release-google-dependencies",
        )
    contract.require(gates.PROFILE_TARGETS.get("release-google") == "release-google", "gates.release-google-profile")
    contract.require(
        "google-provider-cutover-contract" in catalog.get("release", object()).dependencies
        if "release" in catalog
        else False,
        "gates.release-cutover-dependency",
    )
    for relative in (
        "scripts/smoke-google-services-gate.sh",
        "scripts/smoke-google-services-reproducibility.sh",
        "scripts/validate-google-services-release-acceptance.py",
    ):
        contract.require(regular_file(ROOT / relative), f"gates.command-file:{relative}")


def production_metadata_checks(contract: Contract, gs: Any) -> None:
    expected_paths = {
        "data/google-services/mindthegapps-13.0.0-arm64-20231025_200931.json",
        "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json",
    }
    registered = gs.registered_metadata_files()
    contract.require(set(registered) == expected_paths, "metadata.registry-files")
    data_root = ROOT / "data/google-services"
    entries = tuple(data_root.iterdir())
    actual = {path.relative_to(ROOT).as_posix() for path in entries}
    contract.require(all(regular_file(path) for path in entries), "metadata.regular-files")
    contract.require(actual == expected_paths, "metadata.directory-inventory")
    schemas = {
        MINDTHEGAPPS_RELEASE: (
            getattr(gs, "GOOGLE_RELEASE_SCHEMA_V1", "dev.xenoid.google-release/v1"),
            {"schema", "provider", "release", "integrationRevision", "source", "android", "selection", "archive", "runtimeRequirements", "members", "apks"},
        ),
        MICROG_RELEASE: (
            getattr(gs, "GOOGLE_RELEASE_SCHEMA_V2", "dev.xenoid.google-release/v2"),
            {"schema", "provider", "release", "integrationRevision", "android", "sources", "components", "signaturePolicy", "productPolicy", "runtimeRequirements"},
        ),
    }
    for release, (schema, keys) in schemas.items():
        spec = gs.load_release_spec(ROOT, release)
        raw = spec.metadata_path.read_bytes()
        contract.require(hashlib.sha256(raw).hexdigest() == registered[spec.metadata_path.relative_to(ROOT).as_posix()], f"metadata.digest:{release}")
        parsed = json.loads(raw)
        contract.require(set(parsed) == keys and parsed.get("schema") == schema, f"metadata.exact-top-level:{release}")
        contract.require(gs._validate_release_metadata(parsed, release) == parsed, f"metadata.validator:{release}")


def production_policy_checks(contract: Contract) -> None:
    root = ROOT / "runtime/redroid/microg-policy"
    upstream = root / "upstream"
    expected_upstream = {
        "privapp-permissions-com.google.android.gms.xml",
        "default-permissions-com.google.android.gms.xml",
        "sysconfig-com.google.android.gms.xml",
        "microg.xml",
    }
    actual_upstream = {path.name for path in upstream.glob("*.xml") if path.is_file()}
    contract.require(actual_upstream == expected_upstream, "policy.upstream-inventory")
    for name in expected_upstream:
        contract.require(regular_file(upstream / name), f"policy.upstream-regular:{name}")
    permissions_path = root / "policy-inputs/api33-permissions.json"
    contract.require(regular_file(permissions_path), "policy.api33-present")
    payload = permissions_path.read_bytes()
    value = json.loads(payload)
    contract.require(
        set(value) == {"schema", "frameworkResSha256", "aapt2Sha256", "permissions"},
        "policy.api33-keys",
    )
    contract.require(value.get("schema") == "dev.xenoid.android-permissions/v1", "policy.api33-schema")
    contract.require(HEX64.fullmatch(str(value.get("frameworkResSha256", ""))) is not None, "policy.framework-digest")
    contract.require(HEX64.fullmatch(str(value.get("aapt2Sha256", ""))) is not None, "policy.aapt2-digest")
    permissions = value.get("permissions")
    valid_permissions = isinstance(permissions, list) and bool(permissions)
    contract.require(valid_permissions, "policy.permissions-list")
    if valid_permissions:
        contract.require(
            all(isinstance(item, Mapping) and set(item) == {"name", "protectionLevel"} for item in permissions),
            "policy.permission-keys",
        )
        names = [item.get("name") for item in permissions]
        contract.require(all(isinstance(name, str) and name for name in names), "policy.permission-names")
        contract.require(
            names == sorted(names, key=lambda name: name.encode("utf-8")) and len(set(names)) == len(names),
            "policy.permission-order",
        )
    contract.require(payload == canonical_document(value), "policy.api33-canonical")


def public_claim_paths() -> tuple[Path, ...]:
    required = (
        ROOT / "README.md",
        ROOT / "README_CN.md",
        ROOT / "docs/architecture.md",
        ROOT / "docs/operations.md",
        ROOT / "docs/build.md",
        ROOT / "docs/mcp-tools.md",
        ROOT / "skills/xenoid/SKILL.md",
        ROOT / "skills/xenoid-development/SKILL.md",
    )
    return required


def production_documentation_checks(contract: Contract) -> None:
    for path in public_claim_paths():
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        contract.require(
            MICROG_RELEASE in text,
            f"docs.microg-release:{relative}",
        )
        if relative not in {"README.md", "README_CN.md"}:
            contract.require(
                "MindTheGapps" in text
                and retired_claim_near_mindthegapps(text),
                f"docs.mtg-retired:{relative}",
            )
    for relative in ("examples/config-macos-colima.json", "examples/config-linux-arm.json"):
        value = json.loads((ROOT / relative).read_bytes())
        contract.require(
            value.get("google_services_provider") == "microg"
            and value.get("google_services_release") == MICROG_RELEASE,
            f"examples.microg-default:{relative}",
        )

    for relative, heading in (
        ("README.md", "### Google Services"),
        ("README_CN.md", "### Google \u670d\u52a1"),
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        section = text.split(heading, 1)[1].split("\n### ", 1)[0]
        nonempty = [line for line in section.splitlines() if line.strip()]
        contract.require(len(nonempty) <= 4, f"docs.readme-google-concise:{relative}")
        contract.require(
            "./xenoid up" in text
            and "init --no-google-services" in text
            and "docs/operations.md#google-play-services-default" in text,
            f"docs.readme-default-flow:{relative}",
        )

    operations = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    for required in (
        "github.com/MindTheGapps/13.0.0-arm64/releases/tag/",
        "github.com/microg/GmsCore/releases/tag/v0.3.15.250932",
        "github.com/microg/GsfProxy/releases/tag/v0.1.0",
        "GsfProxy.apk",
        "com.google.android.gsf-8.apk",
        "init --no-google-services",
    ):
        contract.require(required in operations, f"docs.clone-flow:{required}")
    contract.require(
        "automatically downloads" in operations.lower()
        and "automatic acquisition" in operations.lower(),
        "docs.clone-flow:auto-acquisition",
    )
    claim_files = [ROOT / "README.md", ROOT / "README_CN.md", *sorted((ROOT / "docs").glob("*.md")), *sorted((ROOT / "skills").glob("**/*.md"))]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in claim_files)
    lowered = combined.casefold()
    forbidden_selectable = (
        r'"google_services_provider"\s*:\s*"mindthegapps"',
        r"google-services\s+enable[^\n]*mindthegapps",
        r"only accepted enabled pair is\s+`?mindthegapps",
        r"sole (?:known|registered|selectable) release is\s+`?mindthegapps",
    )
    for pattern in forbidden_selectable:
        contract.require(re.search(pattern, lowered) is None, f"docs.retired-not-selectable:{pattern}")
    forbidden_capability = (
        r"\bsupports\s+(?:google\s+)?play integrity",
        r"\bplay integrity\s+(?:is|are)\s+supported",
        r"\bsupports\s+(?:google\s+)?device certification",
        r"\bdevice certification\s+(?:is|are)\s+supported",
        r"\bsupports\s+drm\b",
        r"\bdrm\s+(?:is|are)\s+supported",
        r"(?<!\u4e0d)\u652f\u6301\s*(?:play integrity|drm|device certification)",
    )
    for pattern in forbidden_capability:
        contract.require(re.search(pattern, lowered) is None, f"docs.unsupported-claim:{pattern}")


def disabled_clean_checks(contract: Contract, gs: Any, config: Any, cli: Any, gates: Any) -> None:
    contract.require(not hasattr(gs, "PROVIDER_MICROG"), "disabled.no-provider-constant")
    contract.require(not hasattr(gs, "MICROG_PLAY_RELEASE"), "disabled.no-release-constant")
    contract.require(not hasattr(gs, "import_microg"), "disabled.no-importer")
    contract.require(tuple(gs.registered_releases(selectable_only=True)) == (), "disabled.no-selectable-release")
    contract.require(gs.release_availability(MINDTHEGAPPS_RELEASE) == "retired-source", "disabled.retired-source-retained")
    none_cfg = config.new_instance_config("cutover", "11111111-2222-4333-8444-555555555555")
    contract.require(
        (none_cfg.google_services_provider, none_cfg.google_services_release) == ("none", "none"),
        "disabled.none-pair",
    )
    try:
        config.new_instance_config(
            "cutover",
            "11111111-2222-4333-8444-555555555555",
            {"google_services_provider": "microg", "google_services_release": MICROG_RELEASE},
        )
    except Exception:
        pass
    else:
        contract.require(False, "disabled.microg-config-rejected")
    parser = cli.build_parser()
    google = subparser(parser, "google-services")
    try:
        subparser(google, "import-microg")
    except AssertionError:
        pass
    else:
        contract.require(False, "disabled.no-import-command")
    catalog = {item.name: item for item in gates.GATE_CATALOG}
    contract.require("google-provider-cutover-contract" in catalog, "disabled.cutover-gate-retained")
    for name in ("google-runtime", "google-reproducibility", "google-release-acceptance", "release-google"):
        contract.require(name not in catalog, f"disabled.no-gate:{name}")
    contract.require(gates.PROFILE_TARGETS.get("release-google") is None, "disabled.no-release-google-profile")
    contract.require(not (ROOT / "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json").exists(), "disabled.no-v2-metadata")
    contract.require(not (ROOT / "runtime/redroid/microg-policy").exists(), "disabled.no-policy")
    for path in public_claim_paths():
        text = path.read_text(encoding="utf-8")
        contract.require(MICROG_RELEASE not in text, f"disabled.no-production-claim:{path.relative_to(ROOT).as_posix()}")


def main() -> int:
    contract = Contract()
    try:
        from xenoid import cli, config, gates, google_services as gs, mcp_server, remote_service, runtime_image
    except Exception as exc:
        result = {
            "schema": SCHEMA,
            "ok": False,
            "mode": "mixed",
            "detail": f"module-import:{type(exc).__name__}",
        }
        sys.stdout.buffer.write(canonical_document(result))
        return 1

    core_markers = (
        hasattr(gs, "PROVIDER_MICROG"),
        hasattr(gs, "MICROG_PLAY_RELEASE"),
        hasattr(gs, "import_microg"),
        MICROG_RELEASE in set(gs.registered_releases()),
        (ROOT / "data/google-services/microg-0.3.15.250932-phonesky-30.4.17-gsfproxy-0.1.0.json").exists(),
        (ROOT / "runtime/redroid/microg-policy").exists(),
    )
    production_surface = any(core_markers)
    if production_surface:
        checks = (
            ("registry", lambda: production_registry_checks(contract, gs, config)),
            ("cli", lambda: production_cli_checks(contract, cli)),
            ("mcp", lambda: production_mcp_checks(contract, mcp_server)),
            ("remote", lambda: production_remote_checks(contract, remote_service)),
            ("runtime-image", lambda: production_runtime_image_checks(contract, runtime_image)),
            ("shell", lambda: production_shell_checks(contract)),
            ("gates", lambda: production_gate_checks(contract, gates)),
            ("metadata", lambda: production_metadata_checks(contract, gs)),
            ("policy", lambda: production_policy_checks(contract)),
            ("docs", lambda: production_documentation_checks(contract)),
        )
        for label, check in checks:
            contract.run(label, check)
        ok = not contract.failures
        mode = "production" if ok else "mixed"
        detail = "production-contract-complete" if ok else ",".join(sorted(set(contract.failures)))[:16384]
    else:
        contract.run("disabled", lambda: disabled_clean_checks(contract, gs, config, cli, gates))
        ok = not contract.failures
        mode = "disabled-clean" if ok else "mixed"
        detail = "disabled-clean-contract-complete" if ok else ",".join(sorted(set(contract.failures)))[:16384]

    result = {"schema": SCHEMA, "ok": ok, "mode": mode, "detail": detail}
    sys.stdout.buffer.write(canonical_document(result))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
