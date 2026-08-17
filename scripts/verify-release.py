#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, inspect, json, pathlib, tarfile, tempfile, sys
GENERIC_CAMERA_PATHS = [
  'native/xenoid-camerahal/android.hardware.camera.provider-service-aidl',
  'native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml',
  'native/xenoid-camerahal/media_profiles_V1_0.xml',
  'native/xenoid-gralloc/gralloc.redroid.so',
  'artifacts/android.hardware.camera.provider-service-aidl',
  'artifacts/android.hardware.camera.provider.ICameraProvider.xml',
  'artifacts/media_profiles_V1_0.xml',
  'artifacts/gralloc.redroid.so',
]
RETIRED_CAMERA_BASENAMES = {
  'xenoid-camerahal',
  'xenoid-camerahal.rc',
}
GENERIC_RUNTIME_CAMERA_TOKENS = (
  'service vendor.camera-provider-aidl /system/bin/hw/android.hardware.camera.provider-service-aidl',
  'COPY payload/android.hardware.camera.provider-service-aidl /system/bin/hw/android.hardware.camera.provider-service-aidl',
  'COPY --chmod=644 payload/gralloc.redroid.so /vendor/lib64/hw/gralloc.redroid.so',
  'COPY --chmod=644 payload/media_profiles_V1_0.xml /vendor/etc/media_profiles_V1_0.xml',
)
RETIRED_RUNTIME_CAMERA_TOKENS = (
  'service xenoid-camerahal ',
  '/system/bin/xenoid-camerahal',
  '/system/bin/hw/xenoid-camerahal',
  'init.svc.xenoid-camerahal',
)
CAMERA_HARNESS_JAVA_PREFIX = 'tests/camera-runtime-probe/java/org/example/cameraruntimeprobe/'
CAMERA_HARNESS_JAVA_PATHS = [
  CAMERA_HARNESS_JAVA_PREFIX + name
  for name in (
    'CamcorderProfilesProbeActivity.java',
    'Camera2ProbeActivity.java',
    'CameraSupport.java',
    'FrameSeriesProbeActivity.java',
    'FixtureActivity.java',
    'IsolationProbeService.java',
    'LegacyProbeActivity.java',
    'NdkProbeActivity.java',
    'PrivacyProbeActivity.java',
    'ProbeIo.java',
    'RecorderProbeActivity.java',
    'ReplayProbeActivity.java',
    'UpdateProbeActivity.java',
  )
]

REQUIRED = [
  'README.md', 'README_CN.md', 'RUNBOOK.md', 'doctor.json', 'manifest.json',
  'docs/remote-service.md',
  'bin/xenoid', 'bin/xenoid-mcp', 'bin/xenoid-service',
  'src/xenoid/__init__.py', 'src/xenoid/cli.py', 'src/xenoid/backend.py',
  'src/xenoid/config.py', 'src/xenoid/storage.py', 'src/xenoid/device_identity.py',
  'src/xenoid/util.py', 'src/xenoid/daemon_client.py',
  'src/xenoid/proxy_controller.py', 'src/xenoid/proxy_protocol.py',
  'src/xenoid/proxy_source.py', 'src/xenoid/mcp_server.py',
  'src/xenoid/remote_service.py', 'src/xenoid/operation_lock.py',
  'src/xenoid/doctor.py', 'scripts/xenoid-up.sh',
  'src/xenoid/google_services.py',
  'scripts/make-runtime-context.sh', 'scripts/make-rootfs-image.sh',
  'scripts/patch-services-runtime.py', 'scripts/redroid-preflight.sh',
  'scripts/build-kmod.sh', 'scripts/build-ebpf.sh', 'scripts/load-ebpf.sh',
  'scripts/with-shared-protection-lock.py', 'scripts/with-up-lock.py',
  'examples/fingerprints/pixel-raven-android13.json', 'examples/hide/default-policy.json',
  'scripts/build-proxy-sandbox.sh', 'scripts/xenoid-proxy-engine.py',
  'scripts/xenoid-proxy-agent.py', 'scripts/xenoid-proxy-compile-worker.py',
  'scripts/xenoid-proxy-fetch-worker.py',
  'scripts/xenoid-proxy-agent@.service', 'scripts/proxy-engine-assets.json',
  'scripts/xenoid-proxy-sandbox',
  'daemon/app/build/outputs/apk/debug/app-debug.apk',
  'native/xenoid-input/xenoid-input', 'native/xenoid-hide/xenoid-hide',
  'native/xenoid-hide/xenoid-overlay', 'native/xenoid-hide/xenoid-prop-area',
  'native/xenoid-hide/xenoid-ssaid', 'native/xenoid-profile/xenoid-profile',
  'native/xenoid-netctl/xenoid-netctl', 'native/xenoid-rootd/xenoid-rootd-arm64',
  'native/xenoid-zygote/libxenoid_zygote.so',
  'native/xenoid-shim/libxenoid_shim-arm64.so',
  'native/xenoid-pivot/xenoid-pivot',
  'native/xenoid-sensorshal/xenoid-sensorshal',
  'native/xenoid-sensorshal/android.hardware.sensors.ISensors.xml',
  'native/xenoid-proxy-sandbox/Makefile',
  'native/xenoid-proxy-sandbox/xenoid_proxy_sandbox.c',
  'native/xenoid-proxy-sandbox/xenoid-proxy-sandbox',
  *GENERIC_CAMERA_PATHS[:3],
  'artifacts/xenoid-daemon.apk', 'artifacts/xenoid-input',
  'artifacts/xenoid-hide-helper', 'artifacts/xenoid-profile-helper',
  'artifacts/xenoid-netctl', 'artifacts/xenoid-rootd-arm64',
  'artifacts/libxenoid_zygote.so', 'artifacts/libxenoid_shim-arm64.so',
  'artifacts/xenoid-pivot', 'artifacts/xenoid-sensorshal',
  'artifacts/android.hardware.sensors.ISensors.xml',
  *GENERIC_CAMERA_PATHS[3:],
  'artifacts/xenoid-overlay-helper', 'artifacts/xenoid-prop-area',
  'artifacts/xenoid-ssaid', 'config/config-macos-colima.json',
  'artifacts/xenoid-proxy-sandbox',
  'config/config-linux-arm.json',
  'skills/xenoid/SKILL.md',
  'scripts/smoke-camera-runtime.sh',
  'scripts/smoke-filesystem-runtime.sh',
  'tests/filesystem-runtime-probe/AndroidManifest.xml',
  'tests/filesystem-runtime-probe/build.sh',
  'tests/filesystem-runtime-probe/native/filesystem_probe.cpp',
  'tests/filesystem-runtime-probe/java/org/example/filesystemruntimeprobe/ProbeActivity.java',
  'tests/filesystem-runtime-probe/java/org/example/filesystemruntimeprobe/IsolationProbeService.java',
  'scripts/smoke-persistence-runtime.sh',
  'tests/persistence-runtime-probe/AndroidManifest.xml',
  'tests/persistence-runtime-probe/build.sh',
  'tests/persistence-runtime-probe/java/org/example/persistenceruntimeprobe/ProbeActivity.java',
  'scripts/smoke-google-services-runtime.sh',
  'scripts/smoke-google-services-convergence.sh',
  'scripts/test-google-services.py',
  'tests/google-services-runtime-probe/AndroidManifest.xml',
  'tests/google-services-runtime-probe/build.sh',
  'tests/google-services-runtime-probe/java/org/example/googleservicesruntimeprobe/ProbeActivity.java',
  'tests/camera-runtime-probe/AndroidManifest.xml',
  'tests/camera-runtime-probe/build.sh',
  'tests/camera-runtime-probe/native/ndk_probe.cpp',
  *CAMERA_HARNESS_JAVA_PATHS,
  'daemon/app/src/main/java/dev/xenoid/daemon/ProxyManager.java',
  'daemon/app/src/main/java/dev/xenoid/daemon/ProxyAgentChannel.java',
  'daemon/app/src/main/java/dev/xenoid/daemon/LocationIdentityManager.java',
  'src/xenoid/location.py', 'src/xenoid/cellular.py',
  'data/cellular/provenance.json', 'data/cellular/carriers.json',
  'data/cellular/LICENSES.txt',
  'scripts/build-ril.sh', 'scripts/build-radio-config.sh',
  'scripts/test-cellular-profile.py',
  'scripts/test-ril-source.py', 'scripts/smoke-cellular-runtime.sh',
  'scripts/patch-telephony-legacy-lte-band.py',
  'scripts/smoke-hardware-features.py',
  'native/xenoid-ril/xenoid_ril.c',
  'native/xenoid-ril/include/telephony/ril.h',
  'native/xenoid-ril/android.hardware.radio.IRadio.xml',
  'native/xenoid-ril/libxenoid-ril.so',
  'native/xenoid-radio-config/radio_config.cpp',
  'native/xenoid-radio-config/framework-min.aidl',
  'native/xenoid-radio-config/android.hardware.radio.config.IRadioConfig.xml',
  'native/xenoid-radio-config/android.hardware.radio.config-service.xenoid',
  'runtime/redroid/xenoid-cellular-overlay/system/etc/apns-conf.xml',
  'runtime/redroid/xenoid-cellular-overlay/system/etc/permissions/xenoid-cellular-features.xml',
  'runtime/redroid/xenoid-cellular-overlay/system/etc/permissions/privapp-permissions-xenoid.xml',
  'runtime/redroid/xenoid-hardware-features.xml',
  'tests/cellular-runtime-probe/AndroidManifest.xml',
  'tests/cellular-runtime-probe/build.sh',
  'tests/cellular-runtime-probe/native/net_probe.cpp',
  'tests/cellular-runtime-probe/java/org/example/cellularruntimeprobe/ProbeActivity.java',
  'tests/cellular-runtime-probe/java/org/example/cellularruntimeprobe/IsolationProbeService.java',
  'skills/xenoid-development/SKILL.md',
  'scripts/test-remote-service.py',
  'scripts/test-mcp-contract.py',
  'artifacts/libxenoid-ril.so',
  'artifacts/android.hardware.radio.config-service.xenoid',
  'data/google-services/mindthegapps-13.0.0-arm64-20231025_200931.json',
]
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('archive'); args=ap.parse_args()
    archive=pathlib.Path(args.archive).resolve()
    out={'ok': False, 'archive': str(archive), 'checks': []}
    if not archive.exists():
        out['error']='archive not found'; print(json.dumps(out,indent=2)); return 1
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        with tarfile.open(archive,'r:gz') as tf:
            if any(member.issym() or member.islnk() for member in tf.getmembers()):
                out['error']='archive links are not allowed'
                print(json.dumps(out, indent=2))
                return 1
            for member in tf.getmembers():
                target = (td / member.name).resolve()
                if pathlib.Path(target).is_relative_to(td.resolve()) is False:
                    out['error'] = f'unsafe archive member: {member.name}'
                    print(json.dumps(out, indent=2))
                    return 1
            kwargs = {"filter": "data"} if "filter" in inspect.signature(tf.extractall).parameters else {}
            tf.extractall(td, **kwargs)
        roots=[p for p in td.iterdir() if p.is_dir()]
        if len(roots) != 1:
            out['error']=f'expected one root dir, found {len(roots)}'; print(json.dumps(out,indent=2)); return 1
        root=roots[0]
        manifest_path=root/'manifest.json'
        if not manifest_path.exists():
            out['error']='manifest missing'; print(json.dumps(out,indent=2)); return 1
        manifest=json.loads(manifest_path.read_text())
        entries=manifest.get('files', [])
        if not isinstance(entries, list) or any(not isinstance(f, dict) or not isinstance(f.get('path'), str) for f in entries):
            out['error']='invalid manifest file list'; print(json.dumps(out,indent=2)); return 1
        files={f['path']: f for f in entries}
        if len(files) != len(entries):
            out['error']='duplicate manifest paths'; print(json.dumps(out,indent=2)); return 1
        for rel in files:
            rel_path=pathlib.Path(rel)
            if rel_path.is_absolute() or '..' in rel_path.parts:
                out['checks'].append({'name':'safe-manifest-path:'+rel,'ok':False,'detail':rel})
        for req in REQUIRED:
            p=root/req
            listed=req == 'manifest.json' or req in files
            ok=p.is_file() and listed
            out['checks'].append({'name':'required:'+req,'ok':ok,'detail':str(p),'listed':listed})
        for rel in ('bin/xenoid', 'bin/xenoid-mcp', 'bin/xenoid-service'):
            executable = root / rel
            out['checks'].append({
                'name': 'executable:' + rel,
                'ok': executable.is_file() and bool(executable.stat().st_mode & 0o111),
                'detail': str(executable),
            })
        sandbox = root/'native/xenoid-proxy-sandbox/xenoid-proxy-sandbox'
        try:
            sandbox_data = sandbox.read_bytes()
            sandbox_mode = sandbox.stat().st_mode
        except OSError:
            sandbox_data = b''
            sandbox_mode = 0
        program_offset = int.from_bytes(sandbox_data[32:40], 'little')
        program_size = int.from_bytes(sandbox_data[54:56], 'little')
        program_count = int.from_bytes(sandbox_data[56:58], 'little')
        sandbox_static = (
            len(sandbox_data) >= 64
            and program_size >= 4
            and program_offset + program_size * program_count <= len(sandbox_data)
            and all(
                int.from_bytes(
                    sandbox_data[
                        program_offset + index * program_size:
                        program_offset + index * program_size + 4
                    ],
                    'little',
                ) != 3
                for index in range(program_count)
            )
        )
        sandbox_linux_arm64 = (
            len(sandbox_data) >= 64
            and sandbox_data[:6] == b'\x7fELF\x02\x01'
            and int.from_bytes(sandbox_data[18:20], 'little') == 183
            and sandbox_static
            and b'/system/bin/linker64' not in sandbox_data
            and bool(sandbox_mode & 0o111)
        )
        out['checks'].append({
            'name':'linux-arm64-proxy-sandbox',
            'ok':sandbox_linux_arm64,
            'detail':str(sandbox),
        })
        artifact_sandbox = root/'artifacts/xenoid-proxy-sandbox'
        staged_sandbox = root/'scripts/xenoid-proxy-sandbox'
        out['checks'].append({
            'name':'proxy-sandbox-artifact-match',
            'ok':artifact_sandbox.is_file()
                 and staged_sandbox.is_file()
                 and sandbox.is_file()
                 and sha(artifact_sandbox) == sha(sandbox)
                 and sha(staged_sandbox) == sha(sandbox),
            'detail':str(artifact_sandbox),
        })
        runtime_context_path = root/'scripts/make-runtime-context.sh'
        try:
            runtime_context = runtime_context_path.read_text()
        except OSError:
            runtime_context = ''
        generic_runtime_paths = (
            all(token in runtime_context for token in GENERIC_RUNTIME_CAMERA_TOKENS)
            and not any(
                token in runtime_context
                for token in RETIRED_RUNTIME_CAMERA_TOKENS
            )
        )
        out['checks'].append({
            'name':'generic-camera-runtime-paths',
            'ok':generic_runtime_paths,
            'detail':str(runtime_context_path),
        })
        harness_java_sources = sorted(
            rel for rel in files
            if rel.startswith(CAMERA_HARNESS_JAVA_PREFIX) and rel.endswith('.java')
        )
        out['checks'].append({
            'name':'camera-runtime-harness-java-sources',
            'ok':bool(harness_java_sources)
                 and all((root/rel).is_file() for rel in harness_java_sources),
            'detail':harness_java_sources,
        })
        for rel, meta in files.items():
            if rel == "manifest.json":
                continue
            p=root/rel
            ok=p.exists() and sha(p)==meta.get('sha256') and p.stat().st_size==meta.get('size')
            if not ok or rel in REQUIRED:
                out['checks'].append({'name':'sha:'+rel,'ok':ok,'detail':str(p)})
        archive_files={
            p.relative_to(root).as_posix()
            for p in root.rglob('*')
            if p.is_file() and p.name != 'manifest.json'
        }
        sys.path.insert(0, str(root/'src'))
        from xenoid.google_services import registered_metadata_files
        registered_google = registered_metadata_files()
        for rel, expected_sha256 in sorted(registered_google.items()):
            p = root/rel
            metadata_ok = (
                rel in files
                and p.is_file()
                and sha(p) == expected_sha256
                and files[rel].get('sha256') == expected_sha256
            )
            out['checks'].append({
                'name':'google-release-metadata:'+rel,
                'ok':metadata_ok,
                'detail':rel,
            })
        proprietary_paths = sorted(
            rel for rel in set(files) | archive_files
            if rel.startswith('.xenoid/')
            or pathlib.PurePosixPath(rel).suffix.lower() in {'.zip', '.pem'}
            or (
                rel.startswith('data/google-services/')
                and rel not in registered_google
            )
        )
        out['checks'].append({
            'name':'google-proprietary-payload-excluded',
            'ok':not proprietary_paths,
            'detail':proprietary_paths,
        })
        retired_camera_paths = sorted(
            rel for rel in set(files) | archive_files
            if pathlib.PurePosixPath(rel).name in RETIRED_CAMERA_BASENAMES
        )
        out['checks'].append({
            'name':'retired-camera-artifact-aliases',
            'ok':not retired_camera_paths,
            'detail':retired_camera_paths,
        })
        for rel in sorted(archive_files - set(files)):
            out['checks'].append({'name':'unlisted:'+rel,'ok':False,'detail':str(root/rel)})
        out['schema']=manifest.get('schema')
        out['fileCount']=len(files)
        out['ok']=all(c['ok'] for c in out['checks']) and out['schema']=='dev.xenoid.release/v1'
    print(json.dumps(out, indent=2))
    return 0 if out['ok'] else 2
if __name__=='__main__': sys.exit(main())
