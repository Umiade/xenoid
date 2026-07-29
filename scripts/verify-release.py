#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, inspect, json, pathlib, tarfile, tempfile, sys
REQUIRED = [
  'README.md', 'README_CN.md', 'RUNBOOK.md', 'doctor.json', 'manifest.json',
  'bin/xenoid', 'bin/xenoid-mcp',
  'src/xenoid/__init__.py', 'src/xenoid/cli.py', 'src/xenoid/backend.py',
  'src/xenoid/config.py', 'src/xenoid/util.py', 'src/xenoid/daemon_client.py',
  'src/xenoid/doctor.py', 'scripts/xenoid-up.sh',
  'scripts/make-runtime-context.sh', 'scripts/make-rootfs-image.sh',
  'scripts/redroid-preflight.sh', 'scripts/build-kmod.sh',
  'scripts/build-ebpf.sh', 'scripts/load-ebpf.sh',
  'examples/fingerprints/sample-profile.json', 'examples/hide/default-policy.json',
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
  'native/xenoid-camerahal/xenoid-camerahal',
  'native/xenoid-camerahal/android.hardware.camera.provider.ICameraProvider.xml',
  'artifacts/xenoid-daemon.apk', 'artifacts/xenoid-input',
  'artifacts/xenoid-hide-helper', 'artifacts/xenoid-profile-helper',
  'artifacts/xenoid-netctl', 'artifacts/xenoid-rootd-arm64',
  'artifacts/libxenoid_zygote.so', 'artifacts/libxenoid_shim-arm64.so',
  'artifacts/xenoid-pivot', 'artifacts/xenoid-sensorshal',
  'artifacts/android.hardware.sensors.ISensors.xml',
  'artifacts/xenoid-camerahal',
  'artifacts/android.hardware.camera.provider.ICameraProvider.xml',
  'artifacts/xenoid-overlay-helper', 'artifacts/xenoid-prop-area',
  'artifacts/xenoid-ssaid', 'config/config-macos-colima.json',
  'config/config-linux-arm.json', 'config/docker-compose.yml',
  'skills/xenoid/SKILL.md',
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
        for rel in sorted(archive_files - set(files)):
            out['checks'].append({'name':'unlisted:'+rel,'ok':False,'detail':str(root/rel)})
        out['schema']=manifest.get('schema')
        out['fileCount']=len(files)
        out['ok']=all(c['ok'] for c in out['checks']) and out['schema']=='dev.xenoid.release/v1'
    print(json.dumps(out, indent=2))
    return 0 if out['ok'] else 2
if __name__=='__main__': sys.exit(main())
