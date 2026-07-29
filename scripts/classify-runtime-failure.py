#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, sys
ap=argparse.ArgumentParser(); ap.add_argument('json_file'); args=ap.parse_args()
data=json.loads(pathlib.Path(args.json_file).read_text())
checks={c.get('name'): c for c in data.get('checks', [])}
failed=[k for k,v in checks.items() if not v.get('ok')]
category='ok' if data.get('ok') else 'unknown'
actions=[]
if 'boot_completed' in failed:
    detail=checks['boot_completed'].get('detail','')
    if 'not found' in detail or 'Connection refused' in json.dumps(data):
        category='android-not-booted'
        actions+=['./xenoid doctor','./xenoid up','docker ps | grep xenoid-android']
if 'daemon_health' in failed:
    if category=='unknown': category='daemon-down'
    actions+=['./xenoid daemon start','adb forward tcp:18765 tcp:18765','./xenoid daemon health']
if 'root_status' in failed and 'daemon_health' not in failed:
    category='root-unavailable'; actions+=['adb root','./xenoid root status']
if 'frida_status' in failed and 'daemon_health' not in failed:
    actions+=['./xenoid frida install','./xenoid frida start']
if 'input_tap' in failed and 'daemon_health' not in failed:
    actions+=['./xenoid input deploy native/xenoid-input/xenoid-input']
if 'profile_status' in failed and 'daemon_health' not in failed:
    actions+=['./xenoid profile deploy-helper native/xenoid-profile/xenoid-profile']
if not actions and not data.get('ok'):
    actions=['./xenoid doctor --full --require-runtime']
out={'ok': data.get('ok') is True, 'category': category, 'failedChecks': failed, 'nextActions': list(dict.fromkeys(actions))}
print(json.dumps(out, indent=2))
sys.exit(0 if out['ok'] else 2)
