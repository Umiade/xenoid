#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 -m compileall src
python3 scripts/test-proxy.py >/tmp/xenoid-test-proxy.json
python3 scripts/test-cellular-profile.py
python3 scripts/test-ril-source.py
python3 scripts/test-google-services.py
python3 scripts/test-proxy-control.py
python3 scripts/test-proxy-compiler.py >/tmp/xenoid-test-proxy-compiler.json
python3 scripts/audit-sensitive-data.py
./xenoid --help >/tmp/xenoid-help.txt
./xenoid google-services --help >/tmp/xenoid-google-services-help.txt
tests/google-services-runtime-probe/build.sh >/tmp/xenoid-google-services-probe-build.txt
VERIFY_INSTANCE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-verify-instance.XXXXXX")"
trap 'rm -rf "$VERIFY_INSTANCE_ROOT"' EXIT
VERIFY_INSTANCE_PROJECT="$VERIFY_INSTANCE_ROOT/project"
VERIFY_INSTANCE_HOME="$VERIFY_INSTANCE_ROOT/home"
mkdir -p "$VERIFY_INSTANCE_PROJECT/src/xenoid" "$VERIFY_INSTANCE_HOME"
env HOME="$VERIFY_INSTANCE_HOME" XENOID_PROJECT="$VERIFY_INSTANCE_PROJECT" \
  ./xenoid --instance verify init >/tmp/xenoid-verify-init.json
env HOME="$VERIFY_INSTANCE_HOME" XENOID_PROJECT="$VERIFY_INSTANCE_PROJECT" \
  ./xenoid --instance verify start --dry-run --skip-preflight >/tmp/xenoid-start-dry-run.json
./xenoid frida install --help >/tmp/xenoid-frida-install-help.txt
scripts/smoke-daemon-api.sh --mock >/tmp/xenoid-smoke-daemon-mock.json
./xenoid hide --help >/tmp/xenoid-hide-help.txt
./xenoid doctor --help >/tmp/xenoid-doctor-help.txt
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"xenoid_start","arguments":{"dryRun":true}}}' \
  | env HOME="$VERIFY_INSTANCE_HOME" XENOID_PROJECT="$VERIFY_INSTANCE_PROJECT" \
      XENOID_INSTANCE=verify ./xenoid-mcp >/tmp/xenoid-mcp-verify.jsonl
python3 - <<'PY'
import json
lines=[json.loads(x) for x in open('/tmp/xenoid-mcp-verify.jsonl') if x.strip()]
tools={t['name'] for t in lines[1]['result']['tools']}
required={'xenoid_doctor','xenoid_start','xenoid_install_runtime_plan','xenoid_up_plan','xenoid_logs','xenoid_view','xenoid_verify_release','xenoid_package_release','xenoid_ebpf_build','xenoid_ebpf_load','xenoid_ebpf_status','xenoid_profile_deploy_helper','xenoid_profile_helper_status','xenoid_linux_binderfs','xenoid_runtime_build_image','xenoid_config_show','xenoid_frida_fetch','xenoid_frida_deploy_scripts','xenoid_frida_load_script','xenoid_input_tap','xenoid_hide_apply','xenoid_device_apply','xenoid_device_generate_frida','xenoid_device_generate_service_frida','xenoid_automation_plan','xenoid_automation_run_host','xenoid_automation_run','xenoid_netctl_deploy','xenoid_netctl_status','xenoid_netctl_set_mac','xenoid_location_list','xenoid_location_status','xenoid_location_set'}
required.add('xenoid_frida_install')
required.update({'xenoid_google_services_status','xenoid_google_services_enable','xenoid_google_services_disable'})
missing=sorted(required-tools)
if missing:
    raise SystemExit('missing MCP tools: '+', '.join(missing))
print('verify ok; tools=', len(tools))
PY

if [[ "${XENOID_SKIP_AUDIT:-0}" != "1" ]]; then
  XENOID_SKIP_AUDIT=1 python3 scripts/audit-goal.py >/tmp/xenoid-goal-audit.json
python3 - <<'PY'
import json
data=json.load(open('/tmp/xenoid-goal-audit.json'))
assert data['ok'], 'goal audit failed'
print('goal audit ok; checks=', len(data['checks']))
PY
fi
