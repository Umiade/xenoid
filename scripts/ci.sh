#!/usr/bin/env bash
# Xenoid CI gate. Aggregates the repo's validation into tiers so a CI runner (or a
# developer) gets one command with a clear pass/fail.
#
#   scripts/ci.sh             static tier only (no Android runtime needed; fast)
#   scripts/ci.sh --runtime   static tier + unified full doctor
#   scripts/ci.sh --full      runtime tier + heavyweight audit-goal
#
# Exit 0 only if every run check passes. Individual failures are listed at the end.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/xenoid-pycache}"

TIER=static
[[ "${1:-}" == "--runtime" ]] && TIER=runtime
[[ "${1:-}" == "--full" ]] && TIER=full

# Portable timeout: macOS lacks GNU `timeout`; use it when present, else run directly
# (the static smokes are fast and well-behaved, so a missing timeout is safe).
TIMEOUT_BIN=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN=timeout
[[ -z "$TIMEOUT_BIN" ]] && command -v gtimeout >/dev/null 2>&1 && TIMEOUT_BIN=gtimeout
with_timeout() { local secs="$1"; shift; if [[ -n "$TIMEOUT_BIN" ]]; then "$TIMEOUT_BIN" "$secs" "$@"; else "$@"; fi }

pass=(); fail=()
run_py() { # run_py <script.py> [args...]
  local name="$1"; shift
  if with_timeout 120 python3 "scripts/$name" "$@" >/tmp/ci-$name.out 2>&1; then pass+=("$name"); else fail+=("$name (rc=$?)"); fi
}
run_sh() { # run_sh <script.sh> [args...]
  local name="$1"; shift
  if with_timeout 120 bash "scripts/$name" "$@" >/tmp/ci-$name.out 2>&1; then pass+=("$name"); else fail+=("$name (rc=$?)"); fi
}
run_cmd() { # run_cmd <label> <cmd...>
  local label="$1"; shift
  if with_timeout 180 "$@" >/tmp/ci-label.out 2>&1; then pass+=("$label"); else fail+=("$label (rc=$?)"); fi
}

echo "[ci] tier=$TIER"

# --- Static tier: compile + MCP surface + source-level smokes (no runtime) ---
echo "[ci] static: python compile"
run_cmd "compileall-src" python3 -m compileall -q src
echo "[ci] static: prospective sensitive-content audit"
run_py audit-sensitive-data.py
echo "[ci] static: instance identity and lease contracts"
run_py test-proxy.py
echo "[ci] static: instance storage and lifecycle contracts"
run_py test-instance-storage.py
echo "[ci] static: pinned Google runtime contracts"
run_py test-google-services.py
echo "[ci] static: proxy compiler and authenticated control contracts"
run_py test-proxy-compiler.py

CI_INSTANCE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/xenoid-ci-instance.XXXXXX")"
trap 'rm -rf "$CI_INSTANCE_ROOT"' EXIT
CI_INSTANCE_PROJECT="$CI_INSTANCE_ROOT/project"
CI_INSTANCE_HOME="$CI_INSTANCE_ROOT/home"
mkdir -p "$CI_INSTANCE_PROJECT/src/xenoid" "$CI_INSTANCE_HOME"
env HOME="$CI_INSTANCE_HOME" XENOID_PROJECT="$CI_INSTANCE_PROJECT" \
  ./xenoid --instance verify init >/tmp/ci-instance-init.json 2>&1
echo "[ci] static: MCP tool surface"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | env HOME="$CI_INSTANCE_HOME" XENOID_PROJECT="$CI_INSTANCE_PROJECT" \
      XENOID_INSTANCE=verify ./xenoid-mcp >/tmp/ci-mcp.jsonl 2>&1
if python3 - <<'PY'
import json,sys
lines=[json.loads(x) for x in open('/tmp/ci-mcp.jsonl') if x.strip()]
tools={t['name'] for t in lines[1]['result']['tools']}
need={'xenoid_doctor','xenoid_start','xenoid_up_plan','xenoid_device_apply','xenoid_hide_apply','xenoid_ebpf_status','xenoid_frida_load_script','xenoid_verify_release'}
need.add('xenoid_frida_install')
need.update({'xenoid_proxy_status','xenoid_proxy_check','xenoid_proxy_on','xenoid_proxy_off','xenoid_proxy_clear','xenoid_proxy_select'})
need.update({'xenoid_location_list','xenoid_location_status','xenoid_location_set'})
need.update({'xenoid_google_services_status','xenoid_google_services_enable','xenoid_google_services_disable'})
missing=sorted(need-tools)
if missing: print('missing MCP tools: '+', '.join(missing)); sys.exit(1)
print(f'mcp tools ok ({len(tools)})')
PY
then pass+=("mcp-tools"); else fail+=("mcp-tools"); fi

# Static source-level smokes (token/contract gates, verified fast and runtime-free).
STATIC_SMOKES=(
  smoke-prop-area-rules.py
  smoke-profile-template.py
  smoke-netctl-source.py
  smoke-native-shim.py
  smoke-rootd-auth.py
  smoke-hook-surfaces.py
  smoke-frida-install.py
  smoke-install-runtime.py
  smoke-idstore-helper.py
  smoke-input-profile.py
  smoke-rtc-overlay.py
  smoke-network-overlay.py
  smoke-mount-namespace-overlay.py
  smoke-kernel-hardening-overlay.py
  smoke-cpu-proc-stats-overlay.py
  smoke-cpu-sysfs-overlay.py
  smoke-devicetree-overlay.py
  smoke-framebuffer-overlay.py
  smoke-kallsyms-tracing-overlay.py
  smoke-kernel-device-overlay.py
  smoke-kernel-proc-overlay.py
  smoke-memory-proc-overlay.py
  smoke-power-supply-overlay.py
  smoke-proc-identity-overlay.py
  smoke-random-sysctl-overlay.py
  smoke-selinux-overlay.py
  smoke-input-devices-overlay.py
)
echo "[ci] static: ${#STATIC_SMOKES[@]} source smokes"
for s in "${STATIC_SMOKES[@]}"; do [[ -f "scripts/$s" ]] && run_py "$s"; done
run_sh smoke-daemon-api.sh --mock

# --- Runtime tier: needs a booted xenoid-android container on adb ---
if [[ "$TIER" == "runtime" || "$TIER" == "full" ]]; then
  echo "[ci] runtime: unified doctor"
  if XENOID_SKIP_AUDIT=1 with_timeout 900 ./xenoid doctor --full --require-runtime --out /tmp/ci-doctor.json >/tmp/ci-doctor.out 2>&1; then
    pass+=("doctor-full")
  else
    fail+=("doctor-full (rc=$?)")
  fi
  echo "[ci] runtime: persistence probe"
  if with_timeout 900 ./scripts/smoke-persistence-runtime.sh >/tmp/ci-persistence-runtime.out 2>&1; then
    pass+=("persistence-runtime")
  else
    fail+=("persistence-runtime (rc=$?)")
  fi
  if ./xenoid config show 2>/dev/null \
    | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("config", {}).get("google_services_provider") != "none" else 1)'
  then
    echo "[ci] runtime: Google services reuse convergence"
    if with_timeout 1200 ./scripts/smoke-google-services-convergence.sh >/tmp/ci-google-convergence.out 2>&1; then
      pass+=("google-services-convergence")
    else
      fail+=("google-services-convergence (rc=$?)")
    fi
  fi
fi

# --- Full tier: configured camera replay plus heavyweight audit ---
if [[ "$TIER" == "full" ]]; then
  echo "[ci] full: source-generated camera replay"
  if with_timeout 900 ./scripts/smoke-camera-runtime.sh --full --loop-seconds 10 \
      --out /tmp/ci-camera-runtime.json >/tmp/ci-camera-runtime.out 2>&1; then
    pass+=("camera-runtime-full")
  else
    fail+=("camera-runtime-full (rc=$?)")
  fi
  echo "[ci] full: audit-goal (rebuilds; this is slow)"
  if XENOID_SKIP_AUDIT=1 with_timeout 900 python3 scripts/audit-goal.py >/tmp/ci-audit-goal.out 2>&1; then pass+=("audit-goal"); else fail+=("audit-goal (rc=$?)"); fi
fi

echo
echo "[ci] PASS ${#pass[@]}  FAIL ${#fail[@]}"
if [[ ${#fail[@]} -gt 0 ]]; then
  printf '[ci] failed: %s\n' "${fail[@]}"
  exit 1
fi
echo "[ci] all green"
