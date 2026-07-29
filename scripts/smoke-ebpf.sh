#!/usr/bin/env bash
# Smoke: build + load + status JSON on Colima/Linux; optionally prove deny for uid>=10000.
set -euo pipefail
VERIFY_LOADED=0
[[ "${1:-}" == "--verify-loaded" ]] && VERIFY_LOADED=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" == "Darwin" ]]; then
  MODE_ARGS=(--colima)
else
  MODE_ARGS=(--local)
fi

build_out="skipped"
load_out="skipped"
if [[ "$VERIFY_LOADED" == 0 ]]; then
  build_out="$("$ROOT/scripts/build-ebpf.sh" "${MODE_ARGS[@]}" 2>&1)" || true
  echo "$build_out" | tail -1 | grep -q '"ok":true' || {
    python3 -c 'import json,sys; print(json.dumps({"ok":False,"stage":"build","output":sys.stdin.read()[-1000:]}))' <<<"$build_out"
    exit 1
  }
  load_out="$("$ROOT/scripts/load-ebpf.sh" "${MODE_ARGS[@]}" load 2>&1)" || true
fi
status_out="$("$ROOT/scripts/load-ebpf.sh" "${MODE_ARGS[@]}" status 2>&1)" || true
status_json="$(echo "$status_out" | tail -1)"
echo "$status_json" | grep -q '"ok":true' || {
  python3 -c 'import json,sys; print(json.dumps({"ok":False,"stage":"status","load":sys.argv[1],"status":sys.argv[2]}))' "$load_out" "$status_out"
  exit 1
}

deny_proof="skipped"
attach="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("attach",""))' "$status_json")"
loaded="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("loaded",False))' "$status_json")"

if [[ "$loaded" == "True" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    proof="$(colima ssh -- bash -s <<'EOS' || true
set +e
marker=/tmp/xenoid-ebpf-frida-marker
rm -rf "$marker"
mkdir -p "$marker"
echo hi > "$marker/x"
id -u nobody >/dev/null 2>&1 || { echo DENY_UNSUPPORTED; exit; }
if sudo -u nobody cat "$marker/x" >/dev/null 2>&1; then
  echo DENY_FAIL
else
  echo DENY_OK
fi
cat "$marker/x" >/dev/null
EOS
)"
  else
    proof="$(bash -s <<'EOS' || true
set +e
marker=/tmp/xenoid-ebpf-frida-marker
rm -rf "$marker"
mkdir -p "$marker"
echo hi > "$marker/x"
id -u nobody >/dev/null 2>&1 || { echo DENY_UNSUPPORTED; exit; }
if sudo -u nobody cat "$marker/x" >/dev/null 2>&1; then
  echo DENY_FAIL
else
  echo DENY_OK
fi
cat "$marker/x" >/dev/null
EOS
)"
  fi
  if echo "$proof" | grep -q DENY_OK; then
    deny_proof="ok"
  else
    deny_proof="failed_or_unsupported"
  fi
fi

if [[ "$deny_proof" == "ok" ]]; then
  python3 -c 'import json,sys; s=json.loads(sys.argv[1]); print(json.dumps({"ok":True,"stage":"smoke","buildOk":True,"status":s,"attach":sys.argv[2],"denyProof":sys.argv[3],"note":"system-layer eBPF path-hide behavior verified"}))' \
    "$status_json" "$attach" "$deny_proof"
else
  python3 -c 'import json,sys; s=json.loads(sys.argv[1]); print(json.dumps({"ok":False,"stage":"deny-proof","buildOk":True,"status":s,"attach":sys.argv[2],"denyProof":sys.argv[3],"error":"unprivileged hidden-path open was not denied"}))' \
    "$status_json" "$attach" "$deny_proof"
  exit 1
fi
