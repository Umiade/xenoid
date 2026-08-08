#!/usr/bin/env bash
set -euo pipefail
DOCKER="${DOCKER:-}"
if [[ -z "$DOCKER" ]]; then
  if command -v docker >/dev/null 2>&1; then DOCKER=docker; elif [[ -x /Applications/Docker.app/Contents/Resources/bin/docker ]]; then DOCKER=/Applications/Docker.app/Contents/Resources/bin/docker; else echo '{"ok":false,"error":"docker not found"}'; exit 2; fi
fi
NAME=xenoid-probe-redroid
$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
set +e
$DOCKER run --privileged --name "$NAME" redroid/redroid:13.0.0_64only-latest androidboot.use_memfd=true >/tmp/xenoid-probe-redroid.out 2>/tmp/xenoid-probe-redroid.err
RC=$?
set -e
STATE="{}"
if $DOCKER inspect "$NAME" >/tmp/xenoid-probe-redroid-inspect.json 2>/dev/null; then STATE=$(python3 - <<'PY'
import json
j=json.load(open('/tmp/xenoid-probe-redroid-inspect.json'))
print(json.dumps(j[0].get('State',{})))
PY
); fi
$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
python3 - <<PY
import json
print(json.dumps({'ok': $RC == 0, 'returncode': $RC, 'stdout': open('/tmp/xenoid-probe-redroid.out').read(), 'stderr': open('/tmp/xenoid-probe-redroid.err').read(), 'state': json.loads('''$STATE''')}))
PY
exit 0
