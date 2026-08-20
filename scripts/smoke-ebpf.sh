#!/usr/bin/env bash
# Fresh observational protection proof through the configured RuntimeManager.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--verify-loaded" ) ]]; then
  echo '{"ok":false,"error":"shared_protection_command_invalid"}'
  exit 2
fi
exec "$ROOT/xenoid" ebpf smoke
