#!/usr/bin/env bash
# Exit 0 if a writable cgroup v2 root with controllers is available.
set -euo pipefail

ROOT="${SANDBOX_CGROUP_ROOT:-/sys/fs/cgroup/ksb.sandbox}"
if [[ ! -d "$ROOT" ]]; then
  exit 1
fi
PROBE="$ROOT/.probe-$$"
if ! mkdir "$PROBE" 2>/dev/null; then
  exit 1
fi
# Controllers must be delegated to children via parent's subtree_control.
if [[ ! -f "$PROBE/memory.max" && ! -f "$PROBE/pids.max" ]]; then
  rmdir "$PROBE" 2>/dev/null || true
  exit 1
fi
rmdir "$PROBE"
echo "$ROOT"
exit 0
