#!/usr/bin/env bash
# Create a writable cgroup v2 root for sandbox-run demos (needs root once).
set -euo pipefail
ROOT="${1:-/sys/fs/cgroup/ksb.sandbox}"
OWNER="${SUDO_USER:-$USER}"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run with sudo: sudo $0 $ROOT" >&2
  exit 1
fi
mkdir -p "$ROOT"
# Enable controllers for children of this root.
for c in memory cpu pids; do
  if grep -qw "$c" /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
    echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
  fi
done
echo '+memory +cpu +pids' > "$ROOT/cgroup.subtree_control" 2>/dev/null || \
  echo '+memory +pids' > "$ROOT/cgroup.subtree_control" 2>/dev/null || true
chown -R "$OWNER:$OWNER" "$ROOT"
echo "Ready: $ROOT (owner=$OWNER, subtree_control=$(cat "$ROOT/cgroup.subtree_control"))"
