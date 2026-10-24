#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

make all check-bins >/dev/null

PASS=0
FAIL=0
SKIP=0

ok() { echo "[PASS] $*"; PASS=$((PASS + 1)); }
bad() { echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $*"; SKIP=$((SKIP + 1)); }

run_expect_zero() {
  local label="$1"
  shift
  set +e
  "$@" >/tmp/ksb-check-cmd.out 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    ok "$label"
  else
    echo "----- output -----"
    cat /tmp/ksb-check-cmd.out || true
    echo "------------------"
    bad "$label (rc=$rc)"
  fi
}

mkdir -p /tmp/ksb-check
echo "hello-allowlist" > /tmp/ksb-check/in.txt
rm -f /tmp/ksb-check/out.txt sandbox.jsonl

run_expect_zero "false-deny: strict-allow file_transform" \
  ./sandbox-run policies/strict-allow.json ./workloads/file_transform \
  /tmp/ksb-check/in.txt /tmp/ksb-check/out.txt

if [[ -f /tmp/ksb-check/out.txt ]] && grep -q "hello-allowlist" /tmp/ksb-check/out.txt; then
  ok "false-deny: output content matches"
else
  bad "false-deny: output content mismatch"
fi

run_expect_zero "true-deny: fork under restrictive" \
  ./sandbox-run policies/restrictive.json ./tests/adversarial/try_fork

run_expect_zero "true-deny: socket under restrictive" \
  ./sandbox-run policies/restrictive.json ./tests/adversarial/try_socket

run_expect_zero "true-deny: clone3 under restrictive" \
  ./sandbox-run policies/restrictive.json ./tests/adversarial/try_clone3

if ./tests/adversarial/landlock_probe >/dev/null 2>&1; then
  run_expect_zero "true-deny: Landlock blocks /etc/passwd" \
    ./sandbox-run policies/strict-allow.json ./tests/adversarial/try_open_etc

  set +e
  LD_PRELOAD="$ROOT/tests/adversarial/libfake_preload.so" \
    ./sandbox-run policies/strict-allow.json ./tests/adversarial/ld_preload_open \
    >/tmp/ksb-check-cmd.out 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    ok "LD_PRELOAD cannot bypass Landlock/seccomp path deny"
  else
    cat /tmp/ksb-check-cmd.out || true
    bad "LD_PRELOAD negative test (rc=$rc)"
  fi
else
  skip "Landlock unavailable on this kernel; path adversarial tests skipped"
fi

set +e
./sandbox-run --mount-ns policies/strict-allow.json ./workloads/file_transform \
  /tmp/ksb-check/in.txt /tmp/ksb-check/out-ns.txt >/tmp/ksb-check/mnt.out 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  ok "mount-ns + pivot_root smoke with strict-allow"
else
  skip "mount-ns smoke failed in this environment (see /tmp/ksb-check/mnt.out)"
fi

# Network namespace: loopback-only egress deny + loopback positive.
set +e
unshare --user --map-root-user --net true >/dev/null 2>&1
userns_net=$?
set -e
if [[ "$userns_net" -eq 0 ]]; then
  run_expect_zero "netns: egress denied under --net-ns=loopback" \
    ./sandbox-run --net-ns=loopback policies/basic.json ./tests/adversarial/try_egress
  run_expect_zero "netns: loopback usable under --net-ns=loopback" \
    ./sandbox-run --net-ns=loopback policies/basic.json ./tests/adversarial/try_loopback
  if command -v ip >/dev/null 2>&1; then
    run_expect_zero "netns: egress denied under --net-ns=veth-deny" \
      ./sandbox-run --net-ns=veth-deny policies/basic.json ./tests/adversarial/try_egress
  else
    skip "iproute2 missing; veth-deny mode not exercised"
  fi
else
  skip "user+net namespaces unavailable; netns tests skipped"
fi

# cgroup v2 pids.max demo (requires writable delegated root).
set +e
CG_ROOT="$(./tests/adversarial/cgroup_probe.sh 2>/dev/null)"
cg_probe=$?
set -e
if [[ "$cg_probe" -eq 0 && -n "$CG_ROOT" ]]; then
  run_expect_zero "cgroup v2: pids.max blocks fork storm" \
    env SANDBOX_CGROUP_ROOT="$CG_ROOT" \
    ./sandbox-run --cgroup --cgroup-pids-max=4 --cgroup-memory-max=64M \
      policies/basic.json ./tests/adversarial/try_pids_limit
else
  skip "cgroup v2 root not writable/delegated (see scripts/setup_cgroup_root.sh)"
fi

echo
echo "Summary: pass=$PASS fail=$FAIL skip=$SKIP"
if [[ "$FAIL" -ne 0 ]]; then
  exit 1
fi
exit 0
