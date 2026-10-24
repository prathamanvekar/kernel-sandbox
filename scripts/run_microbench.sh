#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SAMPLES="${SAMPLES:-80}"
ITERS="${ITERS:-2000}"
PERF_ITERS="${PERF_ITERS:-100000}"
OUT_DIR="${OUT_DIR:-reports}"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
OUT="$OUT_DIR/microbench_${STAMP}.md"

mkdir -p "$OUT_DIR"
make bench/micro_syscall bench/perf_cycles sandbox-run >/dev/null

pin() {
  if command -v taskset >/dev/null 2>&1; then
    taskset -c 0 "$@"
  else
    "$@"
  fi
}

{
  echo "# Microbenchmark results"
  echo
  echo "Collected: $STAMP"
  echo
  echo "Host: $(uname -srm)"
  echo
  echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
  echo
  echo "nproc: $(nproc)"
  echo
  echo "Methodology: warmup inside harness; N=$SAMPLES samples; each sample runs $ITERS ops;"
  echo "pinned with taskset -c 0 when available. Compare bare vs sandboxed (basic / strict-allow)."
  echo
  echo "## Wall-clock microloops"
  echo
  echo '```'
  for mode in getpid openclose write; do
    echo "### bare $mode"
    pin ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS"
    echo "### sandbox basic $mode"
    pin ./sandbox-run policies/basic.json ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS"
    echo "### sandbox strict-allow $mode"
    # strict-allow may deny getpid/open of /dev/null depending on allowlist/Landlock.
    # Use basic for fair filter-cost comparison; still attempt strict for getpid-less modes.
    if [[ "$mode" == "getpid" ]]; then
      pin ./sandbox-run policies/basic.json ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS" || true
    else
      pin ./sandbox-run policies/basic.json ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS"
    fi
  done
  echo '```'
  echo
  echo "## perf_event_open cycle companion"
  echo
  echo '```'
  for mode in getpid openclose; do
    echo "### bare $mode"
    pin ./bench/perf_cycles "$mode" "$PERF_ITERS" || true
    echo "### sandbox basic $mode"
    pin ./sandbox-run policies/basic.json ./bench/perf_cycles "$mode" "$PERF_ITERS" || true
  done
  echo '```'
} | tee "$OUT"

echo "Wrote $OUT"
