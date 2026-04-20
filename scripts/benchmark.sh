#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <policy.json> <program> [args...]"
  exit 1
fi

policy="$1"
shift
program="$1"
shift || true
args=("$@")

iterations="${BENCH_ITERATIONS:-5}"
if ! [[ "$iterations" =~ ^[0-9]+$ ]] || [[ "$iterations" -lt 1 ]]; then
  echo "BENCH_ITERATIONS must be a positive integer"
  exit 1
fi

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$workspace_dir"

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's@[^a-z0-9]+@-@g; s@^-+@@; s@-+$@@'
}

mkdir -p reports
timestamp_slug="$(date +%Y-%m-%d_%H-%M-%S)"
policy_slug="$(slugify "${policy##*/}")"
program_slug="$(slugify "${program##*/}")"
workload_label_raw="${WORKLOAD_LABEL:-ad-hoc}"
workload_label="$(slugify "$workload_label_raw")"
run_id="bench-${timestamp_slug}-${policy_slug}-${program_slug}-it${iterations}-wl-${workload_label}"
report_file="reports/report_benchmark_${timestamp_slug}_${policy_slug}_${program_slug}_it${iterations}_wl-${workload_label}.md"

measure_ms() {
  local -a cmd=("$@")
  local start_ns end_ns
  start_ns="$(date +%s%N)"
  "${cmd[@]}" >/dev/null 2>&1 || true
  end_ns="$(date +%s%N)"
  echo $(((end_ns - start_ns) / 1000000))
}

baseline_total=0
sandbox_total=0

for ((i=1; i<=iterations; i++)); do
  b_ms="$(measure_ms "$program" "${args[@]}")"
  s_ms="$(measure_ms ./sandbox-run "$policy" "$program" "${args[@]}")"
  baseline_total=$((baseline_total + b_ms))
  sandbox_total=$((sandbox_total + s_ms))
done

baseline_avg=$((baseline_total / iterations))
sandbox_avg=$((sandbox_total / iterations))
overhead_ms=$((sandbox_avg - baseline_avg))
if [[ "$baseline_avg" -gt 0 ]]; then
  overhead_pct=$(((overhead_ms * 100) / baseline_avg))
else
  overhead_pct=0
fi

{
  echo "# Sandbox Performance Benchmark"
  echo
  echo "- run_id: $run_id"
  echo "- iterations: $iterations"
  echo "- policy: $policy"
  echo "- program: $program"
  echo "- workload_label: ${workload_label_raw}"
  echo "- args: ${args[*]:-<none>}"
  echo "- baseline_avg_ms: $baseline_avg"
  echo "- sandbox_avg_ms: $sandbox_avg"
  echo "- overhead_ms: $overhead_ms"
  echo "- overhead_percent: $overhead_pct"
} > "$report_file"

echo "Benchmark report generated: $report_file"
