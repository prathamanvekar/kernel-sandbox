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

if [[ ! -f "$policy" ]]; then
  echo "Policy not found: $policy"
  exit 1
fi

if [[ ! -x "$program" && "$program" != /* && "$program" != ./* ]]; then
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "Program not found/executable: $program"
    exit 1
  fi
fi

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$workspace_dir"

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's@[^a-z0-9]+@-@g; s@^-+@@; s@-+$@@'
}

log_file="$(sed -n 's/^[[:space:]]*"log_file"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' "$policy" | head -n 1)"
if [[ -z "$log_file" ]]; then
  log_file="sandbox.log"
fi

mkdir -p reports
timestamp_slug="$(date +%Y-%m-%d_%H-%M-%S)"
policy_slug="$(slugify "${policy##*/}")"
program_slug="$(slugify "${program##*/}")"
workload_label_raw="${WORKLOAD_LABEL:-ad-hoc}"
workload_label="$(slugify "$workload_label_raw")"
run_id="run-${timestamp_slug}-${policy_slug}-${program_slug}-wl-${workload_label}"
report_file="reports/report_run_${timestamp_slug}_${policy_slug}_${program_slug}_wl-${workload_label}.md"
start_epoch="$(date +%s)"
start_human="$(date '+%Y-%m-%d %H:%M:%S')"

{
  echo "[$start_human] REPORT_START run_id=$run_id policy=$policy program=$program args=$*"
} >> "$log_file"

stdout_tmp="$(mktemp)"
stderr_tmp="$(mktemp)"

set +e
./sandbox-run "$policy" "$program" "$@" >"$stdout_tmp" 2>"$stderr_tmp"
cmd_ec=$?
set -e

end_epoch="$(date +%s)"
end_human="$(date '+%Y-%m-%d %H:%M:%S')"
{
  echo "[$end_human] REPORT_END run_id=$run_id exit_code=$cmd_ec"
} >> "$log_file"

run_slice="$(awk -v id="$run_id" '
  index($0, "REPORT_START run_id=" id) { in_run=1 }
  in_run { print }
  index($0, "REPORT_END run_id=" id) { in_run=0 }
' "$log_file")"

kernel_lines=""
if dmesg --since "@$start_epoch" >/dev/null 2>&1; then
  kernel_lines="$(dmesg --since "@$start_epoch" 2>/dev/null | grep -Ei 'seccomp|audit:.*seccomp' || true)"
elif command -v journalctl >/dev/null 2>&1; then
  kernel_lines="$(journalctl -k --since "@$start_epoch" --no-pager 2>/dev/null | grep -Ei 'seccomp|audit:.*seccomp' || true)"
fi

child_pid="$(printf '%s\n' "$run_slice" | sed -n 's/.*Forked child pid=\([0-9]\+\).*/\1/p' | tail -n 1)"
if [[ -n "$child_pid" && -n "$kernel_lines" ]]; then
  kernel_lines="$(printf '%s\n' "$kernel_lines" | grep -E "pid=${child_pid}(\b| )|\[$child_pid\]" || true)"
fi

seccomp_events=0
if [[ -n "$kernel_lines" ]]; then
  seccomp_events="$(printf '%s\n' "$kernel_lines" | sed '/^$/d' | wc -l | tr -d ' ')"
fi

op_not_permitted_count="$( (grep -o "Operation not permitted" "$stdout_tmp" || true; grep -o "Operation not permitted" "$stderr_tmp" || true) 2>/dev/null | wc -l | tr -d ' ' )"
run_slice_denials="$(printf '%s\n' "$run_slice" | grep -Eoc 'errno=1|terminated by signal|Failed to install seccomp filter|execvp failed' || true)"
violations=$((seccomp_events + op_not_permitted_count + run_slice_denials))

{
  echo "# Sandbox Run Report"
  echo
  echo "- run_id: $run_id"
  echo "- policy: $policy"
  echo "- program: $program"
  echo "- workload_label: ${workload_label_raw}"
  echo "- args: ${*:-<none>}"
  echo "- start_time: $start_human"
  echo "- end_time: $end_human"
  echo "- exit_code: $cmd_ec"
  echo "- child_pid: ${child_pid:-unknown}"
  echo "- seccomp_kernel_events: $seccomp_events"
  echo "- operation_not_permitted_count: $op_not_permitted_count"
  echo "- runtime_denial_markers: $run_slice_denials"
  echo "- violation_score: $violations"
  echo
  echo "## Program Stdout"
  echo
  echo '```text'
  cat "$stdout_tmp"
  echo '```'
  echo
  echo "## Program Stderr"
  echo
  echo '```text'
  cat "$stderr_tmp"
  echo '```'
  echo
  echo "## Sandbox Log Slice"
  echo
  echo '```text'
  printf '%s\n' "$run_slice"
  echo '```'
  echo
  echo "## Kernel Seccomp Correlation"
  echo
  if [[ -n "$kernel_lines" ]]; then
    echo '```text'
    printf '%s\n' "$kernel_lines"
    echo '```'
  else
    echo "No kernel seccomp entries found or access to kernel logs is restricted."
  fi
} > "$report_file"

rm -f "$stdout_tmp" "$stderr_tmp"

echo "Report generated: $report_file"
exit "$cmd_ec"
