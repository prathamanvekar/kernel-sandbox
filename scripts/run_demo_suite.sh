#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$workspace_dir"

mkdir -p reports
timestamp_slug="$(date +%Y-%m-%d_%H-%M-%S)"
workload_label_raw="${WORKLOAD_LABEL:-ad-hoc}"
workload_label="$(printf '%s' "$workload_label_raw" | tr '[:upper:]' '[:lower:]' | sed -E 's@[^a-z0-9]+@-@g; s@^-+@@; s@-+$@@')"
suite_id="suite-${timestamp_slug}-baseline-restrictive-no-file-network-wl-${workload_label}"
suite_file="reports/report_suite_${timestamp_slug}_baseline_restrictive_no_file_network_wl-${workload_label}.md"

tmp1="$(mktemp)"
tmp2="$(mktemp)"
tmp3="$(mktemp)"

set +e
./test >"$tmp1" 2>&1
ec1=$?
./sandbox-run policies/restrictive.json ./test >"$tmp2" 2>&1
ec2=$?
./sandbox-run policies/no-file-network.json ./test >"$tmp3" 2>&1
ec3=$?
set -e

{
  echo "# Demo Suite Report"
  echo
  echo "- suite_id: $suite_id"
  echo "- workload_label: ${workload_label_raw}"
  echo "- scenario_baseline_exit: $ec1"
  echo "- scenario_restrictive_exit: $ec2"
  echo "- scenario_no_file_network_exit: $ec3"
  echo
  echo "## Scenario 1: Baseline ./test"
  echo
  echo '```text'
  cat "$tmp1"
  echo '```'
  echo
  echo "## Scenario 2: Restrictive Policy"
  echo
  echo '```text'
  cat "$tmp2"
  echo '```'
  echo
  echo "## Scenario 3: No File + Network Policy"
  echo
  echo '```text'
  cat "$tmp3"
  echo '```'
} > "$suite_file"

rm -f "$tmp1" "$tmp2" "$tmp3"

echo "Demo suite report generated: $suite_file"
