#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-reports}"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
OUT="$OUT_DIR/metrics_${STAMP}.md"
JSONL="$OUT_DIR/metrics_${STAMP}.jsonl"
ATTACH_N="${ATTACH_N:-30}"
SAMPLES="${SAMPLES:-60}"
ITERS="${ITERS:-1500}"

mkdir -p "$OUT_DIR"
make all check-bins >/dev/null
: > "$JSONL"

pin() {
  if command -v taskset >/dev/null 2>&1; then
    taskset -c 0 "$@"
  else
    "$@"
  fi
}

ATTACH_FILE=/tmp/ksb_attach_us.txt
: > "$ATTACH_FILE"
for _ in $(seq 1 "$ATTACH_N"); do
  line="$(pin ./sandbox-run policies/basic.json /bin/true 2>&1 | grep 'Attach latency' || true)"
  us="$(echo "$line" | sed -n 's/.*: \([0-9.]*\) us.*/\1/p')"
  if [[ -n "${us:-}" ]]; then
    echo "$us" >> "$ATTACH_FILE"
    echo "{\"event\":\"attach_us\",\"us\":$us}" >> "$JSONL"
  fi
done

MICRO_OUT=/tmp/micro_collect.txt
: > "$MICRO_OUT"
for mode in getpid openclose write; do
  echo "BARE $mode" >> "$MICRO_OUT"
  pin ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS" >> "$MICRO_OUT"
  echo "SANDBOX $mode" >> "$MICRO_OUT"
  pin ./sandbox-run policies/basic.json ./bench/micro_syscall "$mode" "$SAMPLES" "$ITERS" >> "$MICRO_OUT"
done

PERF_OUT=/tmp/perf_collect.txt
: > "$PERF_OUT"
for mode in getpid openclose; do
  echo "BARE $mode" >> "$PERF_OUT"
  pin ./bench/perf_cycles "$mode" 100000 >> "$PERF_OUT" || echo "mode=$mode note=perf_failed" >> "$PERF_OUT"
  echo "SANDBOX $mode" >> "$PERF_OUT"
  pin ./sandbox-run policies/basic.json ./bench/perf_cycles "$mode" 100000 >> "$PERF_OUT" || echo "mode=$mode note=perf_failed" >> "$PERF_OUT"
done

CHECK_OUT=/tmp/check_collect.txt
set +e
./tests/run_check.sh > "$CHECK_OUT" 2>&1
CHECK_RC=$?
set -e

export OUT ATTACH_FILE MICRO_OUT PERF_OUT CHECK_OUT ATTACH_N SAMPLES ITERS
python3 <<'PY'
import json, os, platform, datetime, re, pathlib

attach_vals = []
p = pathlib.Path(os.environ["ATTACH_FILE"])
if p.exists():
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            attach_vals.append(float(line))
attach_vals.sort()

def pct(vals, p):
    if not vals:
        return None
    idx = int(round((p / 100.0) * (len(vals) - 1)))
    idx = min(max(idx, 0), len(vals) - 1)
    return vals[idx]

attach = {
    "n": len(attach_vals),
    "p50_us": pct(attach_vals, 50),
    "p99_us": pct(attach_vals, 99),
}

micro = pathlib.Path(os.environ["MICRO_OUT"]).read_text()
perf = pathlib.Path(os.environ["PERF_OUT"]).read_text()
check = pathlib.Path(os.environ["CHECK_OUT"]).read_text()

def parse_labeled(text):
    rows = []
    cur = None
    for line in text.splitlines():
        if line.startswith("BARE ") or line.startswith("SANDBOX "):
            cur = line.strip()
        elif line.startswith("mode=") and cur:
            m = dict(part.split("=", 1) for part in line.split() if "=" in part)
            m["label"] = cur
            rows.append(m)
    return rows

rows = parse_labeled(micro)
perf_rows = parse_labeled(perf)

pass_n = len(re.findall(r"\[PASS\]", check))
fail_n = len(re.findall(r"\[FAIL\]", check))
skip_n = len(re.findall(r"\[SKIP\]", check))
true_deny_pass = len(re.findall(r"\[PASS\] true-deny", check))
true_deny_fail = len(re.findall(r"\[FAIL\] true-deny", check))
false_deny_pass = len(re.findall(r"\[PASS\] false-deny", check))
false_deny_fail = len(re.findall(r"\[FAIL\] false-deny", check))
td_total = true_deny_pass + true_deny_fail
fd_total = false_deny_pass + false_deny_fail
td_rate = (100.0 * true_deny_pass / td_total) if td_total else None
fd_ok = (100.0 * false_deny_pass / fd_total) if fd_total else None

cpu = "unknown"
try:
    for line in open("/proc/cpuinfo", encoding="utf-8"):
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
except OSError:
    pass

lines = []
lines.append("# Measured metrics")
lines.append("")
lines.append(
    f"Collected: {datetime.datetime.now(datetime.timezone.utc).isoformat()}"
)
lines.append("")
lines.append(f"Host: {platform.platform()}")
lines.append("")
lines.append(f"Kernel: {platform.release()}")
lines.append("")
lines.append(f"CPU: {cpu}")
lines.append("")
lines.append(f"nproc: {os.cpu_count()}")
lines.append("")
lines.append("## Attach latency (cold launch to filter ready)")
lines.append("")
lines.append(
    f"Policy: `policies/basic.json`, target: `/bin/true`, N={attach['n']} "
    f"(requested {os.environ.get('ATTACH_N')}), pinned with `taskset -c 0` when available."
)
lines.append("")
lines.append("| metric | value |")
lines.append("| --- | --- |")
lines.append(f"| attach p50 | {attach['p50_us']} µs |")
lines.append(f"| attach p99 | {attach['p99_us']} µs |")
lines.append("")
lines.append("## Syscall microloops (bare vs sandboxed basic)")
lines.append("")
lines.append(
    f"Samples={os.environ.get('SAMPLES')}, iters/sample={os.environ.get('ITERS')}."
)
lines.append("")
lines.append("| label | mode | p50 ns/sample | p99 ns/sample | per-op p50 ns | per-op p99 ns |")
lines.append("| --- | --- | --- | --- | --- | --- |")
for r in rows:
    lines.append(
        f"| {r.get('label')} | {r.get('mode')} | {r.get('p50_ns')} | {r.get('p99_ns')} | "
        f"{r.get('per_op_p50_ns')} | {r.get('per_op_p99_ns')} |"
    )
lines.append("")
lines.append("## perf_event_open companion")
lines.append("")
lines.append("| label | mode | cycles | instructions | per-op cycles | note |")
lines.append("| --- | --- | --- | --- | --- | --- |")
for r in perf_rows:
    lines.append(
        f"| {r.get('label')} | {r.get('mode')} | {r.get('cycles')} | {r.get('instructions')} | "
        f"{r.get('per_op_cycles', '')} | {r.get('note', '')} |"
    )
lines.append("")
lines.append("## Correctness gates")
lines.append("")
lines.append("| gate | result |")
lines.append("| --- | --- |")
lines.append(f"| make check pass/fail/skip | {pass_n}/{fail_n}/{skip_n} |")
lines.append(f"| adversarial true-deny rate | {td_rate}% ({true_deny_pass}/{td_total}) |")
lines.append(f"| curated false-deny success | {fd_ok}% ({false_deny_pass}/{fd_total}) |")
lines.append("")
lines.append("## Raw check log")
lines.append("")
lines.append("```")
lines.append(check.rstrip())
lines.append("```")
lines.append("")

out = pathlib.Path(os.environ["OUT"])
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
stable = pathlib.Path("reports/METRICS_LATEST.md")
stable.write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
print(f"Wrote {out}")
print(f"Updated {stable}")
print(json.dumps({"attach": attach, "true_deny_rate": td_rate, "false_deny_success": fd_ok}))
PY

echo "check_rc=$CHECK_RC"
exit "$CHECK_RC"
