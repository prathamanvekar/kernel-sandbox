# User-space Syscall Sandboxing (seccomp-BPF)

## Company Narrative (Practical Positioning)

This can be positioned as an internal **Workload Guardrail** tool for short-lived, semi-trusted tasks where full container orchestration is unnecessary:

- CI pre-check jobs (lint/test tools from external repos)
- Plugin or script execution in backend services
- Internal automation tasks with syscall/network/process restrictions

How companies can use the current implementation today:

- Wrap risky commands with `sandbox-run` before execution.
- Attach a **workload label** (for example `ci-smoke`, `plugin-audit`, `grading-batch`) in GUI so reports are easier to trace.
- Archive generated markdown reports as build artifacts for auditability.

## Build

```bash
make
```

If `libseccomp` is missing:

```bash
sudo apt update
sudo apt install -y build-essential libseccomp-dev strace
```

## Command Format

```bash
./sandbox-run <policy.json> <program> [args...]
```

Example:

```bash
./sandbox-run policies/restrictive.json ./test
```

## Useful Policies

- `policies/basic.json`: almost permissive, good sanity check.
- `policies/restrictive.json`: blocks process creation, network, and selected info syscalls.
- `policies/no-file-network.json`: blocks common file mutation/destructive + network syscalls.

## Observe Behavior

Run target directly:

```bash
./test
```

Run target inside sandbox:

```bash
./sandbox-run policies/restrictive.json ./test
```

Trace syscalls:

```bash
strace -f -o trace.log ./sandbox-run policies/restrictive.json ./test
```

Check sandbox logs:

```bash
tail -n 50 sandbox.log
```

## Per-Run Violation Report (Phase 3)

Generate a single report that includes stdout/stderr, relevant sandbox log slice, and kernel seccomp correlation when available:

```bash
make report
```

Use custom policy/target:

```bash
make report POLICY=policies/no-file-network.json TARGET=./test
```

Add target args:

```bash
make report POLICY=policies/restrictive.json TARGET=./test REPORT_ARGS="arg1 arg2"
```

Reports are written under `reports/` as Markdown files.

Kernel correlation notes:

- The script attempts `dmesg --since` first, then `journalctl -k --since`.
- On some systems, kernel logs are restricted for non-root users; in that case the report still includes sandbox log correlation.

## GUI Dashboard

Start the GUI:

```bash
make gui
```

Open in browser:

```text
http://127.0.0.1:8080
```

From the GUI you can:

- Build project binaries.
- Run baseline target.
- Run target with selected sandbox policy.
- Generate markdown report files.
- Run a demo suite (baseline + restricted scenarios).
- Run performance benchmark comparisons.
- Inspect sandbox.log tail.
- Browse generated reports and policy previews.
- Tag runs with workload labels for easier reporting in team workflows.

## Policy Fields

```json
{
  "allow": ["read", "write"],
  "deny": ["execve", "fork"],
  "file_access": ["./", "/tmp"],
  "network": false,
  "block_process": true,
  "block_file": false,
  "block_info": false,
  "enforce_file_access": true,
  "kill_on_violation": false,
  "log_file": "sandbox.log"
}
```

Notes:

- `deny`: syscall names resolved by libseccomp.
- `network=false`: blocks common socket syscalls.
- `block_process=true`: blocks `fork`, `vfork`, `clone`, and `clone3` (compat mode).
- `block_file=true`: blocks common file mutation/destructive syscalls.
- `block_info=true`: blocks `getpid`, `getppid`, `uname`.
- `default_deny=true`: filter default is deny; `allow` installs allow rules.
- `landlock=true` with `enforce_file_access=true`: Landlock path-beneath rules from `file_access`.
- `enforce_file_access=true`: also keeps coarse pre-exec argv path checks (defense-in-depth).
- `kill_on_violation=true`: process is killed on denied syscall; otherwise denied with `EPERM`.
- See `docs/DESIGN.md` for NNP ordering, caps/rlimits, mount-ns/`pivot_root`, and residuals.

## Path policy

Seccomp cannot inspect path strings. Prefer `landlock=true` and/or `--mount-ns` with `pivot_root`. Argv allowlisting alone is not runtime path confinement.

## Demo Suite and Benchmark

Generate a multi-scenario demo report:

```bash
make demo-suite
```

Generate performance benchmark report (default 5 iterations):

```bash
make benchmark
```

Custom benchmark iterations:

```bash
BENCH_ITERATIONS=10 make benchmark POLICY=policies/restrictive.json TARGET=./test
```
