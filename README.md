# Process Sandbox (seccomp-BPF)

A small Linux user-space wrapper that runs a program under a JSON-defined seccomp-BPF policy. The goal is lightweight syscall restriction for short-lived workloads, not full container or VM isolation.

The engine is a single C binary (`sandbox-run`) built with libseccomp. Around it, shell scripts produce Markdown run reports, and a small Python HTTP server exposes a local dashboard for build, run, suite, and benchmark flows.

## Requirements

Linux with GCC, Make, and libseccomp development headers. Optional: `strace` for tracing, and access to kernel logs (`dmesg` or `journalctl`) if you want seccomp correlation in reports.

```bash
sudo apt update
sudo apt install -y build-essential libseccomp-dev strace
```

Python 3 is only needed for the GUI (`gui/server.py` uses the standard library).

## Layout

`sandbox.c` is the sandbox engine and builds to `sandbox-run`. `test.c` builds to `test`, a small demo target that exercises write, sleep, open, getpid, fork, and socket. JSON policies live under `policies/`. Helper scripts under `scripts/` wrap runs into Markdown under `reports/`. The GUI is `gui/server.py` plus static files in `gui/static/`. Extra narrative notes are in `docs/`.

## Build

```bash
make
```

This produces `sandbox-run` and `test`. `make clean` removes those binaries and `sandbox.log`.

## Run

```bash
./sandbox-run <policy.json> <program> [args...]
```

Example:

```bash
./sandbox-run policies/restrictive.json ./test
```

The launcher loads the policy, optionally checks the target path and path-like arguments against a coarse allowlist, forks, installs the seccomp filter in the child, then `execv`s the target. Events are appended to the policy's `log_file` (default `sandbox.log`).

Included policies:

`policies/basic.json` is nearly permissive and useful as a sanity check. `policies/restrictive.json` disables network, blocks process creation and selected info syscalls, and enables coarse file-access checks. `policies/no-file-network.json` blocks common file-mutation syscalls and network.

To compare behavior, run `./test` directly, then again under a policy. For syscall traces:

```bash
strace -f -o trace.log ./sandbox-run policies/restrictive.json ./test
```

## Policy model

Policies are JSON objects parsed by a small custom reader in `sandbox.c` (not a full JSON library). Defaults apply when fields are omitted: network allowed, file-access enforcement off, kill-on-violation off, log file `sandbox.log`.

Example shape:

```json
{
  "allow": ["read", "write", "exit", "exit_group"],
  "deny": ["fork", "vfork", "clone", "getpid"],
  "file_access": ["./", "/tmp"],
  "network": false,
  "block_process": true,
  "block_file": false,
  "block_info": true,
  "enforce_file_access": true,
  "kill_on_violation": false,
  "log_file": "sandbox.log"
}
```

The filter starts as allow-all (`SCMP_ACT_ALLOW`) and then applies deny rules. Syscall names in `deny` are resolved with libseccomp. Setting `network` to false installs a fixed set of socket-related denies. `block_process` denies `fork`, `vfork`, and `clone`. `block_file` denies common mutation/destructive calls such as unlink, rename, mkdir, chmod, and truncate. `block_info` denies `getpid`, `getppid`, and `uname`.

If `kill_on_violation` is true, denied syscalls use `SCMP_ACT_KILL_PROCESS`; otherwise they return `EPERM`. The `allow` list is loaded and logged but not used to build an allow-only filter. Denying `execve` / `execveat` in the policy is skipped during the launcher phase so the child can still exec the target.

`file_access` with `enforce_file_access` true performs a coarse pre-execution check that the resolved target and path-like argv entries fall under the listed prefixes. Seccomp does not inspect path strings, so this is not strict runtime path confinement. Stronger isolation would need mechanisms such as namespaces, bind mounts, or Landlock.

## Reports, suite, and benchmark

Single-run Markdown report (stdout/stderr, sandbox log slice, optional kernel seccomp lines):

```bash
make report
make report POLICY=policies/no-file-network.json TARGET=./test
make report POLICY=policies/restrictive.json TARGET=./test REPORT_ARGS="arg1 arg2"
```

Demo suite (baseline `./test`, then restrictive and no-file-network policies):

```bash
make demo-suite
```

Simple timing benchmark (default 5 iterations; override with `BENCH_ITERATIONS`):

```bash
make benchmark
BENCH_ITERATIONS=10 make benchmark POLICY=policies/restrictive.json TARGET=./test
```

Scripts honor `WORKLOAD_LABEL` (default `ad-hoc`) when naming report files. Artifacts land in `reports/`. Kernel correlation tries `dmesg --since`, then `journalctl -k`; if those are unavailable to the user, the report still includes the sandbox log slice.

There is no separate unit-test framework. Validation is the demo binary, the make targets above, and manual observation via `sandbox.log` / `strace`.

## GUI

```bash
make gui
```

Serves `http://127.0.0.1:8080` by default. Host and port can be set with `SANDBOX_GUI_HOST` and `SANDBOX_GUI_PORT`. The dashboard can build, run the target with or without a policy, generate reports, run the demo suite and benchmark, show a log tail, and preview policies and reports. It shells out to the same Make/script paths as the CLI.

## Constraints

Linux and libseccomp only. The JSON parser is intentionally minimal. File-path policy is coarse and pre-exec only. This is process-level syscall filtering, not a container runtime: no namespaces, cgroups, or image layers are applied by this project.
