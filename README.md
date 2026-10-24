# Process Sandbox (seccomp-BPF + Landlock)

A small Linux user-space launcher that runs a program under a JSON policy using kernel enforcement: seccomp-BPF for the syscall surface, optional Landlock for path policy, optional mount/PID namespaces with `pivot_root`, capability dropping, and `prlimit` ceilings. It is a process guardrail for short-lived workloads, not a container runtime.

The engine is a single C binary (`sandbox-run`) built with libseccomp and libcap. Shell helpers produce Markdown reports under `reports/`. A thin Python GUI still wraps the same CLI flows. Design notes and the threat model live in `docs/DESIGN.md`.

## Requirements

Linux with GCC, Make, libseccomp, and libcap development headers. Landlock needs a kernel that exposes the Landlock ABI (this project probes at runtime and skips path LSM tests if unavailable). Optional mount/PID namespace mode needs user namespaces; on some Ubuntu kernels the parent writes uid/gid maps for the child because AppArmor restricts self-mapping for unprofiled binaries.

```bash
sudo apt update
sudo apt install -y build-essential libseccomp-dev libcap-dev strace
```

Python 3 is only needed for the GUI.

## Build and test

```bash
make
make check
```

`make check` builds adversarial helpers and runs true-deny / false-deny gates (including Landlock and `clone3`). `make microbench` and `make metrics` collect wall-clock microloops and attach latency into `reports/`.

## Run

```bash
./sandbox-run <policy.json> <program> [args...]
./sandbox-run --mount-ns --pid-ns policies/strict-allow.json ./workloads/file_transform /tmp/in /tmp/out
```

The launcher loads the policy, optionally checks argv paths, forks, then in the child applies NNP, Landlock, capability drop, rlimits, FD scrub via `close_range`, seccomp load, and `execv`. Structured events go to `audit_jsonl` when set (default in several policies: `sandbox.jsonl`). Text lines still append to `log_file`.

Included policies:

`policies/basic.json` is a nearly permissive compat (default-allow) profile. `policies/restrictive.json` is compat mode with network/process/info denies, including `clone3`. `policies/no-file-network.json` blocks common file-mutation and network syscalls. `policies/strict-allow.json` is default-deny with a least-privilege allowlist for `workloads/file_transform`, Landlock on `./` and `/tmp`, caps/rlimits, and JSONL audit.

## Policy model

Policies are JSON objects parsed by a small custom reader. Important fields beyond the original deny-list model:

`default_deny` (bool): when true, the filter default is `EPERM` or `KILL_PROCESS` and the `allow` array installs `SCMP_ACT_ALLOW` rules (this is the Phase 0 fix; `allow` is no longer ignored). When false, behavior stays compat: default-allow plus deny overlays.

`landlock` (bool): with `enforce_file_access` and `file_access` prefixes, attach a Landlock ruleset before exec. Argv checks remain defense-in-depth only.

`drop_caps`, `close_fds`, `mount_ns`, `pid_ns`, `rlimit_as_mb`, `rlimit_nofile`, `rlimit_nproc`, `audit_jsonl`, and `kill_on_violation` control the rest of the child setup. CLI flags `--mount-ns`, `--pid-ns`, `--no-drop-caps`, and `--audit-jsonl PATH` override policy when needed.

Seccomp cannot inspect path strings. Path confinement is Landlock and/or mount-ns + `pivot_root`, not argv inspection alone. LD_PRELOAD is not a security boundary; see `docs/DESIGN.md` and the adversarial preload test.

## Measured metrics (this machine)

Collected on Linux 6.12.94+, Intel Xeon (4 CPUs), pinned with `taskset -c 0` where noted. Numbers come from `make metrics` / `reports/METRICS_LATEST.md`. Do not treat them as portable SLAs.

| metric | value |
| --- | --- |
| Attach latency p50 (basic → `/bin/true`, N=40) | 196.8 µs |
| Attach latency p99 | 495.8 µs |
| getpid microloop per-op p50 bare / sandboxed | 60.5 ns / 70.1 ns |
| open+close `/dev/null` per-op p50 bare / sandboxed | 618.2 ns / 636.8 ns |
| write `/dev/null` per-op p50 bare / sandboxed | 74.5 ns / 83.5 ns |
| Adversarial true-deny rate (`make check`) | 100% (4/4) |
| Curated false-deny success (strict-allow file transform) | 100% (2/2) |
| `perf_event_open` cycles | unavailable here (ENOENT; no usable PMU in this VM) |

Re-run locally:

```bash
make metrics
# or
SAMPLES=80 ITERS=2000 ATTACH_N=40 ./scripts/collect_metrics.sh
```

The older `make benchmark` path around `test` (which sleeps one second) remains as a smoke timing check only. Prefer `make microbench` / `make metrics` for overhead claims.

## Layout

`sandbox.c` builds to `sandbox-run`. `test.c` is the legacy interactive demo target. `workloads/file_transform.c` is the curated allowlist workload. `bench/` holds microloop and perf-companion programs. `tests/adversarial/` holds true-deny binaries and the LD_PRELOAD negative control. `policies/` holds JSON profiles. `scripts/` wraps reports, suites, microbench, and metrics. `docs/DESIGN.md` covers ordering, threat model, and residuals. CI is `.github/workflows/ci.yml`.

## GUI

```bash
make gui
```

Serves `http://127.0.0.1:8080` by default (`SANDBOX_GUI_HOST` / `SANDBOX_GUI_PORT`). The dashboard shells out to the same Make targets as the CLI.

## Constraints

Linux only. The JSON parser is intentionally minimal (no full schema compiler yet). Hardware performance counters may be missing in VMs; the harness records that instead of inventing cycle counts. Phase 2 items (seccomp-user-notify, netns/veth, cgroup v2, parser fuzzing) are deferred; see the living plan in the project roadmap doc and the TODOs in `docs/DESIGN.md`.
