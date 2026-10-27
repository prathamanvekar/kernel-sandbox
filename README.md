<div align="center">

# Process Sandbox

**seccomp-BPF · Landlock · namespaces · cgroup v2**

A Linux user-space launcher that confines a program under a JSON policy with kernel enforcement.

[![CI](https://github.com/prathamanvekar/kernel-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/prathamanvekar/kernel-sandbox/actions/workflows/ci.yml)

</div>

Process-level confinement for short-lived workloads - not a container runtime. Threat model and filter-install order live in [`docs/DESIGN.md`](docs/DESIGN.md).

## What it enforces

The launcher (`sandbox-run`) applies a JSON policy before `execv`: **seccomp-BPF** via libseccomp for the syscall surface, optional **Landlock** (`landlock_restrict_self`) for path prefixes, optional **user / mount / PID / net** namespaces with **`pivot_root`**, **capability** bounding-set and ambient clear, **`prlimit`**, **`close_range`**, and explicit **`prctl(PR_SET_NO_NEW_PRIVS)`**. Optional **cgroup v2** limits cover memory, pids, and cpu.max. Structured **JSONL** audit sits alongside a text log.

Adversarial CI covers `clone3`, socket/fork denies, Landlock path deny, and an LD_PRELOAD negative control.

## Tech stack (shipped)

`C · seccomp-BPF (libseccomp, default-deny allowlists, ERRNO/KILL_PROCESS, NO_NEW_PRIVS) · Landlock LSM · user/mount/PID/net namespaces · pivot_root · veth (optional) · cgroup v2 (memory/cpu/pids) · capabilities (bounding/ambient) · prlimit · close_range · clone3 · pidfd_open (logging) · JSONL audit · Make/CI · p50/p99 microbenchmarks · perf_event_open harness (skip if no PMU)`

Not shipped (roadmap only): seccomp-user-notify, JSON Schema / PFC export, parser fuzzing.

## Measured metrics (this machine)

Host: Linux 6.12.94+, Intel Xeon, 4 CPUs. Methodology: `taskset -c 0` when available; attach N=40 cold launches (`policies/basic.json` → `/bin/true`, timer stops at ready-pipe after `seccomp_load`); microloops 80 samples × 2000 iters, bare vs sandboxed. Artifact: [`reports/METRICS_LATEST.md`](reports/METRICS_LATEST.md). Re-run: `make metrics`. Not portable SLAs.

| Signal | Result |
| --- | --- |
| Attach latency p50 / p99 | 196.8 µs / 495.8 µs |
| getpid per-op p50 bare → sandboxed | 60.5 ns → 70.1 ns |
| open+close `/dev/null` per-op p50 bare → sandboxed | 618.2 ns → 636.8 ns |
| write `/dev/null` per-op p50 bare → sandboxed | 74.5 ns → 83.5 ns |
| Adversarial true-deny (`make check`) | 100% (4/4) |
| Curated false-deny success (strict-allow file transform) | 100% (2/2) |
| perf_event_open cycles | Unavailable here (`ENOENT`; no usable PMU). Recorded as skip, not invented. |

Prefer `make microbench` / `make metrics` for overhead. Legacy `make benchmark` times `test` (includes `sleep(1)`) and is smoke-only.

## Requirements

```bash
sudo apt update
sudo apt install -y build-essential libseccomp-dev libcap-dev strace
```

Landlock requires a kernel with the Landlock ABI (probed; tests skip if absent). Mount/PID ns needs user namespaces. Python 3 only for the optional GUI.

## Build, check, measure

```bash
make
make check
make metrics
```

## Run

```bash
./sandbox-run <policy.json> <program> [args...]
./sandbox-run --mount-ns --pid-ns policies/strict-allow.json \
  ./workloads/file_transform /tmp/in /tmp/out
./sandbox-run --net-ns=loopback policies/basic.json ./tests/adversarial/try_egress
./sandbox-run --cgroup --cgroup-pids-max=4 --cgroup-memory-max=64M \
  policies/basic.json ./tests/adversarial/try_pids_limit
```

`--net-ns=loopback` (or `veth-deny`) enters a user+net namespace, brings up `lo`, and leaves no default route (egress connect fails). Needs unprivileged user namespaces. `veth-deny` also needs `iproute2`.

`--cgroup` creates a leaf under `/sys/fs/cgroup/ksb.sandbox` (or `SANDBOX_CGROUP_ROOT`) with `memory.max` / `pids.max` / `cpu.max`. One-time setup: `sudo ./scripts/setup_cgroup_root.sh`. On hosts where migrating into that root needs CAP_SYS_ADMIN, attach retries via `sudo -n tee …/cgroup.procs`; if that is unavailable, cgroup tests skip.

Child order: optional userns + net/mount/`pivot_root` / PID ns → cgroup attach gate → `PR_SET_NO_NEW_PRIVS` → Landlock → drop caps → `prlimit` → `close_range` → seccomp load → ready signal → `execv` (details in `docs/DESIGN.md`).

Policies: `basic.json`, `restrictive.json`, `no-file-network.json`, `strict-allow.json`, `netns-loopback.json`, `cgroup-pids.json`.

## Policy model

`default_deny=true` sets filter default to `EPERM` or `KILL_PROCESS` and installs the `allow` list (compat mode remains default-allow plus deny overlays). `landlock` + `enforce_file_access` turn `file_access` prefixes into Landlock rules; argv checks are defense-in-depth only. Also: `drop_caps`, `close_fds`, `mount_ns`, `pid_ns`, `rlimit_*`, `audit_jsonl`, `kill_on_violation`. CLI: `--mount-ns`, `--pid-ns`, `--no-drop-caps`, `--audit-jsonl PATH`.

Seccomp does not inspect path strings. Path policy is Landlock and/or mount-ns + `pivot_root`. LD_PRELOAD is not the security boundary.

## Layout

| Path | Role |
| --- | --- |
| `sandbox.c` → `sandbox-run` | Launcher binary |
| `workloads/file_transform.c` | Curated allowlist target |
| `bench/` | Microloops + perf companion |
| `tests/adversarial/` | True-deny binaries |
| `policies/` | Example JSON policies |
| `scripts/` | Helpers (e.g. cgroup root setup) |
| `reports/` | Measured metrics artifacts |
| `.github/workflows/ci.yml` | Build + adversarial gates |
| `make gui` → `http://127.0.0.1:8080` | Optional local GUI |
