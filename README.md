<div align="center">

# Process Sandbox

**seccomp-BPF · Landlock · namespaces · cgroup v2**

Linux C launcher. JSON policy. Kernel enforcement.

[![CI](https://github.com/prathamanvekar/kernel-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/prathamanvekar/kernel-sandbox/actions/workflows/ci.yml)

</div>

Process-level confinement for short-lived workloads - not a container runtime. Design: [`docs/DESIGN.md`](docs/DESIGN.md).

## Shipped

`sandbox-run` applies policy before `execv`:

- **seccomp-BPF** (libseccomp) - default-deny allowlists, ERRNO / KILL_PROCESS, `PR_SET_NO_NEW_PRIVS`
- **Landlock** (`landlock_restrict_self`) - path prefixes
- **Namespaces** - user / mount / PID / net, optional `pivot_root`, optional veth
- **cgroup v2** - memory / pids / cpu.max
- **Caps / rlimits** - bounding + ambient clear, `prlimit`, `close_range`
- **Audit** - JSONL + text log

CI adversarial gates: `clone3`, socket/fork deny, Landlock path deny, LD_PRELOAD negative control.

Not shipped: seccomp-user-notify, JSON Schema / PFC export, parser fuzzing.

## Metrics

Host: Linux 6.12.94+, Intel Xeon, 4 CPUs. `taskset -c 0` when available. Attach N=40 cold launches (`policies/basic.json` → `/bin/true`, stop at ready-pipe after `seccomp_load`). Microloops: 80 samples × 2000 iters, bare vs sandboxed. Artifact: [`reports/METRICS_LATEST.md`](reports/METRICS_LATEST.md). Re-run: `make metrics`. Not portable SLAs.

| Signal | Result |
| --- | --- |
| Attach latency p50 / p99 | 196.8 µs / 495.8 µs |
| getpid per-op p50 bare → sandboxed | 60.5 ns → 70.1 ns |
| open+close `/dev/null` per-op p50 bare → sandboxed | 618.2 ns → 636.8 ns |
| write `/dev/null` per-op p50 bare → sandboxed | 74.5 ns → 83.5 ns |
| Adversarial true-deny (`make check`) | 100% (4/4) |
| Curated false-deny success (strict-allow file transform) | 100% (2/2) |
| perf_event_open cycles | Skip (`ENOENT`; no PMU) |

Use `make microbench` / `make metrics`. Legacy `make benchmark` times `test` (includes `sleep(1)`) - smoke only.

## Build

```bash
sudo apt update
sudo apt install -y build-essential libseccomp-dev libcap-dev strace
make
make check
make metrics
```

Landlock needs a Landlock ABI kernel (probed; skip if absent). Mount/PID ns needs user namespaces. Python 3 for optional GUI only.

## Run

```bash
./sandbox-run <policy.json> <program> [args...]
./sandbox-run --mount-ns --pid-ns policies/strict-allow.json \
  ./workloads/file_transform /tmp/in /tmp/out
./sandbox-run --net-ns=loopback policies/basic.json ./tests/adversarial/try_egress
./sandbox-run --cgroup --cgroup-pids-max=4 --cgroup-memory-max=64M \
  policies/basic.json ./tests/adversarial/try_pids_limit
```

`--net-ns=loopback` / `veth-deny`: user+net ns, `lo` up, no default route. Needs unprivileged userns. `veth-deny` needs `iproute2`.

`--cgroup`: leaf under `/sys/fs/cgroup/ksb.sandbox` (or `SANDBOX_CGROUP_ROOT`) with `memory.max` / `pids.max` / `cpu.max`. Setup: `sudo ./scripts/setup_cgroup_root.sh`. If migrate needs CAP_SYS_ADMIN, attach retries via `sudo -n tee …/cgroup.procs`; else cgroup tests skip.

Child order: optional userns + net/mount/`pivot_root` / PID ns → cgroup attach → `PR_SET_NO_NEW_PRIVS` → Landlock → drop caps → `prlimit` → `close_range` → seccomp load → ready → `execv`.

Policies: `basic.json`, `restrictive.json`, `no-file-network.json`, `strict-allow.json`, `netns-loopback.json`, `cgroup-pids.json`.

## Policy

`default_deny=true` → default `EPERM` or `KILL_PROCESS` + `allow` list. Compat mode: default-allow + deny overlays. `landlock` + `enforce_file_access` map `file_access` prefixes to Landlock. Argv checks are defense-in-depth only.

Also: `drop_caps`, `close_fds`, `mount_ns`, `pid_ns`, `rlimit_*`, `audit_jsonl`, `kill_on_violation`. CLI: `--mount-ns`, `--pid-ns`, `--no-drop-caps`, `--audit-jsonl PATH`.

Seccomp does not see path strings. Path policy is Landlock and/or mount-ns + `pivot_root`. LD_PRELOAD is not the boundary.

## Layout

| Path | Role |
| --- | --- |
| `sandbox.c` → `sandbox-run` | Launcher |
| `workloads/file_transform.c` | Curated allowlist target |
| `bench/` | Microloops + perf companion |
| `tests/adversarial/` | True-deny binaries |
| `policies/` | Example JSON policies |
| `scripts/` | Helpers (cgroup root setup) |
| `reports/` | Metrics artifacts |
| `.github/workflows/ci.yml` | Build + adversarial gates |
| `make gui` → `http://127.0.0.1:8080` | Optional GUI |
