# Process Sandbox (seccomp-BPF + Landlock)

A Linux user-space launcher in C that runs a program under a JSON policy with kernel enforcement: **seccomp-BPF** (libseccomp) for the syscall surface, optional **Landlock** (`landlock_restrict_self`) for paths, optional **user/mount/PID namespaces** with **`pivot_root`**, **capability** bounding-set / ambient clear, **`prlimit`**, **`close_range`**, and explicit **`prctl(PR_SET_NO_NEW_PRIVS)`**. Structured **JSONL** audit plus a text log. Adversarial CI covers `clone3`, socket/fork denies, Landlock path deny, and an LD_PRELOAD negative control.

Process-level confinement for short-lived workloads, not a container runtime. Threat model and filter-install order: [`docs/DESIGN.md`](docs/DESIGN.md). Resume drafts with these numbers: [`docs/RESUME_BULLETS.md`](docs/RESUME_BULLETS.md).

## Tech stack (shipped)

`C · seccomp-BPF (libseccomp, default-deny allowlists, ERRNO/KILL_PROCESS, NO_NEW_PRIVS) · Landlock LSM · user/mount/PID namespaces · pivot_root · capabilities (bounding/ambient) · prlimit · close_range · clone3 · pidfd_open (logging) · JSONL audit · Make/CI · p50/p99 microbenchmarks · perf_event_open harness (skip if no PMU)`

Not shipped (roadmap only): seccomp-user-notify, netns/veth, cgroup v2, JSON Schema / PFC export, parser fuzzing.

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
```

Child order: optional userns + mount/`pivot_root` / PID ns → `PR_SET_NO_NEW_PRIVS` → Landlock → drop caps → `prlimit` → `close_range` → seccomp load → ready signal → `execv` (details in `docs/DESIGN.md`).

Policies: `basic.json` (compat, nearly permissive), `restrictive.json` (compat denies including `clone3`), `no-file-network.json`, `strict-allow.json` (default-deny allowlist + Landlock + rlimits + JSONL for `workloads/file_transform`).

## Policy model

`default_deny=true` sets filter default to `EPERM` or `KILL_PROCESS` and installs the `allow` list (compat mode remains default-allow plus deny overlays). `landlock` + `enforce_file_access` turn `file_access` prefixes into Landlock rules; argv checks are defense-in-depth only. Also: `drop_caps`, `close_fds`, `mount_ns`, `pid_ns`, `rlimit_*`, `audit_jsonl`, `kill_on_violation`. CLI: `--mount-ns`, `--pid-ns`, `--no-drop-caps`, `--audit-jsonl PATH`.

Seccomp does not inspect path strings. Path policy is Landlock and/or mount-ns + `pivot_root`. LD_PRELOAD is not the security boundary.

## Layout

`sandbox.c` → `sandbox-run`. `workloads/file_transform.c` curated allowlist target. `bench/` microloops + perf companion. `tests/adversarial/` true-deny binaries. `policies/`, `scripts/`, `reports/`, `.github/workflows/ci.yml`. GUI: `make gui` → `http://127.0.0.1:8080`.
