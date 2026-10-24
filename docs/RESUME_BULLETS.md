# Resume bullet drafts (Phase 0/1)

Replace only if you re-measure on another host. Numbers below are from Linux 6.12.94+, Intel Xeon (4 CPUs), `make metrics` / `reports/METRICS_LATEST.md` (attach N=40, microloops 80×2000, `taskset -c 0`).

## One-line tech stack

`C, Linux seccomp-BPF (libseccomp, default-deny allowlists, NO_NEW_PRIVS), Landlock LSM (landlock_restrict_self), user/mount/PID/net namespaces, pivot_root, veth, cgroup v2 (memory/cpu/pids), capabilities (bounding/ambient), prlimit, close_range, clone3, pidfd_open (logging), JSONL audit, adversarial CI, p50/p99 microbenchmarks`

## Bullets

1. Built a Linux user-space sandbox in C using **seccomp-BPF** with **default-deny** profiles and explicit **`PR_SET_NO_NEW_PRIVS`**, installing least-privilege syscall allowlists before `exec`, with policy actions among `ERRNO(EPERM)` and `KILL_PROCESS`.

2. Enforced filesystem isolation with **Landlock** (`landlock_restrict_self`) and optional **mount namespace + `pivot_root`** binds (plus PID ns / user ns for setup), blocking out-of-policy path access in an adversarial suite under CI; argv checks kept only as defense-in-depth. Demonstrated LD_PRELOAD cannot bypass Landlock denials.

3. Measured sandbox cost with **attach-latency p50/p99 of 197 µs / 496 µs** (cold, basic policy → `/bin/true`) and syscall microloops bare vs sandboxed (**getpid** 60.5→70.1 ns/op p50; **open/close** 618→637 ns/op p50). Cross-checked with a `perf_event_open` harness; recorded PMU unavailable (`ENOENT`) instead of inventing cycle counts.

4. Added structured **JSONL** audit events for filter install / attach / exit; CI gates **100% true-deny** on adversarial binaries (`clone3`, socket, fork, Landlock `/etc/passwd`) and **100% false-deny success** on a curated allowlist file-transform workload.

5. Reduced the **capability bounding set**, cleared **ambient** capabilities, applied **`prlimit`** ceilings, scrubbed FDs with **`close_range`**, and covered **`clone3`** in process isolation, with a written threat model for residual escape paths.
