# Design notes: isolation core

This document records the threat model and filter-install ordering for the Phase 0/1 isolation stack. It is intentionally short and mechanism-true.

## Threat model (what we claim)

The launcher confines a short-lived child process using kernel enforcement points:

1. seccomp-BPF (syscall surface): default-deny profiles install only the `allow` list; compat mode remains default-allow plus selective denies.
2. Landlock LSM (path surface): when `landlock` and `enforce_file_access` are set, `file_access` prefixes become Landlock path-beneath rules. Argv path checks remain defense-in-depth only.
3. Capability bounding set and ambient clear: after setup, the child drops effective/permitted/inheritable caps and clears ambient caps so exec cannot regain them.
4. `prlimit` ceilings (`RLIMIT_AS`, `RLIMIT_NOFILE`, `RLIMIT_NPROC`) when set in policy.
5. Optional user + mount (+ PID) namespaces with bind mounts and `pivot_root` (not `chroot`-as-security).
6. `close_range` scrub of inherited FDs before exec.
7. Explicit `prctl(PR_SET_NO_NEW_PRIVS)` and `PR_SET_DUMPABLE=0` before Landlock and seccomp load.

Out of scope for this phase: seccomp-user-notify mediation, cgroup v2 resource controllers, netns/veth topologies, and unprivileged rootless demos beyond the user-ns path used for mount/PID setup.

## What still escapes (honest residual risk)

- Kernel bugs and anything allowed by the policy (an over-broad allowlist is an operator error).
- Attacks that do not need denied syscalls or denied paths (logic bugs inside an allowed workload).
- Host-wide DoS below the configured rlimits / without cgroups.
- Side channels (timing, cache) are not addressed.
- If Landlock is unavailable, path policy degrades to pre-exec argv checks; the launcher prints that fact and tests skip Landlock cases.
- Mount/PID namespace mode requires user-namespace mapping; environments that disable userns will skip or fail that path.

## LD_PRELOAD vs kernel enforcement

Userspace interposition (`LD_PRELOAD`, ptrace helpers, wrapper libraries) is not the security boundary. A static binary or a raw syscall bypasses libc wrappers. Landlock and seccomp decisions are enforced in the kernel after `NO_NEW_PRIVS`. The adversarial suite includes a negative test that loads a fake `open` preload and still fails to read `/etc/passwd` under Landlock.

## Filter install order (child)

1. Optional user/mount/PID namespace enter and `pivot_root` bind setup (needs userns root).
2. `prctl(PR_SET_NO_NEW_PRIVS, 1)` then `PR_SET_DUMPABLE=0`.
3. Landlock ruleset create/add/`landlock_restrict_self` (requires NNP).
4. Clear ambient capabilities; drop bounding set bits; `cap_clear` / `cap_set_proc`.
5. Apply `prlimit` ceilings from policy.
6. `close_range` scrub (preserve stdin/stdout/stderr and the ready pipe).
7. `seccomp_init` / rule install / `seccomp_load` (libseccomp NNP attribute also set).
8. Signal parent on the ready pipe (attach latency sample).
9. `execv` target.

Parent attach latency is measured from pre-fork/clone to the ready-pipe byte after `seccomp_load`.

## Seccomp actions

- Default-deny profiles use `SCMP_ACT_ERRNO(EPERM)` unless `kill_on_violation` is true (`SCMP_ACT_KILL_PROCESS`).
- Compat mode uses allow-all default plus deny overlays with the same action choice.
- `SCMP_FLTATR_CTL_LOG` remains enabled to aid allowlist development; it is not a substitute for audit JSONL.

## Process creation surface

`block_process` denies `fork`, `vfork`, `clone`, and `clone3`. Missing `clone3` is a classic sandbox hole on modern glibc/pthread paths; the adversarial suite asserts it.

## pivot_root vs chroot

`chroot` alone does not change the mount namespace and is weak if privileges remain. The optional mount-ns path builds a private mount tree, bind-mounts allowlisted and runtime paths, then `pivot_root`s into that tree and detaches the old root. Prefer this when the environment supports user namespaces; otherwise leave `mount_ns` off and rely on Landlock + seccomp.

## Observability

- Text log: `log_file` (default `sandbox.log`).
- Structured JSONL: `audit_jsonl` events (`start`, `forked`, `filter_installed`, `attach_ready`, `exit` / `signal`, ...).
- Optional kernel audit netlink correlation remains a Phase 2 stretch; report scripts may still best-effort scrape `dmesg`/`journalctl` when permitted.

## Policy fields (Phase 0/1 additions)

`default_deny`, `landlock`, `drop_caps`, `mount_ns`, `pid_ns`, `close_fds`, `rlimit_as_mb`, `rlimit_nofile`, `rlimit_nproc`, `audit_jsonl`.

CLI overrides: `--mount-ns`, `--pid-ns`, `--no-drop-caps`, `--audit-jsonl PATH`.

## TODOs / deferred (Phase 2)

- seccomp-user-notify supervisor for dynamic `openat`/`connect` decisions.
- Broader rootless user-ns failure matrix across distros.
- Netns + veth deny topology with measured enter cost.
- cgroup v2 memory/CPU demos.
- JSON Schema validation + `seccomp_export_pfc` filter-size reports in CI.
- Fuzzing the policy parser; multi-threaded filter inheritance tests.
