# Design notes: isolation core

Threat model, filter-install order, and tradeoffs for the Phase 0/1 stack. Mechanism-true: what the kernel enforces, what still escapes, and why argv or LD_PRELOAD is not the boundary.

## Threat model (what we claim)

The launcher confines a short-lived child using kernel enforcement points:

1. **seccomp-BPF** (syscall surface). Default-deny profiles install only the JSON `allow` list. Compat mode remains default-allow plus selective denies (`network`, `block_process` including **`clone3`**, `block_file`, `block_info`, plus `deny[]`).
2. **Landlock LSM** (path surface). When `landlock` and `enforce_file_access` are set, `file_access` prefixes become path-beneath rules via `landlock_create_ruleset` / `landlock_add_rule` / **`landlock_restrict_self`**. Argv path checks are defense-in-depth only.
3. **Capability bounding set** and **ambient clear** after setup (`PR_CAPBSET_DROP`, `PR_CAP_AMBIENT_CLEAR_ALL`, `cap_clear` / `cap_set_proc`) so exec cannot regain dropped caps.
4. **`prlimit`** ceilings (`RLIMIT_AS`, `RLIMIT_NOFILE`, `RLIMIT_NPROC`) when set in policy.
5. Optional **user + mount (+ PID) namespaces** with bind mounts and **`pivot_root`** (not chroot-as-security). Parent writes `uid_map` / `gid_map` when the environment blocks self-mapping (common under AppArmor userns restrictions).
6. **`close_range`** scrub of inherited FDs before exec (keep stdio + ready pipe).
7. Explicit **`prctl(PR_SET_NO_NEW_PRIVS)`** and **`PR_SET_DUMPABLE=0`** before Landlock and seccomp load (libseccomp NNP attribute also set).

Out of scope this phase (roadmap only): **seccomp-user-notify**, **cgroup v2**, **netns/veth**, JSON Schema + `seccomp_export_pfc` size CI, parser fuzzing.

## Tradeoffs interviewers probe

**Default-deny vs deny-lists.** Deny-lists are easy to ship and easy to miss (`clone3` is the classic hole). Default-deny forces an allowlist derived from a real workload (`strace` → `policies/strict-allow.json` for `file_transform`). Compat mode stays for older profiles; `default_deny` is the least-privilege path.

**Landlock vs argv path checks.** Seccomp cannot follow userspace pointers to path strings. Pre-exec argv allowlisting is TOCTOU-ish and incomplete (the program can `open` anything once running). Landlock attaches a kernel path policy to the process. We keep argv checks as a cheap early reject, not as the FS story.

**`pivot_root` vs `chroot`.** `chroot` does not create a private mount tree and is weak if privileges remain. Mount-ns + bind mounts + `pivot_root` + detach old root is the container-shaped FS view. If userns is unavailable, leave `mount_ns` off and rely on Landlock + seccomp; do not pretend chroot is enough.

**NNP ordering.** Landlock and useful seccomp both require no-new-privs. Order: ns/`pivot_root` (needs userns root) → NNP → Landlock → drop caps → rlimits → FD scrub → seccomp → exec. Filter install after NNP so a later privileged exec cannot widen the profile.

**Caps: bounding vs effective vs ambient.** Clearing effective/permitted is not enough if ambient survives exec or the bounding set still allows raising caps later. We clear ambient, drop bounding bits, then clear the process set.

**LD_PRELOAD vs kernel.** Libc wrappers are not the boundary. Static binaries and raw syscalls bypass preload. The adversarial suite loads a fake `open` preload and still fails `/etc/passwd` under Landlock.

## What still escapes

Kernel bugs; anything the allowlist permits; logic bugs inside an allowed workload; DoS below rlimits / without cgroups; side channels. If Landlock is unavailable, path policy degrades to argv checks and tests skip. If userns is disabled, mount/PID ns fails closed or is skipped in CI with an explicit note. On this measurement VM, **`perf_event_open` returned ENOENT** (no usable PMU); cycle deltas are not claimed.

## Filter install order (child)

1. Optional user/mount/PID namespace enter and `pivot_root` bind setup (parent maps uid/gid after child `unshare`).
2. `prctl(PR_SET_NO_NEW_PRIVS, 1)` then `PR_SET_DUMPABLE=0`.
3. Landlock ruleset create/add/`landlock_restrict_self`.
4. Ambient clear; bounding-set drop; `cap_set_proc` empty.
5. `prlimit` from policy.
6. `close_range` scrub.
7. `seccomp_init` / rules / `seccomp_load`.
8. Ready-pipe byte to parent (attach latency sample: pre-fork → this byte).
9. `execv`.

## Seccomp actions

Default-deny: `SCMP_ACT_ERRNO(EPERM)` unless `kill_on_violation` → `SCMP_ACT_KILL_PROCESS`. Compat: allow-all default + deny overlays with the same action. `SCMP_FLTATR_CTL_LOG` helps allowlist bring-up; JSONL is the structured audit path. Under default-deny, redundant deny overlays with the same action as the filter default are skipped (libseccomp rejects them).

## Observability

Text `log_file`; JSONL `audit_jsonl` (`start`, `forked`, `filter_installed`, `attach_ready`, `exit` / `signal`, optional `pidfd_opened`). Audit netlink correlation is Phase 2; report scripts may still best-effort scrape `dmesg`/`journalctl`.

## Policy / CLI surface

Fields: `default_deny`, `allow`, `deny`, `file_access`, `landlock`, `enforce_file_access`, `drop_caps`, `mount_ns`, `pid_ns`, `close_fds`, `rlimit_as_mb`, `rlimit_nofile`, `rlimit_nproc`, `audit_jsonl`, `kill_on_violation`, block flags. CLI: `--mount-ns`, `--pid-ns`, `--no-drop-caps`, `--audit-jsonl PATH`.

## Deferred (Phase 2)

seccomp-user-notify supervisor; broader rootless userns matrix; netns + veth; cgroup v2 memory/CPU; JSON Schema + PFC export; parser fuzzing; multi-threaded filter inheritance tests.
