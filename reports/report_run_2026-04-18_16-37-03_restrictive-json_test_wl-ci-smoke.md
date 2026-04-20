# Sandbox Run Report

- run_id: run-2026-04-18_16-37-03-restrictive-json-test-wl-ci-smoke
- policy: policies/restrictive.json
- program: ./test
- workload_label: ci-smoke
- args: <none>
- start_time: 2026-04-18 16:37:03
- end_time: 2026-04-18 16:37:04
- exit_code: 0
- child_pid: 33101
- seccomp_kernel_events: 0
- operation_not_permitted_count: 2
- runtime_denial_markers: 0
- violation_score: 2

## Program Stdout

```text

========== SANDBOX ENGINE START ==========
[Main] Policy file: policies/restrictive.json
[Main] Target: /home/pratham/workspace/academic/os/project-extra/./test
[Child] Installing seccomp filter...
[Policy] Applying sandbox rules...
[Policy] Network access disabled
[Policy] Blocking process creation
[Policy] Blocking system information syscalls
[Policy] file_access entries loaded: 2
[Policy] Coarse file_access enforcement enabled for target and path-like argv inputs
[Policy] Note: seccomp cannot inspect path strings directly; use namespace/Landlock for strict path policy.
[Policy] allow list entries loaded: 4 (informational in deny-by-default mode disabled)
[Child] Executing target

=== Test Program Started ===
[OK] write syscall works
[OK] Sleeping for 1 second...
[TEST] Trying file open...
[TEST] Calling getpid()...
[INFO] PID result: -1 (blocked policy may deny this call)
[TEST] Trying fork()...
[INFO] fork result: Operation not permitted
[TEST] Trying socket()...
[INFO] socket result: Operation not permitted
[END] Finished

========== SANDBOX ENGINE END ==========
[Monitor] Process exit code: 0
```

## Program Stderr

```text
[INFO] open result: No such file or directory
```

## Sandbox Log Slice

```text
[2026-04-18 16:37:03] REPORT_START run_id=run-2026-04-18_16-37-03-restrictive-json-test-wl-ci-smoke policy=policies/restrictive.json program=./test args=
[2026-04-18 16:37:03] Starting sandbox policy=policies/restrictive.json target=./test
[2026-04-18 16:37:03] Forked child pid=33101
[2026-04-18 16:37:03] Seccomp filter installed
[2026-04-18 16:37:04] Process exit code=0
[2026-04-18 16:37:04] REPORT_END run_id=run-2026-04-18_16-37-03-restrictive-json-test-wl-ci-smoke exit_code=0
```

## Kernel Seccomp Correlation

No kernel seccomp entries found or access to kernel logs is restricted.
