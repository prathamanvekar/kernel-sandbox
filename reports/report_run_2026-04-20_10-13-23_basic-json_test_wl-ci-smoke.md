# Sandbox Run Report

- run_id: run-2026-04-20_10-13-23-basic-json-test-wl-ci-smoke
- policy: policies/basic.json
- program: ./test
- workload_label: ci-smoke
- args: <none>
- start_time: 2026-04-20 10:13:23
- end_time: 2026-04-20 10:13:24
- exit_code: 0
- child_pid: 2972
- seccomp_kernel_events: 0
- operation_not_permitted_count: 0
- runtime_denial_markers: 0
- violation_score: 0

## Program Stdout

```text

========== SANDBOX ENGINE START ==========
[Main] Policy file: policies/basic.json
[Main] Target: /home/pratham/workspace/academic/os/project-extra/./test
[Child] Installing seccomp filter...
[Policy] Applying sandbox rules...
[Policy] Skipping deny rule for execveat during launcher phase
[Policy] file_access entries loaded: 2
[Policy] file_access is informational unless enforce_file_access=true
[Policy] Note: seccomp cannot inspect path strings directly; use namespace/Landlock for strict path policy.
[Child] Executing target

=== Test Program Started ===
[OK] write syscall works
[OK] Sleeping for 1 second...
[TEST] Trying file open...
[TEST] Calling getpid()...
[INFO] PID result: 2972 (blocked policy may deny this call)
[TEST] Trying fork()...
[TEST] Trying socket()...
[UNEXPECTED] socket created
[END] Finished
[UNEXPECTED] child process created

========== SANDBOX ENGINE END ==========
[Monitor] Process exit code: 0
```

## Program Stderr

```text
[INFO] open result: No such file or directory
```

## Sandbox Log Slice

```text
[2026-04-20 10:13:23] REPORT_START run_id=run-2026-04-20_10-13-23-basic-json-test-wl-ci-smoke policy=policies/basic.json program=./test args=
[2026-04-20 10:13:23] Starting sandbox policy=policies/basic.json target=./test
[2026-04-20 10:13:23] Forked child pid=2972
[2026-04-20 10:13:23] Seccomp filter installed
[2026-04-20 10:13:24] Process exit code=0
[2026-04-20 10:13:24] REPORT_END run_id=run-2026-04-20_10-13-23-basic-json-test-wl-ci-smoke exit_code=0
```

## Kernel Seccomp Correlation

No kernel seccomp entries found or access to kernel logs is restricted.
