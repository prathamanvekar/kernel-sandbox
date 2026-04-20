# Demo Suite Report

- suite_id: suite-2026-04-20_19-54-01-baseline-restrictive-no-file-network-wl-ci-smoke
- workload_label: ci-smoke
- scenario_baseline_exit: 0
- scenario_restrictive_exit: 0
- scenario_no_file_network_exit: 0

## Scenario 1: Baseline ./test

```text
=== Test Program Started ===
[OK] write syscall works
[OK] Sleeping for 1 second...
[TEST] Trying file open...
[INFO] open result: No such file or directory
[TEST] Calling getpid()...
[INFO] PID result: 15889 (blocked policy may deny this call)
[TEST] Trying fork()...
[TEST] Trying socket()...
[UNEXPECTED] socket created
[END] Finished
[UNEXPECTED] child process created
```

## Scenario 2: Restrictive Policy

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
[INFO] open result: No such file or directory
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

## Scenario 3: No File + Network Policy

```text

========== SANDBOX ENGINE START ==========
[Main] Policy file: policies/no-file-network.json
[Main] Target: /home/pratham/workspace/academic/os/project-extra/./test
[Child] Installing seccomp filter...
[Policy] Applying sandbox rules...
[Policy] Network access disabled
[Policy] Blocking common file mutation syscalls
[Policy] file_access entries loaded: 2
[Policy] Coarse file_access enforcement enabled for target and path-like argv inputs
[Policy] Note: seccomp cannot inspect path strings directly; use namespace/Landlock for strict path policy.
[Child] Executing target

=== Test Program Started ===
[OK] write syscall works
[OK] Sleeping for 1 second...
[TEST] Trying file open...
[INFO] open result: No such file or directory
[TEST] Calling getpid()...
[INFO] PID result: 15894 (blocked policy may deny this call)
[TEST] Trying fork()...
[TEST] Trying socket()...
[INFO] socket result: Operation not permitted
[END] Finished
[UNEXPECTED] child process created

========== SANDBOX ENGINE END ==========
[Monitor] Process exit code: 0
```
