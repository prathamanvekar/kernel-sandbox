# Measured metrics

Collected: 2026-10-24T08:09:21.259756Z

Host: Linux-6.12.94+-x86_64-with-glibc2.39

Kernel: 6.12.94+

CPU: Intel(R) Xeon(R) Processor

nproc: 4

## Attach latency (cold launch to filter ready)

Policy: `policies/basic.json`, target: `/bin/true`, N=40 (requested 40), pinned with `taskset -c 0` when available.

| metric | value |
| --- | --- |
| attach p50 | 196.849 µs |
| attach p99 | 495.779 µs |

## Syscall microloops (bare vs sandboxed basic)

Samples=80, iters/sample=2000.

| label | mode | p50 ns/sample | p99 ns/sample | per-op p50 ns | per-op p99 ns |
| --- | --- | --- | --- | --- | --- |
| BARE getpid | getpid | 121010 | 232676 | 60.51 | 116.34 |
| SANDBOX getpid | getpid | 140195 | 189728 | 70.10 | 94.86 |
| BARE openclose | openclose | 1236355 | 1389252 | 618.18 | 694.63 |
| SANDBOX openclose | openclose | 1273651 | 1998595 | 636.83 | 999.30 |
| BARE write | write | 149054 | 174885 | 74.53 | 87.44 |
| SANDBOX write | write | 166952 | 182507 | 83.48 | 91.25 |

## perf_event_open companion

| label | mode | cycles | instructions | per-op cycles | note |
| --- | --- | --- | --- | --- | --- |
| BARE getpid | getpid | NA | NA |  | perf_unavailable |
| SANDBOX getpid | getpid | NA | NA |  | perf_unavailable |
| BARE openclose | openclose | NA | NA |  | perf_unavailable |
| SANDBOX openclose | openclose | NA | NA |  | perf_unavailable |

## Correctness gates

| gate | result |
| --- | --- |
| make check pass/fail/skip | 8/0/0 |
| adversarial true-deny rate | 100.0% (4/4) |
| curated false-deny success | 100.0% (2/2) |

## Raw check log

```
[PASS] false-deny: strict-allow file_transform
[PASS] false-deny: output content matches
[PASS] true-deny: fork under restrictive
[PASS] true-deny: socket under restrictive
[PASS] true-deny: clone3 under restrictive
[PASS] true-deny: Landlock blocks /etc/passwd
[PASS] LD_PRELOAD cannot bypass Landlock/seccomp path deny
[PASS] mount-ns + pivot_root smoke with strict-allow

Summary: pass=8 fail=0 skip=0
```

