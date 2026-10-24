CC := gcc
CFLAGS := -Wall -Wextra -Werror -O2
LDFLAGS := -lseccomp -lcap
POLICY ?= policies/restrictive.json
TARGET ?= ./test
REPORT_ARGS ?=

ADVERSARIAL_BINS := \
	tests/adversarial/try_clone3 \
	tests/adversarial/try_socket \
	tests/adversarial/try_open_etc \
	tests/adversarial/try_fork \
	tests/adversarial/ld_preload_open \
	tests/adversarial/landlock_probe \
	tests/adversarial/try_egress \
	tests/adversarial/try_loopback \
	tests/adversarial/try_pids_limit

.PHONY: all clean report gui demo-suite benchmark check check-bins microbench metrics

all: sandbox-run test workloads/file_transform bench/micro_syscall bench/perf_cycles

sandbox-run: sandbox.c
	$(CC) $(CFLAGS) sandbox.c -o sandbox-run $(LDFLAGS)

test: test.c
	$(CC) $(CFLAGS) test.c -o test

workloads/file_transform: workloads/file_transform.c
	$(CC) $(CFLAGS) $< -o $@

bench/micro_syscall: bench/micro_syscall.c
	$(CC) $(CFLAGS) $< -o $@

bench/perf_cycles: bench/perf_cycles.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_clone3: tests/adversarial/try_clone3.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_socket: tests/adversarial/try_socket.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_open_etc: tests/adversarial/try_open_etc.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_fork: tests/adversarial/try_fork.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/ld_preload_open: tests/adversarial/ld_preload_open.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/landlock_probe: tests/adversarial/landlock_probe.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_egress: tests/adversarial/try_egress.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_loopback: tests/adversarial/try_loopback.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/try_pids_limit: tests/adversarial/try_pids_limit.c
	$(CC) $(CFLAGS) $< -o $@

tests/adversarial/libfake_preload.so: tests/adversarial/fake_preload.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@ -ldl

check-bins: $(ADVERSARIAL_BINS) tests/adversarial/libfake_preload.so workloads/file_transform

check: all check-bins
	chmod +x tests/run_check.sh tests/adversarial/cgroup_probe.sh \
		scripts/run_microbench.sh scripts/collect_metrics.sh scripts/setup_cgroup_root.sh
	./tests/run_check.sh

microbench: all
	chmod +x scripts/run_microbench.sh
	./scripts/run_microbench.sh

metrics: all check-bins
	chmod +x scripts/collect_metrics.sh scripts/run_microbench.sh
	./scripts/collect_metrics.sh

clean:
	rm -f sandbox-run test sandbox.log sandbox.jsonl
	rm -f workloads/file_transform bench/micro_syscall bench/perf_cycles
	rm -f $(ADVERSARIAL_BINS) tests/adversarial/libfake_preload.so

report: all
	./scripts/run_with_report.sh $(POLICY) $(TARGET) $(REPORT_ARGS)

gui:
	python3 gui/server.py

demo-suite: all
	./scripts/run_demo_suite.sh

benchmark: all
	./scripts/benchmark.sh $(POLICY) $(TARGET) $(REPORT_ARGS)
