CC := gcc
CFLAGS := -Wall -Wextra -Werror -O2
LDFLAGS := -lseccomp
POLICY ?= policies/restrictive.json
TARGET ?= ./test
REPORT_ARGS ?=

.PHONY: all clean report gui demo-suite benchmark

all: sandbox-run test

sandbox-run: sandbox.c
	$(CC) $(CFLAGS) sandbox.c -o sandbox-run $(LDFLAGS)

test: test.c
	$(CC) $(CFLAGS) test.c -o test

clean:
	rm -f sandbox-run test sandbox.log

report: all
	./scripts/run_with_report.sh $(POLICY) $(TARGET) $(REPORT_ARGS)

gui:
	python3 gui/server.py

demo-suite: all
	./scripts/run_demo_suite.sh

benchmark: all
	./scripts/benchmark.sh $(POLICY) $(TARGET) $(REPORT_ARGS)
