#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Cycle/instruction counters via perf_event_open for the same microloops. */

static long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int open_counter(__u32 type, __u64 config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1; /* enable explicitly around the measured loop */
    attr.exclude_kernel = 0; /* include kernel time in syscall cost */
    attr.exclude_hv = 1;
    return (int)perf_event_open(&attr, 0, -1, -1, 0);
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <getpid|openclose> [iters=100000]\n", argv0);
}

int main(int argc, char *argv[]) {
    const char *mode;
    size_t iters = 100000;
    size_t i;
    int fd_cycles; /* PERF_COUNT_HW_CPU_CYCLES group leader fd */
    int fd_instr; /* PERF_COUNT_HW_INSTRUCTIONS counter fd */
    uint64_t cycles = 0;
    uint64_t instr = 0;
    volatile long sink = 0; /* keep measured syscalls from being optimized out */

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    mode = argv[1];
    if (argc >= 3) {
        iters = (size_t)strtoul(argv[2], NULL, 10);
    }

    fd_cycles = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    fd_instr = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
    if (fd_cycles < 0 || fd_instr < 0) {
        fprintf(stderr, "perf_event_open failed (errno=%d). Skipping counters.\n", errno);
        printf("mode=%s iters=%zu cycles=NA instructions=NA note=perf_unavailable\n", mode,
               iters);
        return 0;
    }

    ioctl(fd_cycles, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd_instr, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
    ioctl(fd_instr, PERF_EVENT_IOC_ENABLE, 0);

    if (strcmp(mode, "getpid") == 0) {
        for (i = 0; i < iters; ++i) {
            sink += (long)syscall(SYS_getpid);
        }
    } else if (strcmp(mode, "openclose") == 0) {
        for (i = 0; i < iters; ++i) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd >= 0) {
                close(fd);
            }
        }
    } else {
        usage(argv[0]);
        return 2;
    }

    ioctl(fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
    ioctl(fd_instr, PERF_EVENT_IOC_DISABLE, 0);
    if (read(fd_cycles, &cycles, sizeof(cycles)) != sizeof(cycles)) {
        cycles = 0;
    }
    if (read(fd_instr, &instr, sizeof(instr)) != sizeof(instr)) {
        instr = 0;
    }
    close(fd_cycles);
    close(fd_instr);

    printf("mode=%s iters=%zu cycles=%llu instructions=%llu per_op_cycles=%.2f "
           "per_op_instr=%.2f sink=%ld\n",
           mode, iters, (unsigned long long)cycles, (unsigned long long)instr,
           (double)cycles / (double)iters, (double)instr / (double)iters, (long)sink);
    return 0;
}
