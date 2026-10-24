#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/*
 * Tight syscall microloops for honest overhead measurement.
 * Reports p50/p99 over N samples (each sample = iters syscalls).
 */

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a;
    int64_t y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static void percentile(int64_t *samples, size_t n, int64_t *p50, int64_t *p99) {
    qsort(samples, n, sizeof(int64_t), cmp_i64);
    *p50 = samples[n / 2];
    *p99 = samples[(n * 99) / 100];
    if (*p99 < samples[n - 1] && (n * 99) / 100 < n - 1) {
        /* keep qsort index */
    }
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s <getpid|openclose|write> [samples=100] [iters=1000]\n",
            argv0);
}

int main(int argc, char *argv[]) {
    const char *mode;
    size_t samples = 100;
    size_t iters = 1000;
    size_t i, s;
    int64_t *times;
    int64_t p50, p99;
    volatile long sink = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    mode = argv[1];
    if (argc >= 3) {
        samples = (size_t)strtoul(argv[2], NULL, 10);
    }
    if (argc >= 4) {
        iters = (size_t)strtoul(argv[3], NULL, 10);
    }
    if (samples < 10 || iters < 1) {
        fprintf(stderr, "samples must be >= 10 and iters >= 1\n");
        return 2;
    }

    times = calloc(samples, sizeof(int64_t));
    if (!times) {
        return 1;
    }

    /* Warmup */
    for (i = 0; i < iters; ++i) {
        if (strcmp(mode, "getpid") == 0) {
            sink += (long)syscall(SYS_getpid);
        } else if (strcmp(mode, "openclose") == 0) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd >= 0) {
                close(fd);
            }
        } else if (strcmp(mode, "write") == 0) {
            int wfd = open("/dev/null", O_WRONLY);
            if (wfd >= 0) {
                sink += (long)write(wfd, "x", 1);
                close(wfd);
            }
        }
    }

    if (strcmp(mode, "write") == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) {
            perror("open /dev/null");
            free(times);
            return 1;
        }
        for (s = 0; s < samples; ++s) {
            int64_t t0 = now_ns();
            for (i = 0; i < iters; ++i) {
                if (write(fd, "x", 1) != 1) {
                    sink++;
                }
            }
            times[s] = now_ns() - t0;
        }
        close(fd);
    } else if (strcmp(mode, "getpid") == 0) {
        for (s = 0; s < samples; ++s) {
            int64_t t0 = now_ns();
            for (i = 0; i < iters; ++i) {
                sink += (long)syscall(SYS_getpid);
            }
            times[s] = now_ns() - t0;
        }
    } else if (strcmp(mode, "openclose") == 0) {
        for (s = 0; s < samples; ++s) {
            int64_t t0 = now_ns();
            for (i = 0; i < iters; ++i) {
                int fd = open("/dev/null", O_RDONLY);
                if (fd >= 0) {
                    close(fd);
                } else {
                    sink++;
                }
            }
            times[s] = now_ns() - t0;
        }
    } else {
        usage(argv[0]);
        free(times);
        return 2;
    }

    percentile(times, samples, &p50, &p99);
    printf("mode=%s samples=%zu iters=%zu p50_ns=%lld p99_ns=%lld per_op_p50_ns=%.2f "
           "per_op_p99_ns=%.2f sink=%ld\n",
           mode, samples, iters, (long long)p50, (long long)p99,
           (double)p50 / (double)iters, (double)p99 / (double)iters, (long)sink);

    free(times);
    return 0;
}
