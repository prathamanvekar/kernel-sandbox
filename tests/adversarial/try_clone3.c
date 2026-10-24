#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

/* Expect EPERM (or process kill) under block_process / default-deny without clone3. */
int main(void) {
    struct clone_args args;
    long rc;

    memset(&args, 0, sizeof(args));
    args.flags = 0;
    args.exit_signal = SIGCHLD;
    rc = syscall(__NR_clone3, &args, sizeof(args));
    if (rc < 0) {
        printf("clone3 denied errno=%d (%s)\n", errno, strerror(errno));
        return (errno == EPERM || errno == ENOSYS) ? 0 : 1;
    }
    if (rc == 0) {
        _exit(0);
    }
    printf("UNEXPECTED clone3 succeeded pid=%ld\n", rc);
    return 2;
}
