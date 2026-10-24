#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Under cgroup pids.max=N, creating more than N processes in the cgroup should
 * fail with EAGAIN. Exit 0 if we observe the limit.
 */
int main(void) {
    int i;
    int denied = 0;
    pid_t kids[64];
    int n_kids = 0;

    for (i = 0; i < 64; ++i) {
        pid_t p = fork();
        if (p < 0) {
            printf("fork denied at i=%d errno=%d (%s)\n", i, errno, strerror(errno));
            if (errno == EAGAIN || errno == EPERM) {
                denied = 1;
            }
            break;
        }
        if (p == 0) {
            pause();
            _exit(0);
        }
        kids[n_kids++] = p;
    }

    for (i = 0; i < n_kids; ++i) {
        kill(kids[i], SIGKILL);
        waitpid(kids[i], NULL, 0);
    }

    if (denied) {
        return 0;
    }
    printf("UNEXPECTED: forked %d children without hitting pids.max\n", n_kids);
    return 2;
}
