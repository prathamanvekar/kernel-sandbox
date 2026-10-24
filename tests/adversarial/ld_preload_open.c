#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * Negative control: even if an LD_PRELOAD wrapper tried to "allow" open,
 * kernel Landlock/seccomp still decide. This binary just attempts the open;
 * the companion shared object is optional. Success of open means the sandbox
 * did not enforce path policy.
 */
int main(void) {
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        printf("kernel denied open despite any userspace interposition errno=%d (%s)\n",
               errno, strerror(errno));
        return (errno == EACCES || errno == EPERM) ? 0 : 1;
    }
    printf("UNEXPECTED open succeeded (LD_PRELOAD is not a security boundary)\n");
    close(fd);
    return 2;
}
