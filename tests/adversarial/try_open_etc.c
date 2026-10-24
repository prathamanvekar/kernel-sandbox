#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Under Landlock with only ./ and /tmp allowed, opening /etc/passwd must fail. */
int main(void) {
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        printf("open(/etc/passwd) denied errno=%d (%s)\n", errno, strerror(errno));
        /* Landlock typically returns EACCES; seccomp would be EPERM. */
        return (errno == EACCES || errno == EPERM) ? 0 : 1;
    }
    printf("UNEXPECTED open(/etc/passwd) succeeded\n");
    close(fd);
    return 2;
}
