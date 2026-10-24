#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    pid_t p = fork();
    if (p < 0) {
        printf("fork denied errno=%d (%s)\n", errno, strerror(errno));
        return errno == EPERM ? 0 : 1;
    }
    if (p == 0) {
        _exit(0);
    }
    printf("UNEXPECTED fork succeeded\n");
    return 2;
}
