#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket denied errno=%d (%s)\n", errno, strerror(errno));
        return errno == EPERM ? 0 : 1;
    }
    printf("UNEXPECTED socket succeeded\n");
    close(fd);
    return 2;
}
