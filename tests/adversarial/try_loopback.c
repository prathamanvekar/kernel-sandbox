#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Positive control for netns loopback-up: connect to 127.0.0.1 should reach the
 * stack (ECONNREFUSED if nothing listens) rather than ENETUNREACH (lo down /
 * no local route).
 */
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    int rc;

    if (fd < 0) {
        printf("socket failed errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9); /* discard; typically closed */
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        printf("loopback connect unexpectedly succeeded (service listening?)\n");
        close(fd);
        return 0; /* still proves lo works */
    }
    printf("loopback connect errno=%d (%s)\n", errno, strerror(errno));
    close(fd);
    if (errno == ECONNREFUSED || errno == ETIMEDOUT) {
        return 0;
    }
    if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
        printf("loopback appears down or unroutable\n");
        return 2;
    }
    return 1;
}
