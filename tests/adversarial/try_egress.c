#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Under --net-ns=loopback|veth-deny there is no default route / no external
 * connectivity. connect() to a public address should fail (typically
 * ENETUNREACH). Exit 0 on expected deny.
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
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        printf("UNEXPECTED connect(1.1.1.1:80) succeeded\n");
        close(fd);
        return 2;
    }
    printf("egress denied errno=%d (%s)\n", errno, strerror(errno));
    close(fd);
    /* ENETUNREACH / EHOSTUNREACH / ENETDOWN are the expected isolation signals. */
    if (errno == ENETUNREACH || errno == EHOSTUNREACH || errno == ENETDOWN || errno == EINVAL) {
        return 0;
    }
    return 1;
}
