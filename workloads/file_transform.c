#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Curated allowlist workload: open/read/write/close a pair of files, then exit. */
int main(int argc, char *argv[]) {
    char buf[4096];
    int in_fd;
    int out_fd;
    ssize_t n;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <in> <out>\n", argv[0]);
        return 2;
    }

    in_fd = open(argv[1], O_RDONLY);
    if (in_fd < 0) {
        fprintf(stderr, "open in: %s\n", strerror(errno));
        return 1;
    }
    out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fprintf(stderr, "open out: %s\n", strerror(errno));
        close(in_fd);
        return 1;
    }

    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out_fd, buf + off, (size_t)(n - off));
            if (w < 0) {
                fprintf(stderr, "write: %s\n", strerror(errno));
                close(in_fd);
                close(out_fd);
                return 1;
            }
            off += w;
        }
    }
    if (n < 0) {
        fprintf(stderr, "read: %s\n", strerror(errno));
        close(in_fd);
        close(out_fd);
        return 1;
    }

    close(in_fd);
    close(out_fd);
    return 0;
}
