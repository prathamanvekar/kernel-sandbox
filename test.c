#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

int main() {
    pid_t child;
    int sockfd;
    setbuf(stdout, NULL);

    printf("=== Test Program Started ===\n");

    // Allowed syscall
    printf("[OK] write syscall works\n");

    // Allowed syscall
    printf("[OK] Sleeping for 1 second...\n");
    sleep(1);

    // File access test
    printf("[TEST] Trying file open...\n");
    int fd = open("test.txt", O_RDONLY);
    if (fd < 0) {
        perror("[INFO] open result");
    } else {
        printf("[OK] File opened successfully\n");
        close(fd);
    }

    // Blocked syscall
    printf("[TEST] Calling getpid()...\n");
    pid_t pid = getpid();

    printf("[INFO] PID result: %d (blocked policy may deny this call)\n", pid);

    printf("[TEST] Trying fork()...\n");
    child = fork();
    if (child < 0) {
        printf("[INFO] fork result: %s\n", strerror(errno));
    } else if (child == 0) {
        printf("[UNEXPECTED] child process created\n");
        _exit(0);
    }

    printf("[TEST] Trying socket()...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("[INFO] socket result: %s\n", strerror(errno));
    } else {
        printf("[UNEXPECTED] socket created\n");
        close(sockfd);
    }

    printf("[END] Finished\n");
    return 0;
}
