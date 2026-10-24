#define _GNU_SOURCE
#include <linux/landlock.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        return 1;
    }
    printf("landlock_abi=%d\n", abi);
    return 0;
}
