#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>

/* Theater: pretends to wrap open. Cannot bypass Landlock/seccomp. */
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    mode_t mode = 0;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
    }
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        return real_open(pathname, flags, mode);
    }
    fprintf(stderr, "[fake_preload] open(%s) forwarded to libc; kernel still enforces\n",
            pathname);
    return real_open(pathname, flags);
}
