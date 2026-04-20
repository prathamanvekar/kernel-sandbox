#define _GNU_SOURCE

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <seccomp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_ITEMS 256

typedef struct {
    char *allow[MAX_ITEMS];
    size_t allow_count;
    char *deny[MAX_ITEMS];
    size_t deny_count;
    char *file_access[MAX_ITEMS];
    size_t file_access_count;
    bool network;
    bool block_process;
    bool block_file;
    bool block_info;
    bool enforce_file_access;
    bool kill_on_violation;
    char log_file[PATH_MAX];
} sandbox_policy;

static bool starts_with_path_prefix(const char *path, const char *prefix) {
    size_t prefix_len = strlen(prefix);

    if (strncmp(path, prefix, prefix_len) != 0) {
        return false;
    }
    if (path[prefix_len] == '\0' || path[prefix_len] == '/') {
        return true;
    }
    if (prefix_len > 0 && prefix[prefix_len - 1] == '/') {
        return true;
    }
    return false;
}

static bool make_absolute_path(const char *input, char *out, size_t out_sz) {
    char cwd[PATH_MAX];

    if (!input || !*input) {
        return false;
    }
    if (input[0] == '/') {
        if (snprintf(out, out_sz, "%s", input) >= (int)out_sz) {
            return false;
        }
        return true;
    }
    if (!getcwd(cwd, sizeof(cwd))) {
        return false;
    }
    if (snprintf(out, out_sz, "%s/%s", cwd, input) >= (int)out_sz) {
        return false;
    }
    return true;
}

static char *resolve_program_path(const char *program) {
    char candidate[PATH_MAX];

    if (strchr(program, '/')) {
        if (!make_absolute_path(program, candidate, sizeof(candidate))) {
            return NULL;
        }
        if (access(candidate, X_OK) == 0) {
            return strdup(candidate);
        }
        return NULL;
    }

    {
        const char *path_env = getenv("PATH");
        char *path_dup;
        char *saveptr = NULL;
        char *tok;

        if (!path_env) {
            return NULL;
        }

        path_dup = strdup(path_env);
        if (!path_dup) {
            return NULL;
        }

        tok = strtok_r(path_dup, ":", &saveptr);
        while (tok) {
            if (snprintf(candidate, sizeof(candidate), "%s/%s", tok, program) < (int)sizeof(candidate) &&
                access(candidate, X_OK) == 0) {
                char *resolved = strdup(candidate);
                free(path_dup);
                return resolved;
            }
            tok = strtok_r(NULL, ":", &saveptr);
        }
        free(path_dup);
    }
    return NULL;
}

static bool is_path_like_arg(const char *arg) {
    if (!arg || !*arg) {
        return false;
    }
    if (arg[0] == '/' || strncmp(arg, "./", 2) == 0 || strncmp(arg, "../", 3) == 0) {
        return true;
    }
    return strchr(arg, '/') != NULL;
}

static bool path_allowed_by_policy(const sandbox_policy *policy, const char *path) {
    size_t i;

    if (!policy->enforce_file_access || policy->file_access_count == 0) {
        return true;
    }

    for (i = 0; i < policy->file_access_count; ++i) {
        char allowed_abs[PATH_MAX];
        if (!make_absolute_path(policy->file_access[i], allowed_abs, sizeof(allowed_abs))) {
            continue;
        }
        if (starts_with_path_prefix(path, allowed_abs)) {
            return true;
        }
    }
    return false;
}

static int enforce_file_access_policy(const sandbox_policy *policy, const char *target_exec, int argc, char *argv[]) {
    int i;

    if (!policy->enforce_file_access || policy->file_access_count == 0) {
        return 0;
    }

    if (!path_allowed_by_policy(policy, target_exec)) {
        fprintf(stderr, "[Policy] target executable is outside file_access allowlist: %s\n", target_exec);
        return -1;
    }

    for (i = 3; i < argc; ++i) {
        char arg_abs[PATH_MAX];
        if (!is_path_like_arg(argv[i])) {
            continue;
        }
        if (!make_absolute_path(argv[i], arg_abs, sizeof(arg_abs))) {
            fprintf(stderr, "[Policy] failed to normalize path-like argument: %s\n", argv[i]);
            return -1;
        }
        if (!path_allowed_by_policy(policy, arg_abs)) {
            fprintf(stderr, "[Policy] path argument is outside file_access allowlist: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

static void log_line(const sandbox_policy *policy, const char *fmt, ...) {
    FILE *fp;
    va_list args;
    time_t now;
    struct tm tm_info;
    char ts[64];

    if (!policy || policy->log_file[0] == '\0') {
        return;
    }

    fp = fopen(policy->log_file, "a");
    if (!fp) {
        return;
    }

    now = time(NULL);
    localtime_r(&now, &tm_info);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(fp, "[%s] ", ts);
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    fputc('\n', fp);
    fclose(fp);
}

static void free_policy(sandbox_policy *policy) {
    size_t i;

    for (i = 0; i < policy->allow_count; ++i) {
        free(policy->allow[i]);
    }
    for (i = 0; i < policy->deny_count; ++i) {
        free(policy->deny[i]);
    }
    for (i = 0; i < policy->file_access_count; ++i) {
        free(policy->file_access[i]);
    }
}

static char *read_text_file(const char *path) {
    FILE *fp;
    long size;
    char *buf;

    fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buf = (char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[size] = '\0';
    fclose(fp);
    return buf;
}

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
        ++p;
    }
    return p;
}

static const char *find_key(const char *json, const char *key) {
    char pattern[128];
    const char *p;

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (!p) {
        return NULL;
    }
    p = strchr(p + strlen(pattern), ':');
    if (!p) {
        return NULL;
    }
    return skip_ws(p + 1);
}

static int parse_bool(const char *json, const char *key, bool *value) {
    const char *p = find_key(json, key);
    if (!p) {
        return 0;
    }
    if (strncmp(p, "true", 4) == 0) {
        *value = true;
        return 1;
    }
    if (strncmp(p, "false", 5) == 0) {
        *value = false;
        return 1;
    }
    return -1;
}

static int parse_string(const char *json, const char *key, char *out, size_t out_sz) {
    const char *p = find_key(json, key);
    const char *end;
    size_t n;

    if (!p) {
        return 0;
    }
    if (*p != '"') {
        return -1;
    }
    ++p;
    end = strchr(p, '"');
    if (!end) {
        return -1;
    }
    n = (size_t)(end - p);
    if (n >= out_sz) {
        return -1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int parse_string_array(const char *json, const char *key, char **items, size_t *count) {
    const char *p = find_key(json, key);

    if (!p) {
        *count = 0;
        return 0;
    }
    if (*p != '[') {
        return -1;
    }
    ++p;

    *count = 0;
    for (;;) {
        const char *start;
        const char *end;
        size_t len;
        char *dup;

        p = skip_ws(p);
        if (*p == ']') {
            return 1;
        }
        if (*p != '"') {
            return -1;
        }
        ++p;
        start = p;
        end = strchr(p, '"');
        if (!end) {
            return -1;
        }
        len = (size_t)(end - start);
        if (*count >= MAX_ITEMS) {
            return -1;
        }

        dup = (char *)malloc(len + 1);
        if (!dup) {
            return -1;
        }
        memcpy(dup, start, len);
        dup[len] = '\0';
        items[*count] = dup;
        ++(*count);

        p = skip_ws(end + 1);
        if (*p == ',') {
            ++p;
            continue;
        }
        if (*p == ']') {
            return 1;
        }
        return -1;
    }
}

static int append_syscall_rule(scmp_filter_ctx ctx, const char *name, uint32_t action) {
    int sysno = seccomp_syscall_resolve_name(name);
    if (sysno == __NR_SCMP_ERROR) {
        return -1;
    }
    return seccomp_rule_add(ctx, action, sysno, 0);
}

static int block_network_syscalls(scmp_filter_ctx ctx, uint32_t action) {
    const char *calls[] = {
        "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
        "sendto", "sendmsg", "recvfrom", "recvmsg", "getsockopt", "setsockopt",
        "shutdown", "getpeername", "getsockname"
    };
    size_t i;

    for (i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        if (append_syscall_rule(ctx, calls[i], action) < 0) {
            return -1;
        }
    }
    return 0;
}

static int block_file_syscalls(scmp_filter_ctx ctx, uint32_t action) {
    const char *calls[] = {
        "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir",
        "mkdirat", "rmdir", "chmod", "fchmod", "chown", "fchown", "truncate", "ftruncate"
    };
    size_t i;

    for (i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        int res = append_syscall_rule(ctx, calls[i], action);
        if (res < 0 && strcmp(calls[i], "renameat2") != 0) {
            return -1;
        }
    }
    return 0;
}

static void set_policy_defaults(sandbox_policy *policy) {
    memset(policy, 0, sizeof(*policy));
    policy->network = true;
    policy->enforce_file_access = false;
    policy->kill_on_violation = false;
    snprintf(policy->log_file, sizeof(policy->log_file), "sandbox.log");
}

static int load_policy(const char *policy_path, sandbox_policy *policy) {
    char *json;
    int rc;
    bool b;

    set_policy_defaults(policy);

    json = read_text_file(policy_path);
    if (!json) {
        fprintf(stderr, "[Policy] Failed to read policy file: %s\n", policy_path);
        return -1;
    }

    rc = parse_string_array(json, "allow", policy->allow, &policy->allow_count);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid allow array\n");
        free(json);
        return -1;
    }

    rc = parse_string_array(json, "deny", policy->deny, &policy->deny_count);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid deny array\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    rc = parse_string_array(json, "file_access", policy->file_access, &policy->file_access_count);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid file_access array\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    rc = parse_bool(json, "network", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid network boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->network = b;
    }

    rc = parse_bool(json, "block_process", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid block_process boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->block_process = b;
    }

    rc = parse_bool(json, "block_file", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid block_file boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->block_file = b;
    }

    rc = parse_bool(json, "block_info", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid block_info boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->block_info = b;
    }

    rc = parse_bool(json, "enforce_file_access", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid enforce_file_access boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->enforce_file_access = b;
    }

    rc = parse_bool(json, "kill_on_violation", &b);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid kill_on_violation boolean\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->kill_on_violation = b;
    }

    rc = parse_string(json, "log_file", policy->log_file, sizeof(policy->log_file));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid log_file string\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    free(json);
    return 0;
}

static int apply_policy(scmp_filter_ctx ctx, const sandbox_policy *policy) {
    uint32_t deny_action = policy->kill_on_violation ? SCMP_ACT_KILL_PROCESS : SCMP_ACT_ERRNO(EPERM);
    size_t i;

    printf("[Policy] Applying sandbox rules...\n");

    for (i = 0; i < policy->deny_count; ++i) {
        if (strcmp(policy->deny[i], "execve") == 0 || strcmp(policy->deny[i], "execveat") == 0) {
            printf("[Policy] Skipping deny rule for %s during launcher phase\n", policy->deny[i]);
            continue;
        }
        if (append_syscall_rule(ctx, policy->deny[i], deny_action) < 0) {
            fprintf(stderr, "[Policy] Unknown or unsupported syscall in deny list: %s\n", policy->deny[i]);
            return -1;
        }
    }

    if (!policy->network) {
        printf("[Policy] Network access disabled\n");
        if (block_network_syscalls(ctx, deny_action) < 0) {
            fprintf(stderr, "[Policy] Failed to install network rules\n");
            return -1;
        }
    }

    if (policy->block_process) {
        printf("[Policy] Blocking process creation\n");
        if (append_syscall_rule(ctx, "fork", deny_action) < 0 ||
            append_syscall_rule(ctx, "vfork", deny_action) < 0 ||
            append_syscall_rule(ctx, "clone", deny_action) < 0) {
            fprintf(stderr, "[Policy] Failed to install process rules\n");
            return -1;
        }
    }

    if (policy->block_file) {
        printf("[Policy] Blocking common file mutation syscalls\n");
        if (block_file_syscalls(ctx, deny_action) < 0) {
            fprintf(stderr, "[Policy] Failed to install file rules\n");
            return -1;
        }
    }

    if (policy->block_info) {
        printf("[Policy] Blocking system information syscalls\n");
        if (append_syscall_rule(ctx, "getpid", deny_action) < 0 ||
            append_syscall_rule(ctx, "getppid", deny_action) < 0 ||
            append_syscall_rule(ctx, "uname", deny_action) < 0) {
            fprintf(stderr, "[Policy] Failed to install info rules\n");
            return -1;
        }
    }

    if (policy->file_access_count > 0) {
        printf("[Policy] file_access entries loaded: %zu\n", policy->file_access_count);
        if (policy->enforce_file_access) {
            printf("[Policy] Coarse file_access enforcement enabled for target and path-like argv inputs\n");
        } else {
            printf("[Policy] file_access is informational unless enforce_file_access=true\n");
        }
        printf("[Policy] Note: seccomp cannot inspect path strings directly; use namespace/Landlock for strict path policy.\n");
    }

    (void)policy->allow;
    if (policy->allow_count > 0) {
        printf("[Policy] allow list entries loaded: %zu (informational in deny-by-default mode disabled)\n", policy->allow_count);
    }

    return 0;
}

static int install_filter(const sandbox_policy *policy) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init failed");
        return -1;
    }

    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);

    if (apply_policy(ctx, policy) < 0) {
        seccomp_release(ctx);
        return -1;
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load failed");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return 0;
}

int main(int argc, char *argv[]) {
    sandbox_policy policy;
    char *target_exec;
    char **child_argv;
    pid_t pid;
    int status;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <policy.json> <program> [args...]\n", argv[0]);
        return 1;
    }

    if (load_policy(argv[1], &policy) < 0) {
        return 1;
    }

    target_exec = resolve_program_path(argv[2]);
    if (!target_exec) {
        fprintf(stderr, "[Main] Unable to resolve executable target: %s\n", argv[2]);
        free_policy(&policy);
        return 1;
    }

    if (enforce_file_access_policy(&policy, target_exec, argc, argv) < 0) {
        log_line(&policy, "Denied by file_access policy before execution target=%s", target_exec);
        free(target_exec);
        free_policy(&policy);
        return 1;
    }

    child_argv = (char **)calloc((size_t)(argc - 1), sizeof(char *));
    if (!child_argv) {
        perror("calloc failed");
        free(target_exec);
        free_policy(&policy);
        return 1;
    }
    child_argv[0] = target_exec;
    for (i = 3; i < argc; ++i) {
        child_argv[i - 2] = argv[i];
    }
    child_argv[argc - 2] = NULL;

    printf("\n========== SANDBOX ENGINE START ==========\n");
    printf("[Main] Policy file: %s\n", argv[1]);
    printf("[Main] Target: %s\n", target_exec);

    log_line(&policy, "Starting sandbox policy=%s target=%s", argv[1], argv[2]);

    fflush(NULL);
    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        free_policy(&policy);
        return 1;
    }

    if (pid == 0) {
        printf("[Child] Installing seccomp filter...\n");
        if (install_filter(&policy) < 0) {
            log_line(&policy, "Failed to install seccomp filter");
            free_policy(&policy);
            _exit(1);
        }

        log_line(&policy, "Seccomp filter installed");

        printf("[Child] Executing target\n\n");
        fflush(stdout);
        execv(target_exec, child_argv);

        perror("execv failed");
        log_line(&policy, "execv failed for target=%s errno=%d", target_exec, errno);
        free_policy(&policy);
        _exit(1);
    }

    log_line(&policy, "Forked child pid=%d", pid);

    waitpid(pid, &status, 0);

    printf("\n========== SANDBOX ENGINE END ==========\n");
    if (WIFSIGNALED(status)) {
        printf("[Monitor] Process terminated by signal: %d\n", WTERMSIG(status));
        log_line(&policy, "Process terminated by signal=%d", WTERMSIG(status));
    } else {
        printf("[Monitor] Process exit code: %d\n", WEXITSTATUS(status));
        log_line(&policy, "Process exit code=%d", WEXITSTATUS(status));
    }

    free(child_argv);
    free(target_exec);
    free_policy(&policy);
    return 0;
}
