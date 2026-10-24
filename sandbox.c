#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/close_range.h>
#include <linux/landlock.h>
#include <sched.h>
#include <seccomp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
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
    bool default_deny;
    bool landlock;
    bool drop_caps;
    bool mount_ns;
    bool pid_ns;
    bool close_fds;
    bool cgroup;
    long rlimit_as_mb;
    long rlimit_nofile;
    long rlimit_nproc;
    long cgroup_pids_max;
    char net_ns_mode[32]; /* "", "loopback", "veth-deny" */
    char cgroup_root[PATH_MAX];
    char cgroup_memory_max[64];
    char cgroup_cpu_max[64]; /* e.g. "10000 100000" or "max" */
    char log_file[PATH_MAX];
    char audit_jsonl[PATH_MAX];
} sandbox_policy;

typedef struct {
    const sandbox_policy *policy;
    char *target_exec;
    char **child_argv;
    int ready_fd;
    int map_sync_fd; /* bidirectional sync for userns maps when required */
    int cgroup_gate_fd; /* child blocks until parent finishes cgroup attach */
    char run_id[64];
    const char *policy_path;
} child_ctx;

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                                   size_t size, __u32 flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
                             const void *attr, __u32 flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static int landlock_restrict_self(int ruleset_fd, __u32 flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

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
    char tmp[PATH_MAX];
    char resolved[PATH_MAX];

    if (!input || !*input) {
        return false;
    }
    if (input[0] == '/') {
        if (snprintf(tmp, sizeof(tmp), "%s", input) >= (int)sizeof(tmp)) {
            return false;
        }
    } else {
        if (!getcwd(cwd, sizeof(cwd))) {
            return false;
        }
        if (snprintf(tmp, sizeof(tmp), "%s/%s", cwd, input) >= (int)sizeof(tmp)) {
            return false;
        }
    }
    if (realpath(tmp, resolved)) {
        if (snprintf(out, out_sz, "%s", resolved) >= (int)out_sz) {
            return false;
        }
        return true;
    }
    /* Path may not exist yet (output files); keep lexical absolute form. */
    if (snprintf(out, out_sz, "%s", tmp) >= (int)out_sz) {
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

static int64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static void audit_jsonl(const sandbox_policy *policy, const char *run_id, const char *event,
                        pid_t pid, const char *extra_fmt, ...) {
    FILE *fp;
    va_list args;
    int64_t ts = now_ns();

    if (!policy || policy->audit_jsonl[0] == '\0') {
        return;
    }

    fp = fopen(policy->audit_jsonl, "a");
    if (!fp) {
        return;
    }

    fprintf(fp,
            "{\"event\":\"%s\",\"ts_ns\":%" PRId64 ",\"run_id\":\"%s\",\"pid\":%d",
            event, ts, run_id ? run_id : "", (int)pid);
    if (extra_fmt && extra_fmt[0]) {
        fputc(',', fp);
        va_start(args, extra_fmt);
        vfprintf(fp, extra_fmt, args);
        va_end(args);
    }
    fputs("}\n", fp);
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

static int parse_long(const char *json, const char *key, long *value) {
    const char *p = find_key(json, key);
    char *end = NULL;
    long v;

    if (!p) {
        return 0;
    }
    errno = 0;
    v = strtol(p, &end, 10);
    if (errno != 0 || end == p) {
        return -1;
    }
    *value = v;
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

static int block_process_syscalls(scmp_filter_ctx ctx, uint32_t action) {
    const char *calls[] = {"fork", "vfork", "clone", "clone3"};
    size_t i;

    for (i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        int res = append_syscall_rule(ctx, calls[i], action);
        /* clone3 may be absent on older libseccomp/kernel pairings */
        if (res < 0 && strcmp(calls[i], "clone3") != 0) {
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
    policy->default_deny = false;
    policy->landlock = false;
    policy->drop_caps = true;
    policy->mount_ns = false;
    policy->pid_ns = false;
    policy->close_fds = true;
    policy->cgroup = false;
    policy->rlimit_as_mb = -1;
    policy->rlimit_nofile = -1;
    policy->rlimit_nproc = -1;
    policy->cgroup_pids_max = -1;
    policy->net_ns_mode[0] = '\0';
    policy->cgroup_root[0] = '\0';
    policy->cgroup_memory_max[0] = '\0';
    policy->cgroup_cpu_max[0] = '\0';
    snprintf(policy->log_file, sizeof(policy->log_file), "sandbox.log");
    policy->audit_jsonl[0] = '\0';
}

static int load_policy(const char *policy_path, sandbox_policy *policy) {
    char *json;
    int rc;
    bool b;
    long lv;

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

#define PARSE_BOOL_FIELD(name, field)                                                              \
    do {                                                                                           \
        rc = parse_bool(json, name, &b);                                                           \
        if (rc < 0) {                                                                              \
            fprintf(stderr, "[Policy] Invalid %s boolean\n", name);                                \
            free_policy(policy);                                                                   \
            free(json);                                                                            \
            return -1;                                                                             \
        }                                                                                          \
        if (rc > 0) {                                                                              \
            policy->field = b;                                                                     \
        }                                                                                          \
    } while (0)

    PARSE_BOOL_FIELD("network", network);
    PARSE_BOOL_FIELD("block_process", block_process);
    PARSE_BOOL_FIELD("block_file", block_file);
    PARSE_BOOL_FIELD("block_info", block_info);
    PARSE_BOOL_FIELD("enforce_file_access", enforce_file_access);
    PARSE_BOOL_FIELD("kill_on_violation", kill_on_violation);
    PARSE_BOOL_FIELD("default_deny", default_deny);
    PARSE_BOOL_FIELD("landlock", landlock);
    PARSE_BOOL_FIELD("drop_caps", drop_caps);
    PARSE_BOOL_FIELD("mount_ns", mount_ns);
    PARSE_BOOL_FIELD("pid_ns", pid_ns);
    PARSE_BOOL_FIELD("close_fds", close_fds);
    PARSE_BOOL_FIELD("cgroup", cgroup);
#undef PARSE_BOOL_FIELD

    rc = parse_string(json, "net_ns", policy->net_ns_mode, sizeof(policy->net_ns_mode));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid net_ns string (use \"\", \"loopback\", or \"veth-deny\")\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        if (strcmp(policy->net_ns_mode, "off") == 0 || strcmp(policy->net_ns_mode, "false") == 0) {
            policy->net_ns_mode[0] = '\0';
        } else if (strcmp(policy->net_ns_mode, "loopback") != 0 &&
                   strcmp(policy->net_ns_mode, "veth-deny") != 0 && policy->net_ns_mode[0] != '\0') {
            fprintf(stderr, "[Policy] Unsupported net_ns mode: %s\n", policy->net_ns_mode);
            free_policy(policy);
            free(json);
            return -1;
        }
    }

    rc = parse_string(json, "cgroup_root", policy->cgroup_root, sizeof(policy->cgroup_root));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid cgroup_root\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    rc = parse_string(json, "cgroup_memory_max", policy->cgroup_memory_max,
                      sizeof(policy->cgroup_memory_max));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid cgroup_memory_max\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    rc = parse_string(json, "cgroup_cpu_max", policy->cgroup_cpu_max, sizeof(policy->cgroup_cpu_max));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid cgroup_cpu_max\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    rc = parse_long(json, "cgroup_pids_max", &lv);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid cgroup_pids_max\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->cgroup_pids_max = lv;
    }

    rc = parse_long(json, "rlimit_as_mb", &lv);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid rlimit_as_mb\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->rlimit_as_mb = lv;
    }

    rc = parse_long(json, "rlimit_nofile", &lv);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid rlimit_nofile\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->rlimit_nofile = lv;
    }

    rc = parse_long(json, "rlimit_nproc", &lv);
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid rlimit_nproc\n");
        free_policy(policy);
        free(json);
        return -1;
    }
    if (rc > 0) {
        policy->rlimit_nproc = lv;
    }

    rc = parse_string(json, "log_file", policy->log_file, sizeof(policy->log_file));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid log_file string\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    rc = parse_string(json, "audit_jsonl", policy->audit_jsonl, sizeof(policy->audit_jsonl));
    if (rc < 0) {
        fprintf(stderr, "[Policy] Invalid audit_jsonl string\n");
        free_policy(policy);
        free(json);
        return -1;
    }

    free(json);
    return 0;
}

static int apply_compat_denies(scmp_filter_ctx ctx, const sandbox_policy *policy,
                               uint32_t deny_action) {
    size_t i;

    for (i = 0; i < policy->deny_count; ++i) {
        if (strcmp(policy->deny[i], "execve") == 0 || strcmp(policy->deny[i], "execveat") == 0) {
            printf("[Policy] Skipping deny rule for %s during launcher phase\n", policy->deny[i]);
            continue;
        }
        if (append_syscall_rule(ctx, policy->deny[i], deny_action) < 0) {
            fprintf(stderr, "[Policy] Unknown or unsupported syscall in deny list: %s\n",
                    policy->deny[i]);
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
        printf("[Policy] Blocking process creation (fork/vfork/clone/clone3)\n");
        if (block_process_syscalls(ctx, deny_action) < 0) {
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

    return 0;
}

static int apply_default_deny_allows(scmp_filter_ctx ctx, const sandbox_policy *policy) {
    size_t i;
    bool saw_execve = false;

    if (policy->allow_count == 0) {
        fprintf(stderr, "[Policy] default_deny requires a non-empty allow list\n");
        return -1;
    }

    printf("[Policy] Default-deny mode: installing %zu allow rules\n", policy->allow_count);
    for (i = 0; i < policy->allow_count; ++i) {
        if (strcmp(policy->allow[i], "execve") == 0) {
            saw_execve = true;
        }
        if (append_syscall_rule(ctx, policy->allow[i], SCMP_ACT_ALLOW) < 0) {
            fprintf(stderr, "[Policy] Unknown or unsupported syscall in allow list: %s\n",
                    policy->allow[i]);
            return -1;
        }
    }

    /* Launcher still needs to exec the target after filter load. */
    if (!saw_execve) {
        if (append_syscall_rule(ctx, "execve", SCMP_ACT_ALLOW) < 0) {
            fprintf(stderr, "[Policy] Failed to allow execve for launcher transition\n");
            return -1;
        }
        printf("[Policy] Implicitly allowed execve for launcher transition\n");
    }

    /* Compat deny overlays are redundant under default-deny (same action as the
     * filter default) and libseccomp rejects those rule adds. The allow list is
     * the source of truth; keep block_* / network flags as documentation. */
    if (!policy->network) {
        printf("[Policy] network=false (syscalls remain denied unless listed in allow)\n");
    }
    if (policy->block_process) {
        printf("[Policy] block_process=true (fork/clone/clone3 denied unless listed in allow)\n");
    }

    return 0;
}

static int apply_policy(scmp_filter_ctx ctx, const sandbox_policy *policy) {
    uint32_t deny_action = policy->kill_on_violation ? SCMP_ACT_KILL_PROCESS : SCMP_ACT_ERRNO(EPERM);

    printf("[Policy] Applying sandbox rules (default_deny=%s, action=%s)...\n",
           policy->default_deny ? "true" : "false",
           policy->kill_on_violation ? "KILL_PROCESS" : "ERRNO(EPERM)");

    if (policy->default_deny) {
        if (apply_default_deny_allows(ctx, policy) < 0) {
            return -1;
        }
    } else {
        if (apply_compat_denies(ctx, policy, deny_action) < 0) {
            return -1;
        }
        if (policy->allow_count > 0) {
            printf("[Policy] allow list entries loaded: %zu (informational in compat mode; "
                   "set default_deny=true to install them)\n",
                   policy->allow_count);
        }
    }

    if (policy->file_access_count > 0) {
        printf("[Policy] file_access entries loaded: %zu\n", policy->file_access_count);
        if (policy->enforce_file_access) {
            printf("[Policy] Pre-exec argv path checks enabled (defense-in-depth)\n");
        }
        if (policy->landlock) {
            printf("[Policy] Landlock path policy requested\n");
        } else if (policy->enforce_file_access) {
            printf("[Policy] Note: without landlock=true, path policy is argv-only\n");
        }
    }

    return 0;
}

static int set_no_new_privs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return -1;
    }
    /* Crash dumps from sandboxed children are rarely useful and can leak memory. */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_DUMPABLE)");
        return -1;
    }
    return 0;
}

static int drop_capabilities(void) {
    cap_t caps;
    int i;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) {
        perror("prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
        return -1;
    }

    for (i = 0; i <= CAP_LAST_CAP; ++i) {
        if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0) != 0 && errno != EINVAL && errno != EPERM) {
            /* Keep going; some caps may already be absent. */
        }
    }

    caps = cap_init();
    if (!caps) {
        perror("cap_init");
        return -1;
    }
    if (cap_clear(caps) != 0 || cap_set_proc(caps) != 0) {
        perror("cap_set_proc");
        cap_free(caps);
        return -1;
    }
    cap_free(caps);
    return 0;
}

static int apply_rlimits(const sandbox_policy *policy) {
    struct rlimit rl;

    if (policy->rlimit_as_mb >= 0) {
        rl.rlim_cur = (rlim_t)policy->rlimit_as_mb * 1024UL * 1024UL;
        rl.rlim_max = rl.rlim_cur;
        if (setrlimit(RLIMIT_AS, &rl) != 0) {
            perror("setrlimit(RLIMIT_AS)");
            return -1;
        }
    }
    if (policy->rlimit_nofile >= 0) {
        rl.rlim_cur = (rlim_t)policy->rlimit_nofile;
        rl.rlim_max = rl.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            perror("setrlimit(RLIMIT_NOFILE)");
            return -1;
        }
    }
    if (policy->rlimit_nproc >= 0) {
        rl.rlim_cur = (rlim_t)policy->rlimit_nproc;
        rl.rlim_max = rl.rlim_cur;
        if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
            perror("setrlimit(RLIMIT_NPROC)");
            return -1;
        }
    }
    return 0;
}

static int scrub_fds(int keep_fd) {
    /* Keep stdin/stdout/stderr and optional ready pipe; close everything else. */
    unsigned int first = 3;
    int rc = -1;

    if (keep_fd >= (int)first) {
        if ((unsigned)keep_fd > first) {
            rc = close_range(first, (unsigned)keep_fd - 1U, 0);
        } else {
            rc = 0;
        }
        if (rc == 0) {
            rc = close_range((unsigned)keep_fd + 1U, ~0U, 0);
        }
    } else {
        rc = close_range(first, ~0U, 0);
    }

    if (rc != 0) {
        int fd;
        int max_fd = (int)sysconf(_SC_OPEN_MAX);
        if (max_fd < 0 || max_fd > 1024) {
            max_fd = 1024;
        }
        for (fd = (int)first; fd < max_fd; ++fd) {
            if (fd == keep_fd) {
                continue;
            }
            close(fd);
        }
    }
    return 0;
}

static __u64 landlock_access_fs_handled(int abi) {
    __u64 access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                   LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi >= 3) {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) {
        access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
#endif
    return access;
}

static __u64 landlock_access_fs_allow(int abi) {
    __u64 access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                   LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 2) {
        /* Refer is often not needed for simple workloads; omit to stay strict. */
        (void)abi;
    }
    return access & landlock_access_fs_handled(abi);
}

static int apply_landlock_with_target(const sandbox_policy *policy, const char *target_exec) {
    int abi;
    int ruleset_fd;
    size_t i;
    struct landlock_ruleset_attr attr;
    char target_dir[PATH_MAX];
    char *slash;

    if (!policy->landlock || !policy->enforce_file_access || policy->file_access_count == 0) {
        return 0;
    }

    abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "[Landlock] unavailable (errno=%d); skipping path LSM\n", errno);
        return 1;
    }

    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = landlock_access_fs_handled(abi);
    ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return -1;
    }

    for (i = 0; i < policy->file_access_count; ++i) {
        char allowed_abs[PATH_MAX];
        struct landlock_path_beneath_attr path_attr;
        int fd;

        if (!make_absolute_path(policy->file_access[i], allowed_abs, sizeof(allowed_abs))) {
            close(ruleset_fd);
            return -1;
        }
        fd = open(allowed_abs, O_PATH | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "[Landlock] open(O_PATH) failed for %s: %s\n", allowed_abs,
                    strerror(errno));
            close(ruleset_fd);
            return -1;
        }
        memset(&path_attr, 0, sizeof(path_attr));
        path_attr.allowed_access = landlock_access_fs_allow(abi);
        path_attr.parent_fd = fd;
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) != 0) {
            perror("landlock_add_rule");
            close(fd);
            close(ruleset_fd);
            return -1;
        }
        close(fd);
        printf("[Landlock] allowed path beneath: %s\n", allowed_abs);
    }

    /* Ensure the target binary's directory remains reachable for exec. */
    snprintf(target_dir, sizeof(target_dir), "%s", target_exec);
    slash = strrchr(target_dir, '/');
    if (slash && slash != target_dir) {
        *slash = '\0';
    } else {
        snprintf(target_dir, sizeof(target_dir), "/");
    }

    {
        struct landlock_path_beneath_attr path_attr;
        int fd = open(target_dir, O_PATH | O_CLOEXEC);
        if (fd >= 0) {
            memset(&path_attr, 0, sizeof(path_attr));
            path_attr.allowed_access = landlock_access_fs_allow(abi);
            path_attr.parent_fd = fd;
            if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) != 0) {
                perror("landlock_add_rule(target_dir)");
                close(fd);
                close(ruleset_fd);
                return -1;
            }
            close(fd);
            printf("[Landlock] allowed target dir: %s\n", target_dir);
        }
    }

    /* Dynamic linker / libc paths commonly required after exec. */
    {
        const char *lib_paths[] = {"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/etc/ld.so.cache"};
        size_t j;
        for (j = 0; j < sizeof(lib_paths) / sizeof(lib_paths[0]); ++j) {
            struct landlock_path_beneath_attr path_attr;
            int fd = open(lib_paths[j], O_PATH | O_CLOEXEC);
            if (fd < 0) {
                continue;
            }
            memset(&path_attr, 0, sizeof(path_attr));
            path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                                       LANDLOCK_ACCESS_FS_EXECUTE;
            path_attr.allowed_access &= landlock_access_fs_handled(abi);
            path_attr.parent_fd = fd;
            if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) != 0) {
                close(fd);
                continue;
            }
            close(fd);
        }
    }

    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return -1;
    }
    close(ruleset_fd);
    printf("[Landlock] ruleset attached (ABI %d)\n", abi);
    return 0;
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len;
    size_t i;

    if (!path || path[0] != '/') {
        return -1;
    }
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        return -1;
    }
    len = strlen(tmp);
    for (i = 1; i < len; ++i) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int bind_mount_path(const char *src, const char *dst, bool read_only) {
    struct stat st;

    if (stat(src, &st) != 0) {
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        if (mkdir_p(dst, 0755) != 0) {
            return -1;
        }
    } else {
        char parent[PATH_MAX];
        char *slash;
        snprintf(parent, sizeof(parent), "%s", dst);
        slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = '\0';
            if (mkdir_p(parent, 0755) != 0) {
                return -1;
            }
        }
        {
            int fd = open(dst, O_CREAT | O_WRONLY, 0644);
            if (fd >= 0) {
                close(fd);
            } else {
                return -1;
            }
        }
    }

    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) != 0) {
        return -1;
    }
    if (read_only) {
        if (mount(NULL, dst, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC, NULL) != 0) {
            /* non-fatal on some kernels for files */
        }
    }
    return 0;
}

static int net_if_set_flags(const char *ifname, short flags_on) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        close(fd);
        return -1;
    }
    ifr.ifr_flags |= flags_on;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int run_ip(char *const argv[]) {
    pid_t pid = fork();
    int st = 0;
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        int nullfd = open("/dev/null", O_WRONLY);
        if (nullfd >= 0) {
            dup2(nullfd, STDOUT_FILENO);
            dup2(nullfd, STDERR_FILENO);
            close(nullfd);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(pid, &st, 0) < 0) {
        return -1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        return -1;
    }
    return 0;
}

/* Assumes caller is already root in a user+net namespace. */
static int setup_net_ns(const sandbox_policy *policy) {
    if (policy->net_ns_mode[0] == '\0') {
        return 0;
    }

    if (unshare(CLONE_NEWNET) != 0) {
        perror("unshare(CLONE_NEWNET)");
        return -1;
    }

    if (net_if_set_flags("lo", IFF_UP) != 0) {
        perror("bring up lo");
        return -1;
    }
    printf("[NetNS] loopback up (mode=%s)\n", policy->net_ns_mode);

    if (strcmp(policy->net_ns_mode, "veth-deny") == 0) {
        char *add_argv[] = {"ip", "link", "add", "ksb0", "type", "veth", "peer", "name", "ksb1",
                            NULL};
        char *up_argv[] = {"ip", "link", "set", "ksb0", "up", NULL};
        char *addr_argv[] = {"ip", "addr", "add", "10.200.255.1/30", "dev", "ksb0", NULL};
        /* Peer ksb1 stays DOWN: no usable L2 path even inside the ns. No default route. */
        if (run_ip(add_argv) != 0) {
            fprintf(stderr,
                    "[NetNS] veth create failed (need iproute2 + CAP_NET_ADMIN in userns). "
                    "Falling back to loopback-only.\n");
        } else {
            (void)run_ip(addr_argv);
            (void)run_ip(up_argv);
            printf("[NetNS] veth ksb0 up, peer ksb1 left DOWN (egress/path deny demo)\n");
        }
    }

    return 0;
}

static int write_cgroup_file(const char *dir, const char *name, const char *value) {
    char path[PATH_MAX];
    int fd;
    size_t len;

    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) {
        return -1;
    }
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        return -1;
    }
    len = strlen(value);
    if (write(fd, value, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int cgroup_resolve_root(const sandbox_policy *policy, char *out, size_t out_sz) {
    const char *env = getenv("SANDBOX_CGROUP_ROOT");
    const char *candidates[4];
    size_t n = 0;
    size_t i;

    if (policy->cgroup_root[0]) {
        candidates[n++] = policy->cgroup_root;
    }
    if (env && env[0]) {
        candidates[n++] = env;
    }
    candidates[n++] = "/sys/fs/cgroup/ksb.sandbox";
    candidates[n++] = NULL;

    for (i = 0; i < n && candidates[i]; ++i) {
        char probe[PATH_MAX];
        struct stat st;
        if (stat(candidates[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            continue;
        }
        if (snprintf(probe, sizeof(probe), "%s/.ksb_write_probe", candidates[i]) >=
            (int)sizeof(probe)) {
            continue;
        }
        if (mkdir(probe, 0755) == 0) {
            rmdir(probe);
            snprintf(out, out_sz, "%s", candidates[i]);
            return 0;
        }
    }
    return -1;
}

/*
 * Create a leaf cgroup under a writable cgroup v2 root with requested controllers.
 * Requires the parent to already have memory/cpu/pids in cgroup.subtree_control
 * (see docs). Returns 0 and fills created_path; -1 if unavailable.
 */
static int cgroup_create(const sandbox_policy *policy, char *created_path, size_t created_sz) {
    char root[PATH_MAX];
    char leaf[PATH_MAX];
    char buf[128];

    if (!policy->cgroup) {
        created_path[0] = '\0';
        return 0;
    }

    if (cgroup_resolve_root(policy, root, sizeof(root)) != 0) {
        fprintf(stderr,
                "[Cgroup] No writable cgroup v2 root. Create e.g. /sys/fs/cgroup/ksb.sandbox "
                "owned by this user with '+memory +cpu +pids' in cgroup.subtree_control, "
                "or set SANDBOX_CGROUP_ROOT. Skipping cgroup limits.\n");
        return 1; /* soft skip */
    }

    if (snprintf(leaf, sizeof(leaf), "%s/run-%d-%ld", root, (int)getpid(), (long)time(NULL)) >=
        (int)sizeof(leaf)) {
        return -1;
    }
    if (mkdir(leaf, 0755) != 0) {
        perror("mkdir(cgroup leaf)");
        return -1;
    }

    if (policy->cgroup_memory_max[0]) {
        if (write_cgroup_file(leaf, "memory.max", policy->cgroup_memory_max) != 0) {
            fprintf(stderr, "[Cgroup] failed to set memory.max=%s (%s)\n",
                    policy->cgroup_memory_max, strerror(errno));
            rmdir(leaf);
            return -1;
        }
    }
    if (policy->cgroup_pids_max >= 0) {
        snprintf(buf, sizeof(buf), "%ld", policy->cgroup_pids_max);
        if (write_cgroup_file(leaf, "pids.max", buf) != 0) {
            fprintf(stderr, "[Cgroup] failed to set pids.max (%s)\n", strerror(errno));
            rmdir(leaf);
            return -1;
        }
    }
    if (policy->cgroup_cpu_max[0]) {
        if (write_cgroup_file(leaf, "cpu.max", policy->cgroup_cpu_max) != 0) {
            fprintf(stderr, "[Cgroup] failed to set cpu.max=%s (%s)\n", policy->cgroup_cpu_max,
                    strerror(errno));
            rmdir(leaf);
            return -1;
        }
    }

    snprintf(created_path, created_sz, "%s", leaf);
    printf("[Cgroup] leaf %s memory.max=%s pids.max=%ld cpu.max=%s\n", leaf,
           policy->cgroup_memory_max[0] ? policy->cgroup_memory_max : "(unchanged)",
           policy->cgroup_pids_max, policy->cgroup_cpu_max[0] ? policy->cgroup_cpu_max : "(unchanged)");
    return 0;
}

static int cgroup_attach_pid(const char *cgroup_path, pid_t pid) {
    char buf[32];
    char procs_path[PATH_MAX];
    if (!cgroup_path || !cgroup_path[0]) {
        return 0;
    }
    snprintf(buf, sizeof(buf), "%d\n", (int)pid);
    if (write_cgroup_file(cgroup_path, "cgroup.procs", buf) == 0) {
        return 0;
    }
    /*
     * Crossing into a delegated root like /sys/fs/cgroup/ksb.sandbox from a
     * nested service cgroup often needs CAP_SYS_ADMIN. Retry via passwordless
     * sudo when available; otherwise the caller skips/fails honestly.
     */
    if (snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path) >=
        (int)sizeof(procs_path)) {
        return -1;
    }
    {
        int pipefd[2];
        pid_t helper;
        int st = 0;
        if (pipe(pipefd) != 0) {
            return -1;
        }
        helper = fork();
        if (helper < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return -1;
        }
        if (helper == 0) {
            int fd;
            char *sudo_argv[5];
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
            fd = open("/dev/null", O_WRONLY);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
            sudo_argv[0] = "sudo";
            sudo_argv[1] = "-n";
            sudo_argv[2] = "tee";
            sudo_argv[3] = procs_path;
            sudo_argv[4] = NULL;
            execvp(sudo_argv[0], sudo_argv);
            _exit(127);
        }
        close(pipefd[0]);
        if (write(pipefd[1], buf, strlen(buf)) < 0) {
            /* ignore */
        }
        close(pipefd[1]);
        if (waitpid(helper, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr,
                    "[Cgroup] failed to move pid %d into %s (direct write errno was %s; "
                    "sudo -n tee also failed). Create a writable root under the current "
                    "cgroup tree or grant passwordless sudo for tee on cgroup.procs.\n",
                    (int)pid, cgroup_path, strerror(errno));
            return -1;
        }
        printf("[Cgroup] attached pid %d via sudo -n tee\n", (int)pid);
        return 0;
    }
}

static void cgroup_cleanup(const char *cgroup_path) {
    if (!cgroup_path || !cgroup_path[0]) {
        return;
    }
    if (rmdir(cgroup_path) != 0) {
        /* Best-effort; leaf may still be busy briefly. */
        fprintf(stderr, "[Cgroup] rmdir(%s): %s\n", cgroup_path, strerror(errno));
    }
}

static int setup_mount_ns(const sandbox_policy *policy, const char *target_exec) {
    char root[PATH_MAX];
    char put_old[PATH_MAX];
    char tmpbase[] = "/tmp/ksb-XXXXXX";
    size_t i;
    char target_dir[PATH_MAX];
    char dst[8192];
    char *slash;

    if (!policy->mount_ns) {
        return 0;
    }

    /* Caller already entered a user+mount namespace and mapped to ns root. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("mount(MS_PRIVATE)");
        return -1;
    }

    if (!mkdtemp(tmpbase)) {
        perror("mkdtemp");
        return -1;
    }
    snprintf(root, sizeof(root), "%s/root", tmpbase);
    snprintf(put_old, sizeof(put_old), "%s/root/.old", tmpbase);
    if (mkdir(root, 0755) != 0 || mkdir(put_old, 0755) != 0) {
        perror("mkdir pivot root");
        return -1;
    }
    if (mount("tmpfs", root, "tmpfs", 0, "mode=755") != 0) {
        perror("mount tmpfs root");
        return -1;
    }
    if (mkdir(put_old, 0755) != 0 && errno != EEXIST) {
        perror("mkdir put_old");
        return -1;
    }

    /* Essential runtime paths (read-only). */
    {
        const char *ro[] = {"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/bin", "/bin",
                            "/etc/ld.so.cache"};
        for (i = 0; i < sizeof(ro) / sizeof(ro[0]); ++i) {
            if (snprintf(dst, sizeof(dst), "%s%s", root, ro[i]) >= (int)sizeof(dst)) {
                continue;
            }
            bind_mount_path(ro[i], dst, true);
        }
    }

    /* Policy allowlisted paths (read-write). */
    for (i = 0; i < policy->file_access_count; ++i) {
        char src[PATH_MAX];
        if (!make_absolute_path(policy->file_access[i], src, sizeof(src))) {
            continue;
        }
        if (snprintf(dst, sizeof(dst), "%s%s", root, src) >= (int)sizeof(dst)) {
            continue;
        }
        if (bind_mount_path(src, dst, false) != 0) {
            fprintf(stderr, "[MountNS] bind failed for %s\n", src);
        }
    }

    snprintf(target_dir, sizeof(target_dir), "%s", target_exec);
    slash = strrchr(target_dir, '/');
    if (slash && slash != target_dir) {
        *slash = '\0';
    } else {
        snprintf(target_dir, sizeof(target_dir), "/");
    }
    if (snprintf(dst, sizeof(dst), "%s%s", root, target_dir) < (int)sizeof(dst)) {
        bind_mount_path(target_dir, dst, true);
    }

    if (chdir(root) != 0) {
        perror("chdir new root");
        return -1;
    }
    if (syscall(__NR_pivot_root, ".", ".old") != 0) {
        perror("pivot_root");
        return -1;
    }
    if (umount2(".old", MNT_DETACH) != 0) {
        perror("umount2(.old)");
        /* continue; root is still switched */
    }
    rmdir(".old");
    printf("[MountNS] pivot_root completed into private tmpfs root\n");
    return 0;
}

static int write_id_map(pid_t pid, const char *map_name, const char *content) {
    char path[PATH_MAX];
    int fd;
    size_t len = strlen(content);

    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, map_name);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, content, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * On Ubuntu kernels with apparmor_restrict_unprivileged_userns, a child often
 * cannot write its own uid_map after unshare, while the parent can. Sync:
 * child unshares then writes 'U'; parent writes maps then writes 'G'.
 */
static int parent_map_child_userns(pid_t pid) {
    char map[64];

    if (write_id_map(pid, "setgroups", "deny") != 0) {
        /* optional on some kernels */
    }
    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)getuid());
    if (write_id_map(pid, "uid_map", map) != 0) {
        perror("uid_map");
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1\n", (unsigned)getgid());
    if (write_id_map(pid, "gid_map", map) != 0) {
        perror("gid_map");
        return -1;
    }
    return 0;
}

static int install_filter(const sandbox_policy *policy) {
    uint32_t default_action;
    scmp_filter_ctx ctx;

    if (policy->default_deny) {
        default_action =
            policy->kill_on_violation ? SCMP_ACT_KILL_PROCESS : SCMP_ACT_ERRNO(EPERM);
    } else {
        default_action = SCMP_ACT_ALLOW;
    }

    ctx = seccomp_init(default_action);
    if (!ctx) {
        perror("seccomp_init failed");
        return -1;
    }

    /* NNP is also set explicitly via prctl before this call; keep libseccomp bit on. */
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

static int child_prepare_and_exec(child_ctx *ctx) {
    const sandbox_policy *policy = ctx->policy;
    int ll_rc;

    /* Namespace/pivot_root setup (if requested) is completed by the caller
     * before this function, after parent writes uid/gid maps. */

    if (ctx->cgroup_gate_fd >= 0) {
        char b = 0;
        if (read(ctx->cgroup_gate_fd, &b, 1) != 1 || b != 'C') {
            fprintf(stderr, "[Child] cgroup gate sync failed\n");
            _exit(38);
        }
        close(ctx->cgroup_gate_fd);
        ctx->cgroup_gate_fd = -1;
    }

    /* Order: NNP -> Landlock -> caps/rlimits -> FD scrub -> seccomp -> exec.
     * Landlock and useful seccomp both require NO_NEW_PRIVS. */
    if (set_no_new_privs() < 0) {
        _exit(33);
    }

    ll_rc = apply_landlock_with_target(policy, ctx->target_exec);
    if (ll_rc < 0) {
        _exit(34);
    }

    if (policy->drop_caps) {
        if (drop_capabilities() < 0) {
            _exit(35);
        }
    }

    if (apply_rlimits(policy) < 0) {
        _exit(36);
    }

    if (policy->close_fds) {
        scrub_fds(ctx->ready_fd);
    }

    printf("[Child] Installing seccomp filter...\n");
    if (install_filter(policy) < 0) {
        log_line(policy, "Failed to install seccomp filter");
        audit_jsonl(policy, ctx->run_id, "filter_install_failed", getpid(),
                    "\"policy\":\"%s\"", ctx->policy_path);
        _exit(1);
    }

    log_line(policy, "Seccomp filter installed");
    audit_jsonl(policy, ctx->run_id, "filter_installed", getpid(),
                "\"policy\":\"%s\",\"default_deny\":%s,\"landlock\":%s", ctx->policy_path,
                policy->default_deny ? "true" : "false", policy->landlock ? "true" : "false");

    if (ctx->ready_fd >= 0) {
        char ok = 'R';
        if (write(ctx->ready_fd, &ok, 1) != 1) {
            /* parent may have closed; continue */
        }
        close(ctx->ready_fd);
        ctx->ready_fd = -1;
    }

    printf("[Child] Executing target\n\n");
    fflush(stdout);
    execv(ctx->target_exec, ctx->child_argv);

    perror("execv failed");
    log_line(policy, "execv failed for target=%s errno=%d", ctx->target_exec, errno);
    audit_jsonl(policy, ctx->run_id, "exec_failed", getpid(), "\"errno\":%d", errno);
    _exit(1);
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [options] <policy.json> <program> [args...]\n"
            "Options:\n"
            "  --mount-ns              Enter a mount namespace and pivot_root (needs user ns)\n"
            "  --pid-ns                Enter a PID namespace (needs user ns)\n"
            "  --net-ns=MODE           Network ns: loopback | veth-deny (needs user ns)\n"
            "  --cgroup                Enable cgroup v2 leaf (needs writable cgroup root)\n"
            "  --cgroup-memory-max=V   e.g. 32M\n"
            "  --cgroup-pids-max=N     e.g. 8\n"
            "  --cgroup-cpu-max=V      e.g. '10000 100000' (quota period)\n"
            "  --cgroup-root=PATH      Override cgroup v2 root (or SANDBOX_CGROUP_ROOT)\n"
            "  --no-drop-caps          Skip capability drop\n"
            "  --audit-jsonl PATH      Override audit JSONL path\n"
            "  --help                  Show this help\n",
            argv0);
}

int main(int argc, char *argv[]) {
    sandbox_policy policy;
    char *target_exec;
    char **child_argv;
    pid_t pid;
    int status;
    int i;
    int argi = 1;
    bool cli_mount_ns = false;
    bool cli_pid_ns = false;
    bool cli_no_drop_caps = false;
    bool cli_cgroup = false;
    const char *cli_audit = NULL;
    const char *cli_net_ns = NULL;
    const char *cli_cg_mem = NULL;
    const char *cli_cg_cpu = NULL;
    const char *cli_cg_root = NULL;
    long cli_cg_pids = -1;
    int ready_pipe[2] = {-1, -1};
    int map_from_child[2] = {-1, -1};
    int map_to_child[2] = {-1, -1};
    int cgroup_gate[2] = {-1, -1};
    int64_t t0, t1;
    char run_id[64];
    char cgroup_path[PATH_MAX];
    child_ctx ctx;
    bool use_userns = false;
    int cg_rc;

    cgroup_path[0] = '\0';

    while (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
        if (strcmp(argv[argi], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[argi], "--mount-ns") == 0) {
            cli_mount_ns = true;
        } else if (strcmp(argv[argi], "--pid-ns") == 0) {
            cli_pid_ns = true;
        } else if (strncmp(argv[argi], "--net-ns=", 9) == 0) {
            cli_net_ns = argv[argi] + 9;
        } else if (strcmp(argv[argi], "--cgroup") == 0) {
            cli_cgroup = true;
        } else if (strncmp(argv[argi], "--cgroup-memory-max=", 20) == 0) {
            cli_cg_mem = argv[argi] + 20;
        } else if (strncmp(argv[argi], "--cgroup-pids-max=", 18) == 0) {
            cli_cg_pids = strtol(argv[argi] + 18, NULL, 10);
        } else if (strncmp(argv[argi], "--cgroup-cpu-max=", 17) == 0) {
            cli_cg_cpu = argv[argi] + 17;
        } else if (strncmp(argv[argi], "--cgroup-root=", 14) == 0) {
            cli_cg_root = argv[argi] + 14;
        } else if (strcmp(argv[argi], "--no-drop-caps") == 0) {
            cli_no_drop_caps = true;
        } else if (strcmp(argv[argi], "--audit-jsonl") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "--audit-jsonl requires a path\n");
                return 1;
            }
            cli_audit = argv[++argi];
        } else if (strcmp(argv[argi], "--") == 0) {
            ++argi;
            break;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[argi]);
            usage(argv[0]);
            return 1;
        }
        ++argi;
    }

    if (argc - argi < 2) {
        usage(argv[0]);
        return 1;
    }

    if (load_policy(argv[argi], &policy) < 0) {
        return 1;
    }
    if (cli_mount_ns) {
        policy.mount_ns = true;
    }
    if (cli_pid_ns) {
        policy.pid_ns = true;
    }
    if (cli_net_ns) {
        snprintf(policy.net_ns_mode, sizeof(policy.net_ns_mode), "%s", cli_net_ns);
        if (strcmp(policy.net_ns_mode, "off") == 0) {
            policy.net_ns_mode[0] = '\0';
        }
    }
    if (cli_cgroup) {
        policy.cgroup = true;
    }
    if (cli_cg_mem) {
        snprintf(policy.cgroup_memory_max, sizeof(policy.cgroup_memory_max), "%s", cli_cg_mem);
        policy.cgroup = true;
    }
    if (cli_cg_pids >= 0) {
        policy.cgroup_pids_max = cli_cg_pids;
        policy.cgroup = true;
    }
    if (cli_cg_cpu) {
        snprintf(policy.cgroup_cpu_max, sizeof(policy.cgroup_cpu_max), "%s", cli_cg_cpu);
        policy.cgroup = true;
    }
    if (cli_cg_root) {
        snprintf(policy.cgroup_root, sizeof(policy.cgroup_root), "%s", cli_cg_root);
    }
    if (cli_no_drop_caps) {
        policy.drop_caps = false;
    }
    if (cli_audit) {
        snprintf(policy.audit_jsonl, sizeof(policy.audit_jsonl), "%s", cli_audit);
    }

    target_exec = resolve_program_path(argv[argi + 1]);
    if (!target_exec) {
        fprintf(stderr, "[Main] Unable to resolve executable target: %s\n", argv[argi + 1]);
        free_policy(&policy);
        return 1;
    }

    if (policy.enforce_file_access && policy.file_access_count > 0) {
        if (!path_allowed_by_policy(&policy, target_exec)) {
            fprintf(stderr, "[Policy] target executable is outside file_access allowlist: %s\n",
                    target_exec);
            free(target_exec);
            free_policy(&policy);
            return 1;
        }
        for (i = argi + 2; i < argc; ++i) {
            char arg_abs[PATH_MAX];
            if (!is_path_like_arg(argv[i])) {
                continue;
            }
            if (!make_absolute_path(argv[i], arg_abs, sizeof(arg_abs)) ||
                !path_allowed_by_policy(&policy, arg_abs)) {
                fprintf(stderr, "[Policy] path argument is outside file_access allowlist: %s\n",
                        argv[i]);
                free(target_exec);
                free_policy(&policy);
                return 1;
            }
        }
    }

    child_argv = (char **)calloc((size_t)(argc - argi), sizeof(char *));
    if (!child_argv) {
        perror("calloc failed");
        free(target_exec);
        free_policy(&policy);
        return 1;
    }
    child_argv[0] = target_exec;
    for (i = argi + 2; i < argc; ++i) {
        child_argv[i - (argi + 1)] = argv[i];
    }
    child_argv[argc - (argi + 1)] = NULL;

    snprintf(run_id, sizeof(run_id), "%ld-%d", (long)time(NULL), (int)getpid());

    printf("\n========== SANDBOX ENGINE START ==========\n");
    printf("[Main] Policy file: %s\n", argv[argi]);
    printf("[Main] Target: %s\n", target_exec);
    printf("[Main] Mode: %s | landlock=%s | mount_ns=%s | pid_ns=%s | net_ns=%s | cgroup=%s\n",
           policy.default_deny ? "default-deny" : "compat-allow",
           policy.landlock ? "on" : "off", policy.mount_ns ? "on" : "off",
           policy.pid_ns ? "on" : "off",
           policy.net_ns_mode[0] ? policy.net_ns_mode : "off", policy.cgroup ? "on" : "off");

    log_line(&policy, "Starting sandbox policy=%s target=%s", argv[argi], argv[argi + 1]);
    audit_jsonl(&policy, run_id, "start", getpid(),
                "\"policy\":\"%s\",\"target\":\"%s\"", argv[argi], target_exec);

    cg_rc = cgroup_create(&policy, cgroup_path, sizeof(cgroup_path));
    if (cg_rc < 0) {
        free(child_argv);
        free(target_exec);
        free_policy(&policy);
        return 1;
    }
    if (cg_rc > 0) {
        /* Soft skip: continue without cgroup limits. */
        policy.cgroup = false;
        cgroup_path[0] = '\0';
    }

    if (pipe(ready_pipe) != 0) {
        perror("pipe");
        cgroup_cleanup(cgroup_path);
        free(child_argv);
        free(target_exec);
        free_policy(&policy);
        return 1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.policy = &policy;
    ctx.target_exec = target_exec;
    ctx.child_argv = child_argv;
    ctx.ready_fd = ready_pipe[1];
    ctx.map_sync_fd = -1;
    ctx.cgroup_gate_fd = -1;
    snprintf(ctx.run_id, sizeof(ctx.run_id), "%s", run_id);
    ctx.policy_path = argv[argi];

    use_userns = policy.mount_ns || policy.pid_ns || policy.net_ns_mode[0] != '\0';
    if (use_userns) {
        if (pipe(map_from_child) != 0 || pipe(map_to_child) != 0) {
            perror("pipe(map sync)");
            cgroup_cleanup(cgroup_path);
            free(child_argv);
            free(target_exec);
            free_policy(&policy);
            return 1;
        }
    }
    if (cgroup_path[0]) {
        if (pipe(cgroup_gate) != 0) {
            perror("pipe(cgroup gate)");
            cgroup_cleanup(cgroup_path);
            free(child_argv);
            free(target_exec);
            free_policy(&policy);
            return 1;
        }
        ctx.cgroup_gate_fd = cgroup_gate[0];
    }

    fflush(NULL);
    t0 = now_ns();

    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        free_policy(&policy);
        return 1;
    }

    if (pid == 0) {
        close(ready_pipe[0]);
        if (cgroup_path[0]) {
            close(cgroup_gate[1]);
            ctx.cgroup_gate_fd = cgroup_gate[0];
        }
        if (use_userns) {
            close(map_from_child[0]);
            close(map_to_child[1]);
            {
                int uflags = CLONE_NEWUSER;
                char b = 0;
                if (policy.mount_ns) {
                    uflags |= CLONE_NEWNS;
                }
                if (unshare(uflags) != 0) {
                    perror("unshare(user/ns)");
                    _exit(30);
                }
                if (write(map_from_child[1], "U", 1) != 1) {
                    _exit(31);
                }
                close(map_from_child[1]);
                if (read(map_to_child[0], &b, 1) != 1 || b != 'G') {
                    fprintf(stderr, "[Child] userns map sync failed\n");
                    _exit(31);
                }
                close(map_to_child[0]);
                if (policy.pid_ns) {
                    if (unshare(CLONE_NEWPID) != 0) {
                        perror("unshare(CLONE_NEWPID)");
                        _exit(30);
                    }
                    {
                        pid_t inner = fork();
                        if (inner < 0) {
                            perror("fork(pid_ns)");
                            _exit(30);
                        }
                        if (inner > 0) {
                            int st = 0;
                            waitpid(inner, &st, 0);
                            _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
                        }
                    }
                }
                if (policy.net_ns_mode[0]) {
                    if (setup_net_ns(&policy) < 0) {
                        fprintf(stderr, "[Child] net namespace setup failed\n");
                        _exit(37);
                    }
                }
                if (policy.mount_ns) {
                    if (setup_mount_ns(&policy, target_exec) < 0) {
                        fprintf(stderr, "[Child] mount namespace / pivot_root setup failed\n");
                        _exit(32);
                    }
                }
            }
        }
        child_prepare_and_exec(&ctx);
        _exit(1);
    }

    if (cgroup_path[0]) {
        char go = 'C';
        int attach_rc;
        close(cgroup_gate[0]);
        attach_rc = cgroup_attach_pid(cgroup_path, pid);
        if (attach_rc != 0) {
            audit_jsonl(&policy, run_id, "cgroup_attach_failed", pid, "\"path\":\"%s\"",
                        cgroup_path);
            close(cgroup_gate[1]); /* child will fail the gate and exit */
        } else {
            audit_jsonl(&policy, run_id, "cgroup_attached", pid, "\"path\":\"%s\"", cgroup_path);
            if (write(cgroup_gate[1], &go, 1) != 1) {
                perror("cgroup gate");
            }
            close(cgroup_gate[1]);
        }
    }

    if (use_userns) {
        char b = 0;
        close(map_from_child[1]);
        close(map_to_child[0]);
        if (read(map_from_child[0], &b, 1) != 1 || b != 'U') {
            fprintf(stderr, "[Main] child did not signal userns unshare\n");
        } else if (parent_map_child_userns(pid) != 0) {
            fprintf(stderr, "[Main] failed to write child uid/gid maps\n");
        } else if (write(map_to_child[1], "G", 1) != 1) {
            perror("map sync go");
        }
        close(map_from_child[0]);
        close(map_to_child[1]);
    }

    close(ready_pipe[1]);
    ready_pipe[1] = -1;
    log_line(&policy, "Forked child pid=%d", pid);
    audit_jsonl(&policy, run_id, "forked", pid, "\"policy\":\"%s\"", argv[argi]);

    {
        char ready = 0;
        ssize_t n = read(ready_pipe[0], &ready, 1);
        t1 = now_ns();
        close(ready_pipe[0]);
        if (n == 1 && ready == 'R') {
            double us = (double)(t1 - t0) / 1000.0;
            printf("[Main] Attach latency (fork/clone -> filter ready): %.3f us\n", us);
            audit_jsonl(&policy, run_id, "attach_ready", pid,
                        "\"attach_us\":%.3f", us);
        } else {
            printf("[Main] Child exited before signaling filter ready\n");
            audit_jsonl(&policy, run_id, "attach_failed", pid, "\"note\":\"no_ready_signal\"");
        }
    }

    /* When pid_ns is enabled the supervisor still reaps via waitpid on the
     * clone pid in the parent namespace. pidfd_open is used when available for
     * a stable handle log line (PID-recycle safety for tooling). */
    {
        int pfd = -1;
#ifdef __NR_pidfd_open
        pfd = (int)syscall(__NR_pidfd_open, pid, 0);
#endif
        if (pfd >= 0) {
            audit_jsonl(&policy, run_id, "pidfd_opened", pid, "\"pidfd\":%d", pfd);
            close(pfd);
        }
    }

    waitpid(pid, &status, 0);
    cgroup_cleanup(cgroup_path);

    printf("\n========== SANDBOX ENGINE END ==========\n");
    if (WIFSIGNALED(status)) {
        printf("[Monitor] Process terminated by signal: %d\n", WTERMSIG(status));
        log_line(&policy, "Process terminated by signal=%d", WTERMSIG(status));
        audit_jsonl(&policy, run_id, "signal", pid, "\"signal\":%d", WTERMSIG(status));
    } else {
        printf("[Monitor] Process exit code: %d\n", WEXITSTATUS(status));
        log_line(&policy, "Process exit code=%d", WEXITSTATUS(status));
        audit_jsonl(&policy, run_id, "exit", pid, "\"code\":%d", WEXITSTATUS(status));
    }

    free(child_argv);
    free(target_exec);
    free_policy(&policy);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
