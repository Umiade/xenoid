#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/seccomp.h>
#include <linux/if_tun.h>
#include <linux/sched.h>
#include <linux/sockios.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOCK_TYPE_MASK
#define SOCK_TYPE_MASK 0xf
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif

#define FIXED_BINARY "/usr/lib/xenoid/proxy/mihomo-v1.19.29"
#define RUNTIME_PREFIX "/run/xenoid/proxy/"
#define MAX_FILTER 192

static void fail(const char *code) {
    (void)!write(STDERR_FILENO, code, strlen(code));
    (void)!write(STDERR_FILENO, "\n", 1);
    _exit(126);
}


static int runtime_root(const char *path, char root[PATH_MAX]) {
    const size_t prefix = sizeof(RUNTIME_PREFIX) - 1;
    if (strncmp(path, RUNTIME_PREFIX, prefix) != 0) return 0;
    for (size_t i = 0; i < 12; ++i) {
        const char c = path[prefix + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    if (path[prefix + 12] != '/') return 0;
    memcpy(root, path, prefix + 12);
    root[prefix + 12] = '\0';
    return 1;
}

static int runtime_config_name(const char *path, const char *root) {
    const char *name = path + strlen(root);
    if (strncmp(name, "/config-", 8) != 0) return 0;
    name += 8;
    if ((*name != 'a' && *name != 'b') || name[1] != '-') return 0;
    name += 2;
    if (*name < '0' || *name > '9') return 0;
    while (*name >= '0' && *name <= '9') ++name;
    return strcmp(name, ".yaml") == 0;
}

static int runtime_state_name(const char *path, const char *root) {
    const char *name = path + strlen(root);
    if (strcmp(name, "/mihomo-systemd") == 0) return 1;
    if (strncmp(name, "/mihomo-", 8) != 0) return 0;
    name += 8;
    if ((*name != 'a' && *name != 'b') || name[1] != '-') return 0;
    name += 2;
    if (*name < '0' || *name > '9') return 0;
    while (*name >= '0' && *name <= '9') ++name;
    return *name == '\0';
}

static void validate_regular(const char *path, uid_t owner, mode_t forbidden, int executable) {
    struct stat st;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode) ||
        st.st_uid != owner || (st.st_mode & forbidden) != 0 ||
        (executable && (st.st_mode & 0111) == 0)) {
        fail("sandbox_path_invalid");
    }
}

static void validate_directory(const char *path, uid_t owner) {
    struct stat st;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode) ||
        st.st_uid != owner || (st.st_mode & 0077) != 0) {
        fail("sandbox_path_invalid");
    }
}

static void validate_paths(const char *binary, const char *config, const char *state) {
    char config_real[PATH_MAX], state_real[PATH_MAX], binary_real[PATH_MAX];
    char config_root[PATH_MAX], state_root[PATH_MAX];
    if (!realpath(binary, binary_real) || !realpath(config, config_real) ||
        !realpath(state, state_real) || strcmp(binary, binary_real) != 0 ||
        strcmp(config, config_real) != 0 || strcmp(state, state_real) != 0) {
        fail("sandbox_path_invalid");
    }
    if (strcmp(binary_real, FIXED_BINARY) != 0 ||
        !runtime_root(config_real, config_root) || !runtime_root(state_real, state_root) ||
        strcmp(config_root, state_root) != 0 ||
        !runtime_config_name(config_real, config_root) ||
        !runtime_state_name(state_real, state_root)) {
        fail("sandbox_path_invalid");
    }
    validate_regular(binary_real, 0, 0222, 1);
    validate_regular(config_real, 0, 0022, 0);
    validate_directory(state_real, geteuid());
}

static void validate_capabilities(void) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    memset(data, 0, sizeof(data));
    if (syscall(SYS_capget, &header, data) != 0) fail("sandbox_capability_invalid");
    const uint32_t allowed = (1U << CAP_NET_RAW);
    if ((data[0].effective & allowed) != allowed ||
        (data[0].effective & ~allowed) != 0 || (data[1].effective != 0) ||
        (data[0].permitted & allowed) != allowed ||
        (data[0].permitted & ~allowed) != 0 || data[1].permitted != 0 ||
        (data[0].inheritable & allowed) != allowed ||
        (data[0].inheritable & ~allowed) != 0 || data[1].inheritable != 0) {
        fail("sandbox_capability_invalid");
    }
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_RAW, 0, 0) != 1 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN, 0, 0) != 0) {
        fail("sandbox_capability_invalid");
    }
}

static void emit_stmt(struct sock_filter *filter, size_t *count, uint16_t code, uint32_t k) {
    if (*count >= MAX_FILTER) fail("sandbox_internal_error");
    filter[(*count)++] = (struct sock_filter){.code = code, .jt = 0, .jf = 0, .k = k};
}

static void emit_jump(struct sock_filter *filter, size_t *count, uint16_t code,
                      uint32_t k, uint8_t jt, uint8_t jf) {
    if (*count >= MAX_FILTER) fail("sandbox_internal_error");
    filter[(*count)++] = (struct sock_filter){.code = code, .jt = jt, .jf = jf, .k = k};
}

static void deny_syscall(struct sock_filter *filter, size_t *count, int number) {
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)number, 0, 1);
    emit_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
}

static void guard_clone_namespaces(struct sock_filter *filter, size_t *count) {
#ifdef __NR_clone
    uint32_t forbidden =
        CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
        CLONE_NEWPID | CLONE_NEWNET;
#ifdef CLONE_NEWCGROUP
    forbidden |= CLONE_NEWCGROUP;
#endif
#ifdef CLONE_NEWTIME
    forbidden |= CLONE_NEWTIME;
#endif
    const size_t guard = *count;
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 0);
    emit_stmt(filter, count, BPF_LD | BPF_W | BPF_ABS,
              offsetof(struct seccomp_data, args[0]));
    emit_jump(filter, count, BPF_JMP | BPF_JSET | BPF_K, forbidden, 0, 1);
    emit_stmt(filter, count, BPF_RET | BPF_K,
              SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    emit_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[guard].jf = (uint8_t)(*count - guard - 1);
#endif
}

static void guard_network_ioctl(struct sock_filter *filter, size_t *count) {
#ifdef __NR_ioctl
    const uint32_t denied[] = {
        TUNSETIFF, SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFDSTADDR,
        SIOCSIFBRDADDR, SIOCSIFNETMASK, SIOCSIFMETRIC, SIOCSIFMTU,
        SIOCSIFHWADDR, SIOCSARP, SIOCDARP, SIOCADDRT, SIOCDELRT,
    };
    const size_t guard = *count;
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 0);
    emit_stmt(filter, count, BPF_LD | BPF_W | BPF_ABS,
              offsetof(struct seccomp_data, args[1]));
    for (size_t index = 0; index < sizeof(denied) / sizeof(denied[0]); ++index) {
        emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, denied[index], 0, 1);
        emit_stmt(filter, count, BPF_RET | BPF_K,
                  SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }
    emit_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[guard].jf = (uint8_t)(*count - guard - 1);
#endif
}

static void guard_socket_allowlist(struct sock_filter *filter, size_t *count) {
    const size_t guard = *count;
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 0);
    emit_stmt(filter, count, BPF_LD | BPF_W | BPF_ABS,
              offsetof(struct seccomp_data, args[0]));
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 3, 0);
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0);
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0);
    emit_stmt(filter, count, BPF_RET | BPF_K,
              SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    emit_stmt(filter, count, BPF_LD | BPF_W | BPF_ABS,
              offsetof(struct seccomp_data, args[1]));
    emit_stmt(filter, count, BPF_ALU | BPF_AND | BPF_K, SOCK_TYPE_MASK);
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 3, 0);
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 2, 0);
    emit_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0);
    emit_stmt(filter, count, BPF_RET | BPF_K,
              SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    emit_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[guard].jf = (uint8_t)(*count - guard - 1);
}

static void install_seccomp(void) {
    struct sock_filter filter[MAX_FILTER];
    size_t count = 0;
    emit_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    emit_jump(filter, &count, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 2, 0);
    emit_jump(filter, &count, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    emit_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    emit_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#ifdef __NR_bpf
    deny_syscall(filter, &count, __NR_bpf);
#endif
#ifdef __NR_ptrace
    deny_syscall(filter, &count, __NR_ptrace);
#endif
#ifdef __NR_perf_event_open
    deny_syscall(filter, &count, __NR_perf_event_open);
#endif
#ifdef __NR_add_key
    deny_syscall(filter, &count, __NR_add_key);
#endif
#ifdef __NR_request_key
    deny_syscall(filter, &count, __NR_request_key);
#endif
#ifdef __NR_keyctl
    deny_syscall(filter, &count, __NR_keyctl);
#endif
#ifdef __NR_init_module
    deny_syscall(filter, &count, __NR_init_module);
#endif
#ifdef __NR_finit_module
    deny_syscall(filter, &count, __NR_finit_module);
#endif
#ifdef __NR_delete_module
    deny_syscall(filter, &count, __NR_delete_module);
#endif
#ifdef __NR_kexec_load
    deny_syscall(filter, &count, __NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
    deny_syscall(filter, &count, __NR_kexec_file_load);
#endif
#ifdef __NR_mount
    deny_syscall(filter, &count, __NR_mount);
#endif
#ifdef __NR_umount2
    deny_syscall(filter, &count, __NR_umount2);
#endif
#ifdef __NR_pivot_root
    deny_syscall(filter, &count, __NR_pivot_root);
#endif
#ifdef __NR_setns
    deny_syscall(filter, &count, __NR_setns);
#endif
#ifdef __NR_unshare
    deny_syscall(filter, &count, __NR_unshare);
#endif
#ifdef __NR_clone3
    deny_syscall(filter, &count, __NR_clone3);
#endif
#ifdef __NR_io_uring_setup
    deny_syscall(filter, &count, __NR_io_uring_setup);
#endif
#ifdef __NR_io_uring_enter
    deny_syscall(filter, &count, __NR_io_uring_enter);
#endif
#ifdef __NR_io_uring_register
    deny_syscall(filter, &count, __NR_io_uring_register);
#endif
#ifdef __NR_userfaultfd
    deny_syscall(filter, &count, __NR_userfaultfd);
#endif
#ifdef __NR_open_by_handle_at
    deny_syscall(filter, &count, __NR_open_by_handle_at);
#endif
#ifdef __NR_name_to_handle_at
    deny_syscall(filter, &count, __NR_name_to_handle_at);
#endif
    guard_clone_namespaces(filter, &count);
    guard_network_ioctl(filter, &count);
    guard_socket_allowlist(filter, &count);
    emit_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog program = {.len = (unsigned short)count, .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        fail("sandbox_seccomp_failed");
    }
}

static void set_limits(void) {
    const struct rlimit core = {0, 0};
    const struct rlimit files = {65536, 65536};
    const struct rlimit processes = {4096, 4096};
    const struct rlimit memory = {1536ULL * 1024 * 1024, 1536ULL * 1024 * 1024};
    const struct rlimit output = {128ULL * 1024 * 1024, 128ULL * 1024 * 1024};
    if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_NOFILE, &files) ||
        setrlimit(RLIMIT_NPROC, &processes) || setrlimit(RLIMIT_AS, &memory) ||
        setrlimit(RLIMIT_FSIZE, &output)) {
        fail("sandbox_rlimit_failed");
    }
}

int main(int argc, char **argv) {
    if (argc != 7 || strcmp(argv[1], "--binary") || strcmp(argv[3], "--config") ||
        strcmp(argv[5], "--state")) {
        fail("sandbox_usage_invalid");
    }
    if (geteuid() == 0 || getegid() == 0) fail("sandbox_root_forbidden");
    validate_paths(argv[2], argv[4], argv[6]);
    validate_capabilities();
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) fail("sandbox_prctl_failed");
    set_limits();
    if (chdir(argv[6]) != 0) fail("sandbox_path_invalid");
    umask(0077);
    install_seccomp();
    char *binary = argv[2], *config = argv[4], *state = argv[6];
    char *const child_argv[] = {binary, "-d", state, "-f", config, NULL};
    if (clearenv() != 0 || setenv("HOME", state, 1) || setenv("TMPDIR", state, 1) ||
        setenv("PATH", "/usr/bin:/bin", 1) || setenv("LANG", "C", 1)) {
        fail("sandbox_environment_failed");
    }
    execv(binary, child_argv);
    fail("sandbox_exec_failed");
    return 126;
}
