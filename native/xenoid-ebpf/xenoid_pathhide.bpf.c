// xenoid_pathhide.bpf.c — host-side path-hide for unprivileged apps (uid>=10000).
// Policy mirrors native/xenoid-kmod path_hidden (marker subset).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define ENOENT 2
#define PATH_BUF 128
#define APP_UID_MIN 10000

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} deny_count SEC(".maps");

static __always_inline void bump_deny(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&deny_count, &key);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Bounded substring search — small enough for clang/verifier. */
static __always_inline bool contains(const char *hay, const char *needle)
{
	int nlen = 0;
	int i, j;

	while (nlen < 24 && needle[nlen])
		nlen++;
	if (nlen == 0)
		return false;

	for (i = 0; i < PATH_BUF - 24; i++) {
		char c = hay[i];

		if (c == 0)
			return false;
		if (c != needle[0])
			continue;
		for (j = 0; j < nlen; j++) {
			if (hay[i + j] != needle[j])
				goto next;
		}
		return true;
next:
		;
	}
	return false;
}

static __always_inline bool path_has_dotdot_component(const char *path)
{
	int i;

	for (i = 0; i < PATH_BUF - 2; i++) {
		char c = path[i];

		if (c == 0)
			return false;
		if (c != '.' || path[i + 1] != '.')
			continue;
		if (i != 0 && path[i - 1] != '/')
			continue;
		if (path[i + 2] == 0 || path[i + 2] == '/')
			return true;
	}
	return false;
}

static __always_inline bool path_hidden(const char *path)
{
	if (!path || !path[0])
		return false;
	if (path_has_dotdot_component(path) ||
	    contains(path, "socket/adbd") ||
	    contains(path, "/data/system/.core/"))
		return true;
	return contains(path, "magisk") ||
	       contains(path, "zygisk") ||
	       contains(path, "lsposed") ||
	       contains(path, "xposed") ||
	       contains(path, "frida") ||
	       contains(path, "gum-js-loop") ||
	       contains(path, "xenoid-") ||
	       contains(path, "libxenoid") ||
	       contains(path, ".fs64") ||
	       contains(path, ".netd-helper") ||
	       contains(path, "redroid") ||
	       contains(path, "waydroid") ||
	       contains(path, "anbox") ||
	       contains(path, "tricky_store") ||
	       contains(path, "trickystore");
}

static __always_inline int should_deny_file(struct file *file)
{
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	char path[PATH_BUF];
	long n;
	int i;

	if (uid < APP_UID_MIN)
		return 0;
	if (!file)
		return 0;

	for (i = 0; i < PATH_BUF; i++)
		path[i] = 0;

	n = bpf_d_path(&file->f_path, path, sizeof(path));
	if (n < 0)
		return 0;
	path[PATH_BUF - 1] = 0;
	if (!path_hidden(path))
		return 0;
	bump_deny();
	return -ENOENT;
}

SEC("lsm/file_open")
int BPF_PROG(xenoid_lsm_file_open, struct file *file)
{
	return should_deny_file(file);
}

SEC("fmod_ret/security_file_open")
int BPF_PROG(xenoid_fmod_security_file_open, struct file *file)
{
	return should_deny_file(file);
}

/* Rewrite application-visible uname fields to the configured Android kernel
 * identity. bpf_probe_write_user is available to this GPL program. */
struct new_utsname_spoof {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} uname_buf SEC(".maps");

SEC("kprobe/__arm64_sys_newuname")
int BPF_KPROBE(xenoid_k_newuname, void *pregs)
{
	__u32 pid = bpf_get_current_pid_tgid();
	__u64 b;
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	if (uid < APP_UID_MIN)
		return 0; /* keep real uname for root/system (modprobe, netd, shell) */
	if (bpf_probe_read_kernel(&b, sizeof(b), pregs) < 0)
		return 0; /* regs->regs[0] = user buffer */
	bpf_map_update_elem(&uname_buf, &pid, &b, BPF_ANY);
	return 0;
}

SEC("kretprobe/__arm64_sys_newuname")
int BPF_KRETPROBE(xenoid_kret_newuname, long ret)
{
	struct new_utsname_spoof u = {
		.sysname = "Linux",
		.nodename = "localhost",
		.release = "5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058",
		.version = "#1 SMP PREEMPT Wed Oct 5 04:00:00 UTC 2022",
		.machine = "aarch64",
		.domainname = "",
	};
	__u32 pid = bpf_get_current_pid_tgid();
	__u64 *bp;
	__u64 address;

	bp = bpf_map_lookup_elem(&uname_buf, &pid);
	if (!bp)
		return 0;
	address = *bp;
	bpf_map_delete_elem(&uname_buf, &pid);
	if (ret < 0)
		return 0;
	bpf_probe_write_user((void *)address, &u, sizeof(u));
	return 0;
}

/* kprobe fallback: read file* via CO-RE from PT_REGS. */
SEC("kprobe/security_file_open")
int BPF_KPROBE(xenoid_kprobe_security_file_open, struct file *file)
{
	int ret = should_deny_file(file);

	if (ret)
		bpf_override_return(ctx, (unsigned long)ret);
	return 0;
}
