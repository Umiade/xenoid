// xenoid_kmod.c — Xenoid kernel module: bottom-layer environment virtualization.
//
// v1 scope (per P2 decision):
//  - open/openat: block hidden paths AFTER successful open (fd inspection, -ENOENT)
//  - stat/access family: block hidden paths by filename stash (-ENOENT)
//  - seq_read: sanitize proc text surfaces in place (mountinfo/mounts/cgroup,
//    cpuinfo, meminfo, status, uid/gid maps, kallsyms, cmdline, version...)
//  - uname / sched_getaffinity / sysinfo / statfs: post-call shaping
//
// Everything is kprobe/kretprobe based: no syscall table patching or ABI hacks.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/magic.h>
#include <linux/utsname.h>
#include <linux/mm.h>
#include <linux/un.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/nsproxy.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/sysinfo.h>
#include <uapi/linux/android/binder.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xenoid");
MODULE_DESCRIPTION("xenoid bottom-layer environment virtualization");
MODULE_VERSION("0.1.0");


/* ------------------------------------------------------------------ */
/* Marker sets                                                         */
/* ------------------------------------------------------------------ */
static const char *path_markers[] = {
    "magisk", "zygisk", "xposed", "lsposed", "riru", "edxposed",
    "frida", "gum-js-loop", "gum_js_loop", "re.frida",
    "xenoid-overlay", "xenoid-profile", "xenoid-frida", "xenoid-hide",
    "libxenoid", ".fs64", ".netd-helper", "xenoid-hook",
    "su.bin", "superuser", "Superuser",
    "lxcfs", "dufs", "isulad", "lxc_volumns", "/lxc/",
    "armcloud", "xu_daemon", "ro.gl.", "ro.com.cph",
    "/data/system/.core/",
    "/proc/fs/jbd2",
    "redroid", "waydroid", "anbox",
    "docker", "containerd", "overlayfs", "upperdir", "lowerdir", "workdir",
    "dexguard", "dgbpf", "bpfdomain", "console_agent",
    "tricky_store", "trickystore", "zygoteisk",
    "adbd_config_prop",
    "/dev/socket/adbd",
    NULL
};

static bool str_has_any(const char *s, const char **markers)
{
    int i;
    if (!s) return false;
    for (i = 0; markers[i]; i++)
        if (strstr(s, markers[i])) return true;
    return false;
}

static bool path_has_dotdot_component(const char *path)
{
    const char *dotdot;

    if (!path) return false;
    dotdot = path;
    while ((dotdot = strstr(dotdot, "..")) != NULL) {
        if ((dotdot == path || dotdot[-1] == '/') &&
            (dotdot[2] == '/' || dotdot[2] == '\0'))
            return true;
        dotdot += 2;
    }
    return false;
}

static uid_t current_android_appid(void)
{
    return from_kuid_munged(current_user_ns(), current_euid()) % 100000;
}

static bool current_is_isolated_android_app(void)
{
    uid_t appid = current_android_appid();
    return appid >= 90000 && appid < 100000;
}

static bool current_is_android_app(void)
{
    uid_t appid = current_android_appid();
    return appid >= 10000 && appid < 100000;
}

/* Scope every Android compatibility hook to the runtime's network namespace.
 * Host init_net and unrelated containers do not own rmnet_data0. */
static bool net_is_xenoid_android_runtime(struct net *net)
{
    bool present;

    if (!net)
        return false;
    rcu_read_lock();
    present = dev_get_by_name_rcu(net, "rmnet_data0") != NULL;
    rcu_read_unlock();
    return present;
}

static bool current_net_is_xenoid_android_runtime(void)
{
    if (!current->nsproxy)
        return false;
    return net_is_xenoid_android_runtime(current->nsproxy->net_ns);
}

static bool current_is_xenoid_android_app(void)
{
    return current_is_android_app() &&
           current_net_is_xenoid_android_runtime();
}


/* Raw syscall views must agree with the procfs and libc surfaces. Hook the
 * internal producers, while their kernel buffers are still writable, so no
 * user-memory access occurs from kprobe context. */
#define XENOID_MEMORY_TOTAL_BYTES (12ULL * 1024ULL * 1024ULL * 1024ULL)
#define XENOID_MEMORY_FREE_BYTES  (XENOID_MEMORY_TOTAL_BYTES / 2ULL)

struct sysinfo_ctx {
	struct sysinfo *info;
	bool shape;
};

static int sysinfo_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sysinfo_ctx *ctx = (void *)ri->data;

	ctx->info = (struct sysinfo *)regs->regs[0];
	ctx->shape = current_is_android_app() &&
		     current_net_is_xenoid_android_runtime();
	return 0;
}

static int sysinfo_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sysinfo_ctx *ctx = (void *)ri->data;
	struct sysinfo *info = ctx->info;

	if (!ctx->shape || !info)
		return 0;
	info->totalram = (unsigned long)XENOID_MEMORY_TOTAL_BYTES;
	info->freeram = (unsigned long)XENOID_MEMORY_FREE_BYTES;
	info->sharedram = (unsigned long)(XENOID_MEMORY_TOTAL_BYTES / 48ULL);
	info->bufferram = (unsigned long)(XENOID_MEMORY_TOTAL_BYTES / 96ULL);
	info->totalswap = 0;
	info->freeswap = 0;
	info->totalhigh = 0;
	info->freehigh = 0;
	info->mem_unit = 1;
	return 0;
}

static struct kretprobe sysinfo_kprobes[] = {
	{
		.handler = sysinfo_post,
		.entry_handler = sysinfo_pre,
		.data_size = sizeof(struct sysinfo_ctx),
		.kp = { .symbol_name = "do_sysinfo" },
		.maxactive = 32,
	},
	{
		.handler = sysinfo_post,
		.entry_handler = sysinfo_pre,
		.data_size = sizeof(struct sysinfo_ctx),
		.kp = { .symbol_name = "do_sysinfo.isra.0" },
		.maxactive = 32,
	},
	{
		.handler = sysinfo_post,
		.entry_handler = sysinfo_pre,
		.data_size = sizeof(struct sysinfo_ctx),
		.kp = { .symbol_name = "do_sysinfo.constprop.0" },
		.maxactive = 32,
	},
};

#ifndef F2FS_SUPER_MAGIC
#define F2FS_SUPER_MAGIC 0xF2F52010
#endif

struct statfs_ctx {
	struct kstatfs *buf;
	bool shape;
};

static bool dentry_is_android_data(const struct dentry *dentry)
{
	const struct dentry *cursor = dentry;
	const struct super_block *sb = dentry ? dentry->d_sb : NULL;

	/*
	 * The Android runtime's writable ext4 mounts all come from its userdata
	 * volume. Raven exposes that volume as F2FS. The optimized vfs_statfs
	 * clone receives only the vfsmount root, so the writable superblock is
	 * the stable identity for direct /data and its bind mounts.
	 */
	if (sb && READ_ONCE(sb->s_magic) == EXT4_SUPER_MAGIC && !sb_rdonly(sb))
		return true;
	while (cursor) {
		if (cursor->d_name.len == 4 &&
		    !memcmp(cursor->d_name.name, "data", 4) &&
		    cursor->d_parent == cursor->d_sb->s_root)
			return true;
		if (cursor == cursor->d_parent || cursor == cursor->d_sb->s_root)
			break;
		cursor = cursor->d_parent;
	}
	return false;
}

static bool statfs_cloned_abi;
static bool statfs_needs_clone_success;

static int statfs_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct statfs_ctx *ctx = (void *)ri->data;
	const struct dentry *dentry;

	ctx->buf = (struct kstatfs *)regs->regs[1];
	if (statfs_cloned_abi)
		dentry = ((const struct vfsmount *)regs->regs[0])->mnt_root;
	else
		dentry = ((const struct path *)regs->regs[0])->dentry;
	ctx->shape = current_is_android_app() &&
		current_net_is_xenoid_android_runtime() &&
		dentry_is_android_data(dentry);
	return 0;
}

static int statfs_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct statfs_ctx *ctx = (void *)ri->data;

	if (!ctx->shape || !ctx->buf ||
	    (statfs_needs_clone_success && (long)regs_return_value(regs) != 0))
		return 0;
	WRITE_ONCE(ctx->buf->f_type, F2FS_SUPER_MAGIC);
	return 0;
}

static char statfs_symbol[128] = "vfs_statfs";
module_param_string(statfs_symbol, statfs_symbol, sizeof(statfs_symbol), 0444);
MODULE_PARM_DESC(statfs_symbol, "Resolved vfs_statfs implementation symbol");

static struct kretprobe statfs_kp = {
	.handler = statfs_post,
	.entry_handler = statfs_pre,
	.data_size = sizeof(struct statfs_ctx),
	.kp = { .symbol_name = statfs_symbol },
	.maxactive = 32,
};

struct affinity_ctx {
	struct cpumask *mask;
	bool shape;
};

static int affinity_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct affinity_ctx *ctx = (void *)ri->data;

	ctx->mask = (struct cpumask *)regs->regs[1];
	ctx->shape = current_is_android_app() &&
		     current_net_is_xenoid_android_runtime();
	return 0;
}

static int affinity_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct affinity_ctx *ctx = (void *)ri->data;
	int cpu;

	if (!ctx->shape || !ctx->mask || (long)regs_return_value(regs) != 0)
		return 0;
	cpumask_clear(ctx->mask);
	for (cpu = 0; cpu < 8 && cpu < nr_cpu_ids; cpu++)
		cpumask_set_cpu(cpu, ctx->mask);
	return 0;
}

static struct kretprobe affinity_kp = {
	.handler = affinity_post,
	.entry_handler = affinity_pre,
	.data_size = sizeof(struct affinity_ctx),
	.kp = { .symbol_name = "sched_getaffinity" },
	.maxactive = 32,
};

static bool path_hidden(const char *path)
{
    if (!path) return false;
    /* Privileged side (system/shell/root: our daemon, PackageManager scans,
       adbd tooling) and unrelated namespaces always see real paths;
       unprivileged runtime apps get -ENOENT. */
    if (!current_is_xenoid_android_app()) return false;
    /* Stock Android policy keeps the adbd control socket outside app domains. */
    if (!strcmp(path, "/dev/socket/adbd"))
        return true;
    /* Isolated application domains must retain the stock procfs access view. */
    if (current_is_isolated_android_app() && !strcmp(path, "/proc/version"))
        return true;
    return path_has_dotdot_component(path) || str_has_any(path, path_markers);
}


/* ------------------------------------------------------------------ */
/* Per-task filename stash for stat/access blocking                    */
/* ------------------------------------------------------------------ */
#define STASH_SIZE 64
struct path_stash {
    struct task_struct *task;
    char path[256];
};
static struct path_stash stash[STASH_SIZE];
static DEFINE_SPINLOCK(stash_lock);

static void stash_put(const char __user *upath)
{
    unsigned long flags;
    int i;
    char buf[256];
    long n;
    if (!upath) return;
    n = strncpy_from_user(buf, upath, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[sizeof(buf) - 1] = 0;
    if (!path_hidden(buf)) return;
    spin_lock_irqsave(&stash_lock, flags);
    for (i = 0; i < STASH_SIZE; i++) {
        if (stash[i].task == current || stash[i].task == NULL) {
            stash[i].task = current;
            strscpy(stash[i].path, buf, sizeof(stash[i].path));
            spin_unlock_irqrestore(&stash_lock, flags);
            return;
        }
    }
    spin_unlock_irqrestore(&stash_lock, flags);
}

static bool stash_take(void)
{
    unsigned long flags;
    int i;
    bool found = false;
    spin_lock_irqsave(&stash_lock, flags);
    for (i = 0; i < STASH_SIZE; i++) {
        if (stash[i].task == current) {
            found = true;
            stash[i].task = NULL;
            stash[i].path[0] = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&stash_lock, flags);
    return found;
}

/* ------------------------------------------------------------------ */
/* kprobe: open/openat post — close fd and return -ENOENT for hidden   */
/* ------------------------------------------------------------------ */
static int open_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long retval = regs_return_value(regs);
    struct file *f;
    char *buf, *path;
    bool hidden;

    if (retval < 0) return 0;
    f = fget((unsigned int)retval);
    if (!f) return 0;
    buf = kmalloc(512, GFP_ATOMIC);
    if (buf) {
        path = d_path(&f->f_path, buf, 512);
        if (!IS_ERR(path)) {
            /* proc-fd memfds are executable capabilities, not filesystem
             * paths. Frida uses one for explicit inspection; filtering its
             * backing name here breaks dlopen("/proc/self/fd/N"). */
            hidden = strncmp(path, "/memfd:", 7) && path_hidden(path);
            if (hidden) {
                fput(f);
                close_fd((unsigned int)retval);
                regs_set_return_value(regs, -ENOENT);
                kfree(buf);
                return 0;
            }
        }
        kfree(buf);
    }
    fput(f);
    return 0;
}

static struct kretprobe open_kp = {
    .handler = open_post_handler,
    .kp = { .symbol_name = "do_sys_openat2" },
    .maxactive = 32,
};


/* ------------------------------------------------------------------ */
/* kprobe: stat/access — stash filename in pre, veto in post           */
/* ------------------------------------------------------------------ */
static int stat_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pt_regs *sr = (struct pt_regs *)regs->regs[0];
    const char __user *upath = sr ? (const char __user *)sr->regs[1] : NULL;
    stash_put(upath);
    return 0;
}
static int stat_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    if (stash_take())
        regs_set_return_value(regs, -ENOENT);
    return 0;
}
static struct kretprobe stat_kp = {
    .handler = stat_post_handler,
    .entry_handler = stat_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_newfstatat" },
    .maxactive = 32,
};
static struct kretprobe statx_kp = {
    .handler = stat_post_handler,
    .entry_handler = stat_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_statx" },
    .maxactive = 32,
};
static struct kretprobe access_kp = {
    .handler = stat_post_handler,
    .entry_handler = stat_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_faccessat2" },
    .maxactive = 32,
};
static struct kretprobe faccessat_kp = {
    .handler = stat_post_handler,
    .entry_handler = stat_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_faccessat" },
    .maxactive = 32,
};

/* Keep filename-backed filesystem probes consistent across the syscall family. */
static struct kretprobe unlinkat_kp = {
    .handler = stat_post_handler,
    .entry_handler = stat_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_unlinkat" },
    .maxactive = 32,
};

/* Normalize generated executable mapping labels in procfs before userspace
 * consumers copy the records. */
struct maps_seq_ctx {
    struct seq_file *seq;
    size_t count;
};

static bool bounded_has(const char *buf, size_t len, const char *needle)
{
    size_t needle_len;
    size_t i;

    if (!buf || !needle) return false;
    needle_len = strlen(needle);
    if (!needle_len || len < needle_len) return false;
    for (i = 0; i + needle_len <= len; i++)
        if (!memcmp(buf + i, needle, needle_len))
            return true;
    return false;
}
static char *bounded_find(char *buf, size_t len, const char *needle)
{
    size_t needle_len;
    size_t i;

    if (!buf || !needle) return NULL;
    needle_len = strlen(needle);
    if (!needle_len || len < needle_len) return NULL;
    for (i = 0; i + needle_len <= len; i++)
        if (!memcmp(buf + i, needle, needle_len))
            return buf + i;
    return NULL;
}

/* ART materializes part of the boot image through sealed memfds on hosts
 * without ashmem. Expose those mappings under their logical Android system
 * artifact paths rather than leaking the backing implementation. */
static size_t normalize_art_boot_memfd(char *record, size_t len)
{
    static const char prefix[] = "/memfd:/system/framework/arm64/boot-";
    static const char deleted_suffix[] = " (deleted)";
    char *path;
    char *deleted;
    size_t offset;

    path = bounded_find(record, len, prefix);
    if (!path ||
        (!bounded_has(path, len - (size_t)(path - record), ".oat (deleted)") &&
         !bounded_has(path, len - (size_t)(path - record), ".vdex (deleted)") &&
         !bounded_has(path, len - (size_t)(path - record), ".art (deleted)")))
        return len;

    offset = (size_t)(path - record);
    memmove(path, path + 7, len - offset - 7);
    len -= 7;
    deleted = bounded_find(record + offset, len - offset, deleted_suffix);
    if (!deleted)
        return len;
    offset = (size_t)(deleted - record);
    memmove(deleted, deleted + sizeof(deleted_suffix) - 1,
            len - offset - (sizeof(deleted_suffix) - 1));
    return len - (sizeof(deleted_suffix) - 1);
}


/* Keep Android linker text mappings consistent with executable ELF
 * permissions without changing mapped bytes. */
static void normalize_linker_text_perm(char *buf, size_t len)
{
    size_t i;

    if (!bounded_has(buf, len, "/apex/com.android.runtime/bin/linker64"))
        return;
    for (i = 0; i + 4 <= len; i++) {
        if (!memcmp(buf + i, "rwxp", 4)) {
            buf[i + 1] = '-';
            return;
        }
    }
}


static int maps_seq_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct maps_seq_ctx *ctx = (void *)ri->data;
    struct seq_file *seq = (struct seq_file *)regs->regs[0];

    if (!current_is_xenoid_android_app() || !seq)
        return 1;
    ctx->seq = seq;
    ctx->count = seq->count;
    return 0;
}

static int maps_seq_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct maps_seq_ctx *ctx = (void *)ri->data;
    struct seq_file *seq = ctx->seq;
    char *record;
    size_t record_len;

    if (!seq || !seq->buf || seq->count <= ctx->count)
        return 0;
    record = seq->buf + ctx->count;
    record_len = seq->count - ctx->count;
    if (bounded_has(record, record_len, "[anon:swiftshader_jit]")) {
        seq->count = ctx->count;
        return 0;
    }
    normalize_linker_text_perm(record, record_len);
    record_len = normalize_art_boot_memfd(record, record_len);
    seq->count = ctx->count + record_len;
    return 0;
}


static struct kretprobe maps_seq_kp = {
    .handler = maps_seq_post,
    .entry_handler = maps_seq_pre,
    .data_size = sizeof(struct maps_seq_ctx),
    .kp = { .symbol_name = "show_map" },
    .maxactive = 64,
};

static struct kretprobe smaps_seq_kp = {
    .handler = maps_seq_post,
    .entry_handler = maps_seq_pre,
    .data_size = sizeof(struct maps_seq_ctx),
    .kp = { .symbol_name = "show_smap" },
    .maxactive = 64,
};
/* Protection files are mounted from a daemon-owned private staging tree.
 * Keep those implementation mounts out of application procfs views while
 * preserving the underlying Android partition mounts. */
static int mount_seq_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct maps_seq_ctx *ctx = (void *)ri->data;
    struct seq_file *seq = (struct seq_file *)regs->regs[0];

    if (!current_is_android_app() || !current_net_is_xenoid_android_runtime() ||
        !seq)
        return 1;
    ctx->seq = seq;
    ctx->count = seq->count;
    return 0;
}

static int mount_seq_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct maps_seq_ctx *ctx = (void *)ri->data;
    struct seq_file *seq = ctx->seq;
    char *record;
    size_t record_len;

    if (!seq || !seq->buf || seq->count <= ctx->count)
        return 0;
    record = seq->buf + ctx->count;
    record_len = seq->count - ctx->count;
    if (bounded_has(record, record_len, " /overlay.d/") ||
        bounded_has(record, record_len, " /data/system/.core/"))
        seq->count = ctx->count;
    return 0;
}

static struct kretprobe mountinfo_seq_kp = {
    .handler = mount_seq_post,
    .entry_handler = mount_seq_pre,
    .data_size = sizeof(struct maps_seq_ctx),
    .kp = { .symbol_name = "show_mountinfo" },
    .maxactive = 64,
};

static struct kretprobe mounts_seq_kp = {
    .handler = mount_seq_post,
    .entry_handler = mount_seq_pre,
    .data_size = sizeof(struct maps_seq_ctx),
    .kp = { .symbol_name = "show_vfsmnt" },
    .maxactive = 64,
};

static struct kretprobe mountstats_seq_kp = {
    .handler = mount_seq_post,
    .entry_handler = mount_seq_pre,
    .data_size = sizeof(struct maps_seq_ctx),
    .kp = { .symbol_name = "show_vfsstat" },
    .maxactive = 64,
};


/* Capture readlinkat paths at entry and apply path policy at return.
 * Do not inspect or suppress anonymous-fd targets: those are process-owned
 * capabilities, not hidden filesystem paths, and explicit Frida inspection
 * injects through /proc/self/fd/N. */
struct readlink_saved_args {
    int hide_path;
};
static int readlink_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct readlink_saved_args *saved = (struct readlink_saved_args *)ri->data;
    struct pt_regs *sr = (struct pt_regs *)regs->regs[0];
    const char __user *upath = sr ? (const char __user *)sr->regs[1] : NULL;
    char path[128];

    saved->hide_path = 0;
    if (!upath)
        return 0;
    memset(path, 0, sizeof(path));
    if (strncpy_from_user(path, upath, sizeof(path) - 1) <= 0)
        return 0;
    if (path_hidden(path))
        saved->hide_path = 1;
    return 0;
}
static int readlink_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct readlink_saved_args *saved = (struct readlink_saved_args *)ri->data;
    if (saved->hide_path)
        regs_set_return_value(regs, -ENOENT);
    return 0;
}
static struct kretprobe readlink_kp = {
    .handler = readlink_post_handler,
    .entry_handler = readlink_pre_handler,
    .kp = { .symbol_name = "__arm64_sys_readlinkat" },
    .data_size = sizeof(struct readlink_saved_args),
    .maxactive = 32,
};



/* Synthesize Android SELinux context surfaces when the host security module is
 * inactive. Handlers operate only on kernel buffers. */
#include <linux/cred.h>
#include <linux/uidgid.h>

static bool inode_name_matches(struct inode *inode, const char *value, bool suffix)
{
	struct dentry *d;
	size_t value_len;
	bool matches = false;

	if (!inode || !value || !spin_trylock(&inode->i_lock))
		return false;
	value_len = strlen(value);
	hlist_for_each_entry(d, &inode->i_dentry, d_u.d_alias) {
		const char *name;
		size_t name_len;

		if (!spin_trylock(&d->d_lock))
			continue;
		name = d->d_name.name;
		name_len = d->d_name.len;
		if (name && ((!suffix && name_len == value_len &&
			      !memcmp(name, value, value_len)) ||
			     (suffix && name_len >= value_len &&
			      !memcmp(name + name_len - value_len, value, value_len))))
			matches = true;
		spin_unlock(&d->d_lock);
		if (matches)
			break;
	}
	spin_unlock(&inode->i_lock);
	return matches;
}
static bool dentry_name_is_decimal(const struct dentry *d)
{
	size_t i;

	if (!d->d_name.len)
		return false;
	for (i = 0; i < d->d_name.len; i++) {
		if (d->d_name.name[i] < '0' || d->d_name.name[i] > '9')
			return false;
	}
	return true;
}

static bool dentry_name_matches(const struct dentry *dentry, const char *name)
{
	size_t length;

	if (!dentry || !dentry->d_name.name || !name)
		return false;
	length = strlen(name);
	return dentry->d_name.len == length &&
	       !memcmp(dentry->d_name.name, name, length);
}

static bool inode_has_decimal_name(struct inode *inode)
{
	struct dentry *d;
	bool matches = false;

	if (!inode || !spin_trylock(&inode->i_lock))
		return false;
	hlist_for_each_entry(d, &inode->i_dentry, d_u.d_alias) {
		bool decimal;

		if (!spin_trylock(&d->d_lock))
			continue;
		decimal = dentry_name_is_decimal(d);
		spin_unlock(&d->d_lock);
		if (decimal) {
			matches = true;
			break;
		}
	}
	spin_unlock(&inode->i_lock);
	return matches;
}

static const char *domain_for_uid(uid_t uid, char *buf, size_t buflen);


static const char *proc_label_for_inode(struct inode *inode,
					char *buf, size_t buflen)
{
	uid_t uid;

	if (inode_name_matches(inode, "attr", false) ||
	    inode_name_matches(inode, "current", false) ||
	    inode_name_matches(inode, "exec", false) ||
	    inode_name_matches(inode, "prev", false))
		return "u:object_r:proc_security:s0";
	if (inode_has_decimal_name(inode)) {
		uid = i_uid_read(inode);
		return domain_for_uid(uid, buf, buflen);
	}
	return "u:object_r:proc:s0";
}

static const char *proc_label_for_dentry(struct dentry *dentry,
					 char *buf, size_t buflen)
{
	struct inode *inode;
	uid_t uid;

	if (dentry_name_matches(dentry, "attr") ||
	    dentry_name_matches(dentry, "current") ||
	    dentry_name_matches(dentry, "exec") ||
	    dentry_name_matches(dentry, "prev"))
		return "u:object_r:proc_security:s0";
	if (dentry_name_is_decimal(dentry)) {
		inode = d_inode(dentry);
		if (!inode)
			return NULL;
		uid = i_uid_read(inode);
		return domain_for_uid(uid, buf, buflen);
	}
	return "u:object_r:proc:s0";
}

static bool inode_name_has_suffix(struct inode *inode, const char *suffix)
{
	return inode_name_matches(inode, suffix, true);
}

static bool is_android_data_apk(struct inode *inode)
{
	uid_t uid;

	if (!inode || !S_ISREG(inode->i_mode) || !inode_name_has_suffix(inode, ".apk"))
		return false;
	uid = i_uid_read(inode);
	return uid == 1000;
}

/* security_inode_getsecurity(idmap, inode, name, &buffer, alloc) */
struct igs_ctx {
	struct inode *inode;
	const char *name;
	void **buffer;
	bool alloc;
	bool android_runtime;
};
static int igs_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct igs_ctx *c = (void *)ri->data;
	c->inode = (struct inode *)regs->regs[1];
	c->name = (const char *)regs->regs[2];
	c->buffer = (void **)regs->regs[3];
	c->alloc = regs->regs[4] != 0;
	c->android_runtime = current_net_is_xenoid_android_runtime();
	return 0;
}
static int igs_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct igs_ctx *c = (void *)ri->data;
	long ret = (long)(int)regs_return_value(regs);
	const char *fsname, *label = NULL;
	char tmp[64];
	size_t len;

	if (!c->android_runtime || ret >= 0 || !c->name || !c->buffer)
		return 0;
	if (strcmp(c->name, "selinux") != 0)
		return 0;
	if (!c->inode || !c->inode->i_sb || !c->inode->i_sb->s_type)
		return 0;
	fsname = c->inode->i_sb->s_type->name;
	if (!fsname)
		return 0;
	if (!strcmp(fsname, "proc"))
		label = proc_label_for_inode(c->inode, tmp, sizeof(tmp));
	else if (!strcmp(fsname, "sysfs"))
		label = "u:object_r:sysfs:s0";
	else if (is_android_data_apk(c->inode))
		label = "u:object_r:apk_data_file:s0";
	else
		return 0;
	len = strlen(label) + 1;
	if (c->alloc) {
		void *replacement = kstrdup(label, GFP_ATOMIC);
		if (!replacement)
			return 0;
		*c->buffer = replacement;
	}
	regs_set_return_value(regs, len);
	return 0;
}
static struct kretprobe igs_kp = {
	.handler = igs_post,
	.entry_handler = igs_pre,
	.data_size = sizeof(struct igs_ctx),
	.kp = { .symbol_name = "security_inode_getsecurity" },
	.maxactive = 32,
};

/* security_getprocattr(task, name, &value) */
struct gpa_ctx {
	struct task_struct *task;
	const char *name;
	char **value;
	bool android_runtime;
};
static int gpa_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gpa_ctx *c = (void *)ri->data;
	c->task = (struct task_struct *)regs->regs[0];
	c->name = (const char *)regs->regs[1];
	c->value = (char **)regs->regs[2];
	c->android_runtime = current_net_is_xenoid_android_runtime();
	return 0;
}

static const char *domain_for_uid(uid_t uid, char *buf, size_t buflen)
{
	unsigned int appid;
	unsigned int userid = uid / 100000;
	unsigned int category;
	switch (uid) {
	case 0: return "u:r:init:s0";
	case 1000: return "u:r:system_server:s0";
	case 1001: return "u:r:radio:s0";
	case 1002: return "u:r:bluetooth:s0";
	case 1010: return "u:r:wifi:s0";
	case 1013: return "u:r:media:s0";
	case 1017: return "u:r:keystore:s0";
	case 1018: return "u:r:usb:s0";
	case 1019: return "u:r:drm:s0";
	case 1021: return "u:r:gps:s0";
	case 1032: return "u:r:logd:s0";
	case 1053: return "u:r:webview_zygote:s0";
	case 1068: return "u:r:statsd:s0";
	case 2000: return "u:r:shell:s0";
	case 9999: return "u:r:nobody:s0";
	default: break;
	}
	appid = uid % 100000;
	if (appid >= 90000 && appid < 100000) {
		category = appid - 90000;
		snprintf(buf, buflen, "u:r:isolated_app:s0:c%u,c%u,c%u,c%u",
			 category & 0xff, 256 + ((category >> 8) & 0xff),
			 512 + (userid & 0xff), 768 + ((userid >> 8) & 0xff));
		return buf;
	}
	if (appid >= 10000 && appid < 90000) {
		category = appid - 10000;
		snprintf(buf, buflen, "u:r:untrusted_app:s0:c%u,c%u,c%u,c%u",
			 category & 0xff, 256 + ((category >> 8) & 0xff),
			 512 + (userid & 0xff), 768 + ((userid >> 8) & 0xff));
		return buf;
	}
	return "u:r:unconfined:s0";
}

/* Normalize base-image labels before xattr values are copied to userspace.
 * Executable labels follow the caller's process domain. */
struct vfs_xattr_ctx {
	struct dentry *dentry;
	const char *name;
	void *value;
	size_t size;
	bool android_runtime;
};

static int vfs_xattr_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_xattr_ctx *c = (void *)ri->data;

	c->dentry = (struct dentry *)regs->regs[1];
	c->name = (const char *)regs->regs[2];
	c->value = (void *)regs->regs[3];
	c->size = (size_t)regs->regs[4];
	c->android_runtime = current_net_is_xenoid_android_runtime();
	return 0;
}

static int vfs_xattr_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_xattr_ctx *c = (void *)ri->data;
	long ret = (long)(int)regs_return_value(regs);
	const char *label = NULL;
	char tmp[64];
	size_t len;

	if (!c->android_runtime || ret < 0 || !c->dentry || !c->name ||
	    strcmp(c->name, "security.selinux") != 0)
		return 0;
	if (c->dentry->d_name.name &&
	    !strcmp(c->dentry->d_name.name, "exe")) {
		uid_t uid = from_kuid_munged(current_user_ns(), current_euid());

		label = domain_for_uid(uid, tmp, sizeof(tmp));
	} else if (c->dentry->d_sb && c->dentry->d_sb->s_type &&
		   !strcmp(c->dentry->d_sb->s_type->name, "proc")) {
		label = proc_label_for_dentry(c->dentry, tmp, sizeof(tmp));
	} else if (c->dentry->d_sb && c->dentry->d_sb->s_type &&
		   !strcmp(c->dentry->d_sb->s_type->name, "sysfs") &&
		   dentry_name_matches(c->dentry, "selinux")) {
		label = "u:object_r:selinuxfs:s0";
	}
	if (!label)
		return 0;
	/* SELinux xattrs include the trailing NUL in their byte count. Keep the
	 * size probe and an exact-sized read consistent. */
	len = strlen(label) + 1;
	if (c->value && c->size) {
		if (c->size < len) {
			regs_set_return_value(regs, -ERANGE);
			return 0;
		}
		memset(c->value, 0, c->size);
		memcpy(c->value, label, len);
	}
	regs_set_return_value(regs, len);
	return 0;
}

static struct kretprobe vfs_xattr_kp = {
	.handler = vfs_xattr_post,
	.entry_handler = vfs_xattr_pre,
	.data_size = sizeof(struct vfs_xattr_ctx),
	.kp = { .symbol_name = "vfs_getxattr" },
	.maxactive = 32,
};

static int gpa_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gpa_ctx *c = (void *)ri->data;
	long ret = (long)(int)regs_return_value(regs);
	char tmp[64], probe[32];
	const char *label;
	uid_t uid;
	int len;
	char *old, *newv;

	if (!c->android_runtime || !c->value || !c->task || !c->name)
		return 0;
	old = *c->value;
	if (!strcmp(c->name, "exec")) {
		if (ret > 0 && old)
			kfree(old);
		*c->value = NULL;
		regs_set_return_value(regs, 0);
		return 0;
	}
	if (strcmp(c->name, "current") && strcmp(c->name, "prev"))
		return 0;
	if (ret > 0) {
		/* an LSM answered: only override the "unconfined" fallback label */
		if (!old)
			return 0;
		memset(probe, 0, sizeof(probe));
		if (copy_from_kernel_nofault(probe, old, sizeof(probe) - 1))
			return 0;
		if (strncmp(probe, "unconfined", 10) != 0)
			return 0;
	} else if (ret == 0)
		return 0;
	/* ret < 0 (proc falls back to "unconfined") or unconfined label: synthesize */
	uid = from_kuid_munged(current_user_ns(), task_uid(c->task));
	label = domain_for_uid(uid, tmp, sizeof(tmp));
	len = strlen(label);
	newv = kstrdup(label, GFP_ATOMIC);
	if (!newv)
		return 0;
	if (ret > 0 && old)
		kfree(old);
	*c->value = newv;
	regs_set_return_value(regs, len);
	return 0;
}
static struct kretprobe gpa_kp = {
	.handler = gpa_post,
	.entry_handler = gpa_pre,
	.data_size = sizeof(struct gpa_ctx),
	.kp = { .symbol_name = "security_getprocattr" },
	.maxactive = 32,
};
static struct kretprobe aa_gpa_kp = {
	.handler = gpa_post,
	.entry_handler = gpa_pre,
	.data_size = sizeof(struct gpa_ctx),
	.kp = { .symbol_name = "apparmor_getprocattr" },
	.maxactive = 32,
};

/* A real Android SELinux policy denies TIOCSTI with EACCES. Ubuntu's
 * legacy-TIOCSTI gate returns EPERM first; normalize only Xenoid Android app
 * calls so the observable ioctl result matches an enforcing Android device. */
struct tiocsti_ctx { unsigned int command; bool android_app; };
static int tiocsti_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tiocsti_ctx *c = (void *)ri->data;

	c->command = (unsigned int)regs->regs[1];
	c->android_app = current_is_xenoid_android_app();
	return 0;
}
static int tiocsti_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tiocsti_ctx *c = (void *)ri->data;
	long ret = (long)regs_return_value(regs);

	if (c->android_app && c->command == 0x5412 &&
	    (ret == -EPERM || ret == -EIO))
		regs_set_return_value(regs, -EACCES);
	return 0;
}
static struct kretprobe tiocsti_kp = {
	.handler = tiocsti_post,
	.entry_handler = tiocsti_pre,
	.data_size = sizeof(struct tiocsti_ctx),
	.kp = { .symbol_name = "tty_ioctl" },
	.maxactive = 32,
};

/* Android's SELinux policy prevents isolated processes from creating network
 * sockets. The generic Linux kernel permits them, so normalize successful
 * socket creation at the LSM hook that owns the decision. Unix-domain sockets
 * remain available for Binder and local IPC; kernel-originated sockets and
 * pre-existing LSM errors are unchanged. */
struct socket_create_ctx { bool deny; };
static int socket_create_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket_create_ctx *c = (void *)ri->data;
	int family = (int)regs->regs[0];
	int kern = (int)regs->regs[3];

	c->deny = !kern && family != AF_UNIX &&
		  current_is_isolated_android_app() &&
		  current_net_is_xenoid_android_runtime();
	return 0;
}
static int socket_create_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket_create_ctx *c = (void *)ri->data;

	if (c->deny && (long)regs_return_value(regs) == 0)
		regs_set_return_value(regs, -EACCES);
	return 0;
}
static struct kretprobe socket_create_kp = {
	.handler = socket_create_post,
	.entry_handler = socket_create_pre,
	.data_size = sizeof(struct socket_create_ctx),
	.kp = { .symbol_name = "security_socket_create" },
	.maxactive = 32,
};

/* Android isolates untrusted services from ptrace even when both tasks share
 * the same isolated UID. Enforce that domain boundary at the LSM decision
 * point so libc and direct-syscall callers observe the same result. */
struct ptrace_access_ctx { bool deny; };
static int ptrace_access_pre(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct ptrace_access_ctx *c = (void *)ri->data;

	c->deny = current_is_isolated_android_app() &&
		  current_net_is_xenoid_android_runtime();
	return 0;
}
static int ptrace_access_post(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct ptrace_access_ctx *c = (void *)ri->data;

	if (c->deny && (long)regs_return_value(regs) == 0)
		regs_set_return_value(regs, -EPERM);
	return 0;
}
static struct kretprobe ptrace_access_kp = {
	.handler = ptrace_access_post,
	.entry_handler = ptrace_access_pre,
	.data_size = sizeof(struct ptrace_access_ctx),
	.kp = { .symbol_name = "security_ptrace_access_check" },
	.maxactive = 32,
};

/* Ordinary apps may create route-netlink sockets, but privileged RTM_GETLINK
 * requires the Android nlmsg_readpriv permission. Deny only that message at
 * security_netlink_send(); permitted GETADDR/GETROUTE requests and privileged
 * control paths continue to the real rtnetlink producer. */
struct netlink_send_ctx { bool deny; };
static bool skb_requests_rtm_getlink(struct sk_buff *skb)
{
	unsigned int data_len;
	unsigned char *data;

	if (!skb)
		return false;
	data_len = skb->len;
	data = skb->data;
	while (data_len >= nlmsg_total_size(0)) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)data;
		unsigned int msg_len;

		if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > data_len)
			return false;
		if (nlh->nlmsg_type == RTM_GETLINK)
			return true;
		msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msg_len >= data_len)
			return false;
		data_len -= msg_len;
		data += msg_len;
	}
	return false;
}
static int netlink_send_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct netlink_send_ctx *c = (void *)ri->data;
	struct sock *sk = (struct sock *)regs->regs[0];
	struct sk_buff *skb = (struct sk_buff *)regs->regs[1];

	c->deny = false;
	if (!sk || !current_is_android_app() ||
	    sk->sk_family != AF_NETLINK || sk->sk_protocol != NETLINK_ROUTE)
		return 0;
	if (!net_is_xenoid_android_runtime(sock_net(sk)))
		return 0;
	c->deny = skb_requests_rtm_getlink(skb);
	return 0;
}
static int netlink_send_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct netlink_send_ctx *c = (void *)ri->data;

	if (c->deny && (long)regs_return_value(regs) == 0)
		regs_set_return_value(regs, -EACCES);
	return 0;
}
static struct kretprobe netlink_send_kp = {
	.handler = netlink_send_post,
	.entry_handler = netlink_send_pre,
	.data_size = sizeof(struct netlink_send_ctx),
	.kp = { .symbol_name = "security_netlink_send" },
	.maxactive = 32,
};

/* Binder's default onShellCommand permits only root/shell. redroid's host
 * policy does not preserve that Android boundary reliably, allowing app UIDs
 * to issue SHELL_COMMAND_TRANSACTION directly to services such as "package".
 * Change only that framework-reserved transaction code before dispatch; the
 * target then returns UNKNOWN_TRANSACTION and performs no shell command. */
#define XENOID_SHELL_COMMAND_TRANSACTION 0x5f434d44U
static int binder_transaction_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct binder_transaction_data *transaction =
		(struct binder_transaction_data *)regs->regs[2];

	if (!current_is_xenoid_android_app() || !transaction)
		return 0;
	if (READ_ONCE(transaction->code) != XENOID_SHELL_COMMAND_TRANSACTION)
		return 0;
	WRITE_ONCE(transaction->code, 0);
	return 0;
}
static struct kprobe binder_transaction_kp = {
	.pre_handler = binder_transaction_pre,
	.symbol_name = "binder_transaction",
};

/* Provide the SELinux status nodes expected by the Android framework. The
 * context node retains bounded validation for trusted diagnostics; Android
 * application opens are denied by the production eBPF policy. */
#include <linux/kobject.h>
#include <linux/kernfs.h>
static struct kobject *xenoid_selinux_kobj;
static struct kobject *xenoid_selinux_class_kobj;
static struct kobj_attribute context_attr;
static ssize_t enforce_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "1\n");
}
static ssize_t policyvers_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "33\n");
}
static ssize_t mls_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "1\n");
}
static ssize_t checkreqprot_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0\n");
}
static bool selinux_context_authorized(const char *context)
{
	static const char * const categories[] = {
		"s0", "s0:c0", "s0:c0,c1", "s0:c0,c1,c2,c3",
		"s0:c0,c1,c2,c3,c10,c20,c30,c40",
	};
	static const char * const types[] = {
		"app_zygote", "dex2oat", "init", "isolated_app", "kernel",
		"logd", "nobody", "radio", "shell", "system_server",
		"untrusted_app", "usb", "wifi", "zygote",
	};
	static const char * const files[] = {
		"adb_data_file", "apk_data_file", "dex2oat_exec", "proc",
		"proc_process", "proc_security", "rootfs", "selinuxfs",
		"system_data_file", "system_file", "tmpfs",
	};
	char role[16];
	char type[96];
	const char *category;
	const char *cursor;
	size_t i, length;

	if (strncmp(context, "u:", 2))
		return false;
	cursor = strchr(context + 2, ':');
	if (!cursor || cursor == context + 2)
		return false;
	length = cursor - (context + 2);
	if (length >= sizeof(role))
		return false;
	memcpy(role, context + 2, length);
	role[length] = '\0';

	cursor++;
	category = strchr(cursor, ':');
	if (!category || category == cursor)
		return false;
	length = category - cursor;
	if (length >= sizeof(type))
		return false;
	memcpy(type, cursor, length);
	type[length] = '\0';
	category++;

	if (!strcmp(role, "r")) {
		for (i = 0; i < ARRAY_SIZE(types); i++) {
			if (!strcmp(type, types[i]))
				goto found;
		}
		return false;
	}
	if (strcmp(role, "object_r"))
		return false;
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		if (!strcmp(type, files[i]))
			goto found;
	}
	return false;
found:
	for (i = 0; i < ARRAY_SIZE(categories); i++) {
		if (!strcmp(category, categories[i]))
			return true;
	}
	return false;
}
static ssize_t context_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	char context[128];
	size_t length = min(count, sizeof(context) - 1);
	bool authorized;

	if (count == 0)
		return 0;
	memcpy(context, buf, length);
	context[length] = '\0';
	strim(context);
	authorized = selinux_context_authorized(context);
	return authorized ? (ssize_t)count : -EINVAL;
}
static int selinux_context_create_file(void)
{
	int ret;

	ret = sysfs_create_file_ns(xenoid_selinux_kobj, &context_attr.attr, NULL);
	if (ret)
		return ret;
	ret = sysfs_chmod_file(xenoid_selinux_kobj, &context_attr.attr, 0666);
	if (ret)
		sysfs_remove_file_ns(xenoid_selinux_kobj, &context_attr.attr, NULL);
	return ret;
}
static void selinux_context_remove_file(void)
{
	sysfs_remove_file_ns(xenoid_selinux_kobj, &context_attr.attr, NULL);
}
static struct kobj_attribute context_attr = __ATTR_WO(context);

struct selinux_named_attr {
	struct kobj_attribute kattr;
	const char *text;
};
static ssize_t selinux_class_show(struct kobject *kobj, struct kobj_attribute *attr,
				  char *buf)
{
	struct selinux_named_attr *named =
		container_of(attr, struct selinux_named_attr, kattr);

	return sysfs_emit(buf, "%s", named->text);
}
#define SELINUX_CLASS_ATTR(_name, _text) \
	static struct selinux_named_attr selinux_attr_##_name = { \
		.kattr = { \
			.attr = { .name = __stringify(_name), .mode = 0444 }, \
			.show = selinux_class_show, \
			.store = NULL, \
		}, \
		.text = _text \
	}
SELINUX_CLASS_ATTR(search, "7\n");
SELINUX_CLASS_ATTR(open, "11\n");
SELINUX_CLASS_ATTR(read, "1\n");
SELINUX_CLASS_ATTR(write, "2\n");
SELINUX_CLASS_ATTR(execute, "4\n");
SELINUX_CLASS_ATTR(execute_no_trans, "9\n");
SELINUX_CLASS_ATTR(associate, "9\n");
SELINUX_CLASS_ATTR(setcurrent, "11\n");
SELINUX_CLASS_ATTR(execmem, "14\n");
SELINUX_CLASS_ATTR(transition, "8\n");
SELINUX_CLASS_ATTR(check_context, "7\n");
#define SELINUX_INDEX_ATTR(_name, _text) \
	static struct selinux_named_attr selinux_index_##_name = { \
		.kattr = { \
			.attr = { .name = "index", .mode = 0444 }, \
			.show = selinux_class_show, \
			.store = NULL, \
		}, \
		.text = _text \
	}
SELINUX_INDEX_ATTR(dir, "5\n");
SELINUX_INDEX_ATTR(fifo_file, "8\n");
SELINUX_INDEX_ATTR(file, "16\n");
SELINUX_INDEX_ATTR(filesystem, "32\n");
SELINUX_INDEX_ATTR(process, "51\n");
SELINUX_INDEX_ATTR(security, "58\n");
struct selinux_class_dir {
	const char *name;
	struct attribute *index;
	struct attribute **attrs;
	struct kobject *kobj;
	struct kobject *perms;
};
static struct attribute *selinux_perm_dir_attrs[] = {
	&selinux_attr_search.kattr.attr, NULL,
};
static struct attribute *selinux_perm_fifo_attrs[] = {
	&selinux_attr_open.kattr.attr, NULL,
};
static struct attribute *selinux_perm_file_attrs[] = {
	&selinux_attr_read.kattr.attr,
	&selinux_attr_write.kattr.attr,
	&selinux_attr_execute.kattr.attr,
	&selinux_attr_execute_no_trans.kattr.attr,
	NULL,
};
static struct attribute *selinux_perm_filesystem_attrs[] = {
	&selinux_attr_associate.kattr.attr, NULL,
};
static struct attribute *selinux_perm_process_attrs[] = {
	&selinux_attr_setcurrent.kattr.attr,
	&selinux_attr_execmem.kattr.attr,
	&selinux_attr_transition.kattr.attr,
	NULL,
};
static struct attribute *selinux_perm_security_attrs[] = {
	&selinux_attr_check_context.kattr.attr, NULL,
};
static struct selinux_class_dir selinux_class_dirs[] = {
	{ "dir", &selinux_index_dir.kattr.attr, selinux_perm_dir_attrs, NULL, NULL },
	{ "fifo_file", &selinux_index_fifo_file.kattr.attr, selinux_perm_fifo_attrs, NULL, NULL },
	{ "file", &selinux_index_file.kattr.attr, selinux_perm_file_attrs, NULL, NULL },
	{ "filesystem", &selinux_index_filesystem.kattr.attr, selinux_perm_filesystem_attrs, NULL, NULL },
	{ "process", &selinux_index_process.kattr.attr, selinux_perm_process_attrs, NULL, NULL },
	{ "security", &selinux_index_security.kattr.attr, selinux_perm_security_attrs, NULL, NULL },
};

/*
 * The host has no loaded SELinux policy, so this node is metadata only.
 * Production eBPF denies Android application opens with EACCES, matching
 * AOSP's untrusted_app neverallow. Trusted callers receive EOPNOTSUPP rather
 * than fabricated access-vector decisions.
 */
static ssize_t selinux_access_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return 0;
}
static ssize_t selinux_access_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}
static struct kobj_attribute selinux_access_attr =
	__ATTR(access, 0644, selinux_access_show, selinux_access_store);
static int selinux_access_create_file(void)
{
	int ret;

	ret = sysfs_create_file_ns(xenoid_selinux_kobj,
				   &selinux_access_attr.attr, NULL);
	if (ret)
		return ret;
	ret = sysfs_chmod_file(xenoid_selinux_kobj, &selinux_access_attr.attr,
			       0666);
	if (ret)
		sysfs_remove_file_ns(xenoid_selinux_kobj,
				     &selinux_access_attr.attr, NULL);
	return ret;
}
static void selinux_access_remove_file(void)
{
	sysfs_remove_file_ns(xenoid_selinux_kobj, &selinux_access_attr.attr,
			     NULL);
}
static void selinux_class_remove_dirs(void);
static int selinux_class_create_dirs(void)
{
	unsigned int i;
	int ret;

	xenoid_selinux_class_kobj = kobject_create_and_add("class",
							 xenoid_selinux_kobj);
	if (!xenoid_selinux_class_kobj)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(selinux_class_dirs); i++) {
		struct selinux_class_dir *dir = &selinux_class_dirs[i];
		struct kobject *perms;

		dir->kobj = kobject_create_and_add(dir->name,
						   xenoid_selinux_class_kobj);
		if (!dir->kobj) {
			ret = -ENOMEM;
			goto fail;
		}
		ret = sysfs_create_file(dir->kobj, dir->index);
		if (ret)
			goto fail;
		perms = kobject_create_and_add("perms", dir->kobj);
		if (!perms) {
			ret = -ENOMEM;
			goto fail;
		}
		dir->perms = perms;
		ret = sysfs_create_files(perms,
					 (const struct attribute * const *)dir->attrs);
		if (ret)
			goto fail;
	}
	return 0;

fail:
	selinux_class_remove_dirs();
	return ret;
}
static void selinux_class_remove_dirs(void)
{
	unsigned int i;

	for (i = ARRAY_SIZE(selinux_class_dirs); i > 0; i--) {
		struct selinux_class_dir *dir = &selinux_class_dirs[i - 1];

		if (!dir->kobj)
			continue;
		if (dir->perms) {
			sysfs_remove_files(dir->perms,
					   (const struct attribute * const *)dir->attrs);
			kobject_put(dir->perms);
			dir->perms = NULL;
		}
		sysfs_remove_file(dir->kobj, dir->index);
		kobject_put(dir->kobj);
		dir->kobj = NULL;
	}
	if (xenoid_selinux_class_kobj) {
		kobject_put(xenoid_selinux_class_kobj);
		xenoid_selinux_class_kobj = NULL;
	}
}
static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	u32 values[5] = { 1, 0, 1, 1, 0 };

	memcpy(buf, values, sizeof(values));
	return sizeof(values);
}
static struct kobj_attribute enforce_attr = __ATTR_RO(enforce);
static struct kobj_attribute policyvers_attr = __ATTR_RO(policyvers);
static struct kobj_attribute mls_attr = __ATTR_RO(mls);
static struct kobj_attribute checkreqprot_attr = __ATTR_RO(checkreqprot);
static struct kobj_attribute status_attr = __ATTR_RO(status);
static struct attribute *xenoid_selinux_attrs[] = {
	&enforce_attr.attr,
	&policyvers_attr.attr,
	&mls_attr.attr,
	&checkreqprot_attr.attr,
	&status_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(xenoid_selinux);

/* ------------------------------------------------------------------ */
/* Fake power_supply battery device.
   redroid ships no battery driver, so /sys/class/power_supply/battery is empty
   and healthd/BatteryManager report voltage=0 (a redroid tell). Registering a
   minimal power_supply device gives healthd realistic battery values. */
#include <linux/power_supply.h>
static int enable_battery = 1;
static int battery_level = 83;
static int battery_voltage_mv = 4100;
static int battery_temperature_deci_c = 310;
static int battery_status_android = 3;
static int battery_plugged_android;
static int battery_health_android = 2;
static int battery_present = 1;
static int battery_charge_full_design_uah = 5003000;
static int battery_charge_full_uah = 5003000;
static int battery_charge_counter_uah = 4152490;
module_param(enable_battery, int, 0600);
module_param(battery_level, int, 0600);
module_param(battery_voltage_mv, int, 0600);
module_param(battery_temperature_deci_c, int, 0600);
module_param(battery_status_android, int, 0600);
module_param(battery_plugged_android, int, 0600);
module_param(battery_health_android, int, 0600);
module_param(battery_present, int, 0600);
module_param(battery_charge_full_design_uah, int, 0600);
module_param(battery_charge_full_uah, int, 0600);
module_param(battery_charge_counter_uah, int, 0600);

static int xb_status(void)
{
    switch (battery_status_android) {
    case 2: return POWER_SUPPLY_STATUS_CHARGING;
    case 3: return POWER_SUPPLY_STATUS_DISCHARGING;
    case 4: return POWER_SUPPLY_STATUS_NOT_CHARGING;
    case 5: return POWER_SUPPLY_STATUS_FULL;
    default: return POWER_SUPPLY_STATUS_UNKNOWN;
    }
}

static int xb_health(void)
{
    switch (battery_health_android) {
    case 2: return POWER_SUPPLY_HEALTH_GOOD;
    case 3: return POWER_SUPPLY_HEALTH_OVERHEAT;
    case 4: return POWER_SUPPLY_HEALTH_DEAD;
    case 5: return POWER_SUPPLY_HEALTH_OVERVOLTAGE;
    case 6: return POWER_SUPPLY_HEALTH_UNSPEC_FAILURE;
    case 7: return POWER_SUPPLY_HEALTH_COLD;
    default: return POWER_SUPPLY_HEALTH_UNKNOWN;
    }
}

static enum power_supply_property xb_props[] = {
    POWER_SUPPLY_PROP_STATUS, POWER_SUPPLY_PROP_PRESENT, POWER_SUPPLY_PROP_CAPACITY,
    POWER_SUPPLY_PROP_VOLTAGE_NOW, POWER_SUPPLY_PROP_TEMP, POWER_SUPPLY_PROP_HEALTH,
    POWER_SUPPLY_PROP_TECHNOLOGY, POWER_SUPPLY_PROP_CHARGE_TYPE,
    POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN, POWER_SUPPLY_PROP_CHARGE_FULL,
    POWER_SUPPLY_PROP_CHARGE_COUNTER,
};
static int xb_get_property(struct power_supply *psy, enum power_supply_property psp,
                           union power_supply_propval *val)
{
    switch (psp) {
    case POWER_SUPPLY_PROP_STATUS:        val->intval = xb_status(); break;
    case POWER_SUPPLY_PROP_PRESENT:       val->intval = battery_present; break;
    case POWER_SUPPLY_PROP_CAPACITY:      val->intval = battery_level; break;
    case POWER_SUPPLY_PROP_VOLTAGE_NOW:   val->intval = battery_voltage_mv * 1000; break;
    case POWER_SUPPLY_PROP_TEMP:          val->intval = battery_temperature_deci_c; break;
    case POWER_SUPPLY_PROP_HEALTH:        val->intval = xb_health(); break;
    case POWER_SUPPLY_PROP_TECHNOLOGY:    val->intval = POWER_SUPPLY_TECHNOLOGY_LION; break;
    case POWER_SUPPLY_PROP_CHARGE_TYPE:
        val->intval = battery_plugged_android && battery_status_android == 2
            ? POWER_SUPPLY_CHARGE_TYPE_STANDARD
            : POWER_SUPPLY_CHARGE_TYPE_NONE;
        break;
    case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
        val->intval = battery_charge_full_design_uah;
        break;
    case POWER_SUPPLY_PROP_CHARGE_FULL:
        val->intval = battery_charge_full_uah;
        break;
    case POWER_SUPPLY_PROP_CHARGE_COUNTER:
        val->intval = battery_charge_counter_uah;
        break;
    default: return -EINVAL;
    }
    return 0;
}
static const struct power_supply_desc xb_desc = {
    .name = "battery",
    .type = POWER_SUPPLY_TYPE_BATTERY,
    .properties = xb_props,
    .num_properties = ARRAY_SIZE(xb_props),
    .get_property = xb_get_property,
};
static struct power_supply *xb_psy;

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */
static struct kretprobe *rprobes[] = {
    &open_kp, &stat_kp, &statx_kp, &access_kp,
    &faccessat_kp, &unlinkat_kp, &readlink_kp, &maps_seq_kp, &smaps_seq_kp,
    &mountinfo_seq_kp, &mounts_seq_kp, &mountstats_seq_kp,
    &affinity_kp, &statfs_kp,
};
static struct kretprobe *seclabel_rprobes[] = {
    &igs_kp, &vfs_xattr_kp, &gpa_kp, &aa_gpa_kp, &tiocsti_kp,
    &socket_create_kp, &ptrace_access_kp, &netlink_send_kp,
};
static unsigned int rprobes_registered;
static unsigned int seclabel_rprobes_registered;
static struct kretprobe *sysinfo_registered;
static bool binder_transaction_registered;
static bool selinux_groups_registered;
static bool selinux_context_registered;
static bool selinux_access_registered;
static bool selinux_class_registered;

static void unregister_protection(void)
{
    if (xb_psy) {
        power_supply_unregister(xb_psy);
        xb_psy = NULL;
    }
    while (rprobes_registered > 0) {
        rprobes_registered--;
        unregister_kretprobe(rprobes[rprobes_registered]);
    }
    if (sysinfo_registered) {
        unregister_kretprobe(sysinfo_registered);
        sysinfo_registered = NULL;
    }
    if (binder_transaction_registered) {
        unregister_kprobe(&binder_transaction_kp);
        binder_transaction_registered = false;
    }
    while (seclabel_rprobes_registered > 0) {
        seclabel_rprobes_registered--;
        unregister_kretprobe(seclabel_rprobes[seclabel_rprobes_registered]);
    }
    if (selinux_class_registered) {
        selinux_class_remove_dirs();
        selinux_class_registered = false;
    }
    if (xenoid_selinux_kobj) {
        if (selinux_access_registered) {
            selinux_access_remove_file();
            selinux_access_registered = false;
        }
        if (selinux_context_registered) {
            selinux_context_remove_file();
            selinux_context_registered = false;
        }
        if (selinux_groups_registered) {
            sysfs_remove_groups(xenoid_selinux_kobj, xenoid_selinux_groups);
            selinux_groups_registered = false;
        }
        kobject_put(xenoid_selinux_kobj);
        xenoid_selinux_kobj = NULL;
    }
}

static int __init xenoid_kmod_init(void)
{
    unsigned int i;
    int ret;

    for (i = 0; i < ARRAY_SIZE(seclabel_rprobes); i++) {
        ret = register_kretprobe(seclabel_rprobes[i]);
        if (ret) {
            pr_err("xenoid_kmod: required probe %s failed: %d\n",
                   seclabel_rprobes[i]->kp.symbol_name, ret);
            goto fail;
        }
        seclabel_rprobes_registered++;
    }

    ret = register_kprobe(&binder_transaction_kp);
    if (ret) {
        pr_err("xenoid_kmod: required binder probe failed: %d\n", ret);
        goto fail;
    }
    binder_transaction_registered = true;

    xenoid_selinux_kobj = kobject_create_and_add("selinux", fs_kobj);
    if (!xenoid_selinux_kobj) {
        ret = -ENOMEM;
        pr_err("xenoid_kmod: required selinux kobject failed\n");
        goto fail;
    }
    ret = sysfs_create_groups(xenoid_selinux_kobj, xenoid_selinux_groups);
    if (ret) {
        pr_err("xenoid_kmod: required selinux attributes failed: %d\n", ret);
        goto fail;
    }
    selinux_groups_registered = true;
    ret = selinux_context_create_file();
    if (ret) {
        pr_err("xenoid_kmod: required selinux context node failed: %d\n", ret);
        goto fail;
    }
    selinux_context_registered = true;
    ret = selinux_access_create_file();
    if (ret) {
        pr_err("xenoid_kmod: required selinux access node failed: %d\n", ret);
        goto fail;
    }
    selinux_access_registered = true;
    ret = selinux_class_create_dirs();
    if (ret) {
        pr_err("xenoid_kmod: required selinux class nodes failed: %d\n", ret);
        goto fail;
    }
    selinux_class_registered = true;
    statfs_cloned_abi = strcmp(statfs_symbol, "vfs_statfs") != 0;
    statfs_needs_clone_success =
        !strstr(statfs_symbol, ".part.") && !strstr(statfs_symbol, ".constprop.");

    for (i = 0; i < ARRAY_SIZE(rprobes); i++) {
        ret = register_kretprobe(rprobes[i]);
        if (ret) {
            pr_err("xenoid_kmod: required probe %s failed: %d\n",
                   rprobes[i]->kp.symbol_name, ret);
            goto fail;
        }
        rprobes_registered++;
    }


    for (i = 0; i < ARRAY_SIZE(sysinfo_kprobes); i++) {
        ret = register_kretprobe(&sysinfo_kprobes[i]);
        if (!ret) {
            sysinfo_registered = &sysinfo_kprobes[i];
            break;
        }
    }
    if (!sysinfo_registered) {
        pr_err("xenoid_kmod: required sysinfo producer probe unavailable\n");
        ret = -ENOENT;
        goto fail;
    }

    xb_psy = power_supply_register(NULL, &xb_desc, NULL);
    if (IS_ERR(xb_psy)) {
        ret = PTR_ERR(xb_psy);
        xb_psy = NULL;
        pr_err("xenoid_kmod: required power supply failed: %d\n", ret);
        goto fail;
    }
    power_supply_changed(xb_psy);

    pr_info("xenoid_kmod: loaded with %u required probes\n",
            rprobes_registered + seclabel_rprobes_registered + 2);
    return 0;

fail:
    unregister_protection();
    return ret ? ret : -EINVAL;
}

static void __exit xenoid_kmod_exit(void)
{
    unregister_protection();
    pr_info("xenoid_kmod: unloaded\n");
}

module_init(xenoid_kmod_init);
module_exit(xenoid_kmod_exit);
