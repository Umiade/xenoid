// xenoid_kmod.c — Xenoid kernel module: bottom-layer environment virtualization.
//
// v1 scope (per P2 decision):
//  - open/openat: block hidden paths AFTER successful open (fd inspection, -ENOENT)
//  - stat/access family: block hidden paths by filename stash (-ENOENT)
//  - seq_read: sanitize proc text surfaces in place (mountinfo/mounts/cgroup,
//    cpuinfo, meminfo, status, uid/gid maps, kallsyms, cmdline, version...)
//  - uname / sched_getaffinity / sysinfo / statfs: post-call shaping
//
// Everything is kprobe/kretprobe based: no syscall table patching, no ABI hacks.
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
#include <linux/utsname.h>
#include <linux/mm.h>
#include <linux/un.h>
#include <linux/magic.h>
#include <linux/net.h>
#include <linux/netlink.h>
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



static bool path_hidden(const char *path)
{
    if (!path) return false;
    /* Privileged side (system/shell/root: our daemon, PackageManager scans,
       adbd tooling) always sees real paths; unprivileged apps get -ENOENT. */
    if (current_android_appid() < 10000) return false;
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
            hidden = path_hidden(path);
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

    if (current_android_appid() < 10000 || !seq)
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
    if (bounded_has(record, record_len, "[anon:swiftshader_jit]"))
        seq->count = ctx->count;
    else
        normalize_linker_text_perm(record, record_len);
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

/* Capture readlinkat paths at entry and apply path policy at return. */
struct readlink_saved_args {
    int hide_path;
    int deny_memfd;
};
static int readlink_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct readlink_saved_args *saved = (struct readlink_saved_args *)ri->data;
    struct pt_regs *sr = (struct pt_regs *)regs->regs[0];
    const char __user *upath = sr ? (const char __user *)sr->regs[1] : NULL;
    char path[128];
    char *fdtext;
    long fd;
    struct file *f;
    char *target;
    bool benign = false;

    saved->hide_path = 0;
    saved->deny_memfd = 0;
    if (!upath)
        return 0;
    memset(path, 0, sizeof(path));
    if (strncpy_from_user(path, upath, sizeof(path) - 1) <= 0)
        return 0;
    if (path_hidden(path))
        saved->hide_path = 1;
    if (!current->cred || current->cred->uid.val < 10000)
        return 0;
    if (!strncmp(path, "/proc/self/fd/", 14))
        fdtext = path + 14;
    else if (!strncmp(path, "/proc/", 6)) {
        char *fdpart = strstr(path + 6, "/fd/");
        if (!fdpart)
            return 0;
        fdtext = fdpart + 4;
    } else {
        return 0;
    }
    if (kstrtol(fdtext, 10, &fd) || fd < 0)
        return 0;
    f = fget((unsigned int)fd);
    if (!f)
        return 0;
    target = kmalloc(512, GFP_ATOMIC);
    if (target) {
        char *p = d_path(&f->f_path, target, 512);
        if (!IS_ERR(p)) {
            if (strstr(p, "memfd:fontMap") || strstr(p, "memfd:shared_memory/") ||
                strstr(p, "memfd:gralloc-buffer"))
                benign = true;
            if (!benign && strstr(p, "memfd:") && strstr(p, "(deleted)")) {
                const char *q = strstr(p, "memfd:") + 6;
                int hex = 0, dash = 0;
                for (; *q; q++) {
                    if (*q == '-') dash++;
                    else if ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) hex++;
                    else break;
                }
                benign = dash >= 4 && hex >= 20;
            }
        }
        kfree(target);
    }
    fput(f);
    saved->deny_memfd = benign ? 1 : 0;
    return 0;
}
static int readlink_post_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct readlink_saved_args *saved = (struct readlink_saved_args *)ri->data;
    if (saved->hide_path || saved->deny_memfd)
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

static const char *proc_label_for_inode(struct inode *inode)
{
	if (inode_name_matches(inode, "current", false) ||
	    inode_name_matches(inode, "exec", false) ||
	    inode_name_matches(inode, "prev", false) ||
	    inode_name_matches(inode, "attr", false))
		return "u:object_r:proc_security:s0";
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
struct igs_ctx { struct inode *inode; const char *name; void **buffer; bool alloc; };
static int igs_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct igs_ctx *c = (void *)ri->data;
	c->inode = (struct inode *)regs->regs[1];
	c->name = (const char *)regs->regs[2];
	c->buffer = (void **)regs->regs[3];
	c->alloc = regs->regs[4] != 0;
	return 0;
}
static int igs_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct igs_ctx *c = (void *)ri->data;
	long ret = (long)(int)regs_return_value(regs);
	const char *fsname, *label = NULL;
	int len;

	if (ret >= 0 || !c->name || !c->buffer)
		return 0;
	if (strcmp(c->name, "selinux") != 0)
		return 0;
	if (!c->inode || !c->inode->i_sb || !c->inode->i_sb->s_type)
		return 0;
	fsname = c->inode->i_sb->s_type->name;
	if (!fsname)
		return 0;
	if (!strcmp(fsname, "proc"))
		label = proc_label_for_inode(c->inode);
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
struct gpa_ctx { struct task_struct *task; const char *name; char **value; };
static int gpa_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gpa_ctx *c = (void *)ri->data;
	c->task = (struct task_struct *)regs->regs[0];
	c->name = (const char *)regs->regs[1];
	c->value = (char **)regs->regs[2];
	return 0;
}

static const char *domain_for_uid(uid_t uid, char *buf, size_t buflen)
{
	unsigned int appid;
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
		snprintf(buf, buflen, "u:r:isolated_app:s0:c%u,c256,c512,c768", appid - 90000);
		return buf;
	}
	if (appid >= 10000 && appid < 90000) {
		snprintf(buf, buflen, "u:r:untrusted_app:s0:c%u,c256,c512,c768", appid);
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
};

static int vfs_xattr_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_xattr_ctx *c = (void *)ri->data;

	c->dentry = (struct dentry *)regs->regs[1];
	c->name = (const char *)regs->regs[2];
	c->value = (void *)regs->regs[3];
	c->size = (size_t)regs->regs[4];
	return 0;
}

static int vfs_xattr_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vfs_xattr_ctx *c = (void *)ri->data;
	long ret = (long)(int)regs_return_value(regs);
	char tmp[64];
	const char *label;
	uid_t uid;
	size_t len;

	if (ret < 0 || !c->dentry || !c->name)
		return 0;
	if (strcmp(c->name, "security.selinux") != 0 ||
	    !c->dentry->d_name.name ||
	    strcmp(c->dentry->d_name.name, "exe") != 0)
		return 0;

	uid = from_kuid_munged(current_user_ns(), current_euid());
	label = domain_for_uid(uid, tmp, sizeof(tmp));
	len = strlen(label);
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

	if (!c->value || !c->task)
		return 0;
	if (!c->name || (strcmp(c->name, "current") && strcmp(c->name, "exec") && strcmp(c->name, "prev")))
		return 0;
	old = *c->value;
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
 * legacy-TIOCSTI gate returns EPERM first; normalize only Android app UIDs so
 * the observable ioctl result matches an enforcing Android device. */
struct tiocsti_ctx { unsigned int command; bool android_app; };
static int tiocsti_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tiocsti_ctx *c = (void *)ri->data;
	uid_t uid = from_kuid_munged(current_user_ns(), current_euid());

	c->command = (unsigned int)regs->regs[1];
	c->android_app = uid >= 10000 && uid < 100000;
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

/* Android's appdomain policy never allows route-netlink sockets. The Ubuntu
 * host policy has no equivalent domain, so reproduce the SELinux denial for
 * Android application UIDs while leaving system and Bluetooth UIDs alone. */
struct route_netlink_ctx { bool deny; };
static int route_netlink_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct route_netlink_ctx *c = (void *)ri->data;
	struct pt_regs *syscall_regs = (struct pt_regs *)regs->regs[0];
	uid_t uid = from_kuid_munged(current_user_ns(), current_euid());
	int domain, type, protocol;

	c->deny = false;
	if (!syscall_regs || uid < 10000 || uid >= 100000)
		return 0;
	domain = (int)syscall_regs->regs[0];
	type = (int)syscall_regs->regs[1];
	protocol = (int)syscall_regs->regs[2];
	c->deny = domain == AF_NETLINK && (type & 0xf) == SOCK_RAW &&
		  protocol == NETLINK_ROUTE;
	return 0;
}
static int route_netlink_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct route_netlink_ctx *c = (void *)ri->data;
	long ret = (long)regs_return_value(regs);

	if (!c->deny)
		return 0;
	if (ret >= 0)
		close_fd((unsigned int)ret);
	regs_set_return_value(regs, -EACCES);
	return 0;
}
static struct kretprobe route_netlink_kp = {
	.handler = route_netlink_post,
	.entry_handler = route_netlink_pre,
	.data_size = sizeof(struct route_netlink_ctx),
	.kp = { .symbol_name = "__arm64_sys_socket" },
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
	uid_t uid = from_kuid_munged(current_user_ns(), current_euid());

	if (uid < 10000 || uid >= 100000 || !transaction)
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

/* Provide the SELinux status files expected by the Android framework. */
#include <linux/kobject.h>
static struct kobject *xenoid_selinux_kobj;
static ssize_t enforce_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "1\n");
}
static ssize_t policyvers_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "33\n");
}
static ssize_t permissive_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0\n");
}
static struct kobj_attribute enforce_attr = __ATTR_RO(enforce);
static struct kobj_attribute policyvers_attr = __ATTR_RO(policyvers);
static struct kobj_attribute permissive_attr = __ATTR_RO(permissive);
static struct attribute *xenoid_selinux_attrs[] = {
	&enforce_attr.attr,
	&policyvers_attr.attr,
	&permissive_attr.attr,
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
module_param(enable_battery, int, 0600);

static enum power_supply_property xb_props[] = {
    POWER_SUPPLY_PROP_STATUS, POWER_SUPPLY_PROP_PRESENT, POWER_SUPPLY_PROP_CAPACITY,
    POWER_SUPPLY_PROP_VOLTAGE_NOW, POWER_SUPPLY_PROP_TEMP, POWER_SUPPLY_PROP_HEALTH,
    POWER_SUPPLY_PROP_TECHNOLOGY, POWER_SUPPLY_PROP_CHARGE_TYPE,
};
static int xb_get_property(struct power_supply *psy, enum power_supply_property psp,
                           union power_supply_propval *val)
{
    switch (psp) {
    case POWER_SUPPLY_PROP_STATUS:        val->intval = POWER_SUPPLY_STATUS_DISCHARGING; break;
    case POWER_SUPPLY_PROP_PRESENT:       val->intval = 1; break;
    case POWER_SUPPLY_PROP_CAPACITY:      val->intval = 83; break;
    case POWER_SUPPLY_PROP_VOLTAGE_NOW:   val->intval = 4100000; break;
    case POWER_SUPPLY_PROP_TEMP:          val->intval = 310; break;
    case POWER_SUPPLY_PROP_HEALTH:        val->intval = POWER_SUPPLY_HEALTH_GOOD; break;
    case POWER_SUPPLY_PROP_TECHNOLOGY:    val->intval = POWER_SUPPLY_TECHNOLOGY_LION; break;
    case POWER_SUPPLY_PROP_CHARGE_TYPE:   val->intval = POWER_SUPPLY_CHARGE_TYPE_NONE; break;
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
};
static struct kretprobe *seclabel_rprobes[] = {
    &igs_kp, &vfs_xattr_kp, &gpa_kp, &aa_gpa_kp, &tiocsti_kp, &route_netlink_kp,
};
static unsigned int rprobes_registered;
static unsigned int seclabel_rprobes_registered;
static bool binder_transaction_registered;
static bool selinux_groups_registered;

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
    if (binder_transaction_registered) {
        unregister_kprobe(&binder_transaction_kp);
        binder_transaction_registered = false;
    }
    while (seclabel_rprobes_registered > 0) {
        seclabel_rprobes_registered--;
        unregister_kretprobe(seclabel_rprobes[seclabel_rprobes_registered]);
    }
    if (xenoid_selinux_kobj) {
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

    for (i = 0; i < ARRAY_SIZE(rprobes); i++) {
        ret = register_kretprobe(rprobes[i]);
        if (ret) {
            pr_err("xenoid_kmod: required probe %s failed: %d\n",
                   rprobes[i]->kp.symbol_name, ret);
            goto fail;
        }
        rprobes_registered++;
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
            rprobes_registered + seclabel_rprobes_registered + 1);
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
