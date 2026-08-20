// Engine-host loader for the Xenoid shared eBPF protection unit.
// Commands: stage TX DIGEST | prove TX DIGEST | activate TX DIGEST |
//           discard TX | load DIGEST | status | unload
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xenoid_pathhide.skel.h"

#define PIN_BASE "/sys/fs/bpf/xenoid-shared"
#define PIN_CURRENT PIN_BASE "/current"
#define PIN_TRANSACTIONS PIN_BASE "/transactions"
#define LEGACY_PIN_DIR "/sys/fs/bpf/xenoid"
#define LOCK_PATH "/run/lock/xenoid-ebpf-loader.lock"
#define PATH_CAP 320

static const char *const pin_names[] = {
	"path_link", "selinux_permission_link", "uname_entry_link",
	"uname_return_link", "deny_count", "policy_identity",
};

struct policy_identity_value {
	uint8_t input_digest[32];
	uint8_t artifact_digest[32];
	uint32_t program_ids[4];
	uint8_t program_tags[4][8];
	uint32_t attach_mode;
};

static char observed_program_tags[65];

static void program_tags_hex(const uint8_t tags[4][8], char out[65])
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < 32; i++) {
		uint8_t value = tags[i / 8][i % 8];
		out[i * 2] = digits[value >> 4];
		out[i * 2 + 1] = digits[value & 15];
	}
	out[64] = '\0';
}

enum attach_mode {
	MODE_LSM = 0,
	MODE_FMOD = 1,
	MODE_KPROBE = 2,
};

static const char *attach_name(uint32_t mode)
{
	switch (mode) {
	case MODE_LSM: return "lsm";
	case MODE_FMOD: return "fmod_ret";
	case MODE_KPROBE: return "kprobe";
	default: return "invalid";
	}
}

static int valid_hex(const char *value, size_t length)
{
	size_t i;

	if (!value || strlen(value) != length)
		return 0;
	for (i = 0; i < length; i++)
		if (value[i] < '0' || value[i] > '9') {
			if (value[i] < 'a' || value[i] > 'f')
				return 0;
		}
	return 1;
}

static int digest_bytes(const char *hex, uint8_t out[32])
{
	size_t i;

	if (!valid_hex(hex, 64))
		return -EINVAL;
	for (i = 0; i < 32; i++) {
		unsigned int value;
		if (sscanf(hex + i * 2, "%2x", &value) != 1)
			return -EINVAL;
		out[i] = (uint8_t)value;
	}
	return 0;
}

static void digest_hex(const uint8_t value[32], char out[65])
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < 32; i++) {
		out[i * 2] = digits[value[i] >> 4];
		out[i * 2 + 1] = digits[value[i] & 15];
	}
	out[64] = '\0';
}

static int pin_path(char out[PATH_CAP], const char *dir, const char *name)
{
	int written = snprintf(out, PATH_CAP, "%s/%s", dir, name);
	return written > 0 && written < PATH_CAP ? 0 : -ENAMETOOLONG;
}

static void emit_status(int ok, int loaded, const char *digest,
			const char *artifact_digest, const char *attach,
			const char *error,
			int replacement_requires_maintenance)
{
	printf("{\"schema\":\"dev.xenoid.ebpf-deployment/v1\","
	       "\"ok\":%s,\"loaded\":%s,\"digest\":",
	       ok ? "true" : "false", loaded ? "true" : "false");
	if (digest)
		printf("\"%s\"", digest);
	else
		printf("null");
	printf(",\"artifactSha256\":");
	if (artifact_digest)
		printf("\"%s\"", artifact_digest);
	else
		printf("null");
	printf(",\"programTags\":");
	if (loaded && observed_program_tags[0])
		printf("\"%s\"", observed_program_tags);
	else
		printf("null");
	printf(",\"attach\":");
	if (attach)
		printf("\"%s\"", attach);
	else
		printf("null");
	printf(",\"links\":%s,\"maps\":%s,\"probes\":%s,"
	       "\"replacementRequiresMaintenance\":%s,\"error\":",
	       loaded ? "[\"path\",\"selinuxPermission\",\"unameEntry\",\"unameReturn\"]" : "[]",
	       loaded ? "[\"denyCount\",\"policyIdentity\"]" : "[]",
	       loaded ? "[\"linkInventory\",\"unprivilegedDeny\"]" : "[]",
	       replacement_requires_maintenance ? "true" : "false");
	if (error)
		printf("\"%s\"", error);
	else
		printf("null");
	printf("}\n");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int ensure_directory(const char *path, mode_t mode)
{
	struct stat st;

	if (mkdir(path, mode) < 0 && errno != EEXIST)
		return -errno;
	if (lstat(path, &st) < 0)
		return -errno;
	if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) || st.st_uid != 0)
		return -EPERM;
	if (chmod(path, mode) < 0)
		return -errno;
	return 0;
}

static int ensure_pin_roots(void)
{
	int err;

	if (access("/sys/fs/bpf", F_OK) != 0)
		return -ENOENT;
	err = ensure_directory(PIN_BASE, 0700);
	if (err)
		return err;
	return ensure_directory(PIN_TRANSACTIONS, 0700);
}

static int clear_pin_dir(const char *dir)
{
	char path[PATH_CAP];
	size_t i;
	int failed = 0;

	for (i = 0; i < sizeof(pin_names) / sizeof(pin_names[0]); i++) {
		if (pin_path(path, dir, pin_names[i])) {
			failed = 1;
			continue;
		}
		if (unlink(path) < 0 && errno != ENOENT)
			failed = 1;
		if (access(path, F_OK) == 0 || errno != ENOENT)
			failed = 1;
	}
	if (rmdir(dir) < 0 && errno != ENOENT)
		failed = 1;
	return failed ? -EIO : 0;
}

static int clear_legacy_pins(void)
{
	static const char *const names[] = {
		"pathhide_link", "selinux_permission_link", "deny_count",
		"uname_link", "uname_k_link",
	};
	char path[PATH_CAP];
	size_t i;
	int failed = 0;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (pin_path(path, LEGACY_PIN_DIR, names[i]) ||
		    (unlink(path) < 0 && errno != ENOENT))
			failed = 1;
	}
	if (unlink("/var/tmp/xenoid-ebpf-state.json") < 0 && errno != ENOENT)
		failed = 1;
	if (rmdir(LEGACY_PIN_DIR) < 0 && errno != ENOENT)
		failed = 1;
	return failed ? -EIO : 0;
}

static int bpf_lsm_active(void)
{
	FILE *file;
	char active[512] = {};
	char *entry;

	file = fopen("/sys/kernel/security/lsm", "r");
	if (!file)
		return 0;
	if (!fgets(active, sizeof(active), file)) {
		fclose(file);
		return 0;
	}
	fclose(file);
	for (entry = strtok(active, ",\n"); entry; entry = strtok(NULL, ",\n"))
		if (!strcmp(entry, "bpf"))
			return 1;
	return 0;
}

static int identity_for_dir(const char *dir, struct policy_identity_value *identity)
{
	struct bpf_map_info info = {};
	uint32_t length = sizeof(info);
	char path[PATH_CAP];
	uint32_t key = 0;
	int fd;
	int err = 0;

	if (pin_path(path, dir, "policy_identity"))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	if (bpf_obj_get_info_by_fd(fd, &info, &length) < 0 ||
	    info.type != BPF_MAP_TYPE_ARRAY ||
	    info.key_size != sizeof(key) ||
	    info.value_size != sizeof(*identity) ||
	    info.max_entries != 1)
		err = -EINVAL;
	else if (bpf_map_lookup_elem(fd, &key, identity) < 0)
		err = -errno;
	close(fd);
	return err;
}

static int validate_map(const char *dir, const char *name, uint32_t key_size,
			uint32_t value_size)
{
	struct bpf_map_info info = {};
	uint32_t length = sizeof(info);
	char path[PATH_CAP];
	int fd;

	if (pin_path(path, dir, name))
		return 0;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return 0;
	if (bpf_obj_get_info_by_fd(fd, &info, &length) < 0) {
		close(fd);
		return 0;
	}
	close(fd);
	return info.type == BPF_MAP_TYPE_ARRAY && info.key_size == key_size &&
	       info.value_size == value_size && info.max_entries == 1;
}

static int validate_link(const char *dir, const char *name,
			 uint32_t expected_id, const uint8_t expected_tag[8],
			 uint32_t expected_link_type, uint32_t expected_prog_type,
			 uint32_t expected_attach_type)
{
	struct bpf_link_info link_info = {};
	struct bpf_prog_info prog_info = {};
	uint32_t length = sizeof(link_info);
	char path[PATH_CAP];
	int link_fd;
	int prog_fd;
	int ok;

	if (pin_path(path, dir, name))
		return 0;
	link_fd = bpf_obj_get(path);
	if (link_fd < 0)
		return 0;
	if (bpf_obj_get_info_by_fd(link_fd, &link_info, &length) < 0 ||
	    !link_info.prog_id || link_info.prog_id != expected_id ||
	    link_info.type != expected_link_type) {
		close(link_fd);
		return 0;
	}
	close(link_fd);
	prog_fd = bpf_prog_get_fd_by_id(link_info.prog_id);
	if (prog_fd < 0)
		return 0;
	length = sizeof(prog_info);
	ok = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &length) == 0 &&
	     prog_info.type == expected_prog_type &&
	     (link_info.type != BPF_LINK_TYPE_TRACING ||
	      link_info.tracing.attach_type == expected_attach_type) &&
	     prog_info.id == expected_id &&
	     memcmp(prog_info.tag, expected_tag, sizeof(prog_info.tag)) == 0;
	close(prog_fd);
	return ok;
}

static int status_for_dir(const char *dir, char digest[65],
			  char artifact_digest[65], uint32_t *mode)
{
	static const char *const links[] = {
		"path_link", "selinux_permission_link", "uname_entry_link",
		"uname_return_link",
	};
	struct policy_identity_value identity = {};
	size_t i;
	int err;

	err = identity_for_dir(dir, &identity);
	if (err || identity.attach_mode > MODE_KPROBE)
		return 0;
	if (identity.attach_mode == MODE_LSM && !bpf_lsm_active())
		return 0;
	if (!validate_map(dir, "deny_count", sizeof(uint32_t), sizeof(uint64_t)) ||
	    !validate_map(dir, "policy_identity", sizeof(uint32_t),
			  sizeof(struct policy_identity_value)))
		return 0;
	for (i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
		uint32_t link_type;
		uint32_t prog_type;
		uint32_t attach_type;

		if (i >= 2 || identity.attach_mode == MODE_KPROBE) {
			link_type = BPF_LINK_TYPE_PERF_EVENT;
			prog_type = BPF_PROG_TYPE_KPROBE;
			attach_type = 0;
		} else if (identity.attach_mode == MODE_LSM) {
			link_type = BPF_LINK_TYPE_TRACING;
			prog_type = BPF_PROG_TYPE_LSM;
			attach_type = BPF_LSM_MAC;
		} else {
			link_type = BPF_LINK_TYPE_TRACING;
			prog_type = BPF_PROG_TYPE_TRACING;
			attach_type = BPF_MODIFY_RETURN;
		}
		if (!validate_link(dir, links[i], identity.program_ids[i],
				   identity.program_tags[i], link_type, prog_type,
				   attach_type))
			return 0;
	}
	program_tags_hex(identity.program_tags, observed_program_tags);
	digest_hex(identity.input_digest, digest);
	digest_hex(identity.artifact_digest, artifact_digest);
	*mode = identity.attach_mode;
	return 1;
}

static int pin_link(struct bpf_link *link, const char *dir, const char *name)
{
	char path[PATH_CAP];
	int err = pin_path(path, dir, name);
	return err ? err : bpf_link__pin(link, path);
}

static int pin_map(struct bpf_map *map, const char *dir, const char *name)
{
	char path[PATH_CAP];
	int err = pin_path(path, dir, name);
	return err ? err : bpf_map__pin(map, path);
}

static int try_one_mode(enum attach_mode mode, const char *dir,
			const char *digest, const char *artifact_digest)
{
	struct xenoid_pathhide_bpf *skel;
	struct bpf_link *path_link = NULL;
	struct bpf_link *permission_link = NULL;
	struct bpf_link *uname_entry = NULL;
	struct bpf_link *uname_return = NULL;
	struct bpf_program *path_program;
	struct bpf_program *permission_program;
	struct policy_identity_value identity = { .attach_mode = mode };
	uint32_t key = 0;
	int err;

	err = digest_bytes(digest, identity.input_digest);
	if (!err)
		err = digest_bytes(artifact_digest, identity.artifact_digest);
	if (err)
		return err;
	skel = xenoid_pathhide_bpf__open();
	if (!skel)
		return errno ? -errno : -ENOMEM;
	bpf_program__set_autoload(skel->progs.xenoid_lsm_file_open, mode == MODE_LSM);
	bpf_program__set_autoload(skel->progs.xenoid_fmod_security_file_open, mode == MODE_FMOD);
	bpf_program__set_autoload(skel->progs.xenoid_kprobe_security_file_open, mode == MODE_KPROBE);
	bpf_program__set_autoload(skel->progs.xenoid_lsm_inode_permission, mode == MODE_LSM);
	bpf_program__set_autoload(skel->progs.xenoid_fmod_security_inode_permission, mode == MODE_FMOD);
	bpf_program__set_autoload(skel->progs.xenoid_kprobe_security_inode_permission, mode == MODE_KPROBE);
	err = xenoid_pathhide_bpf__load(skel);
	if (err)
		goto out;
	switch (mode) {
	case MODE_LSM:
		path_program = skel->progs.xenoid_lsm_file_open;
		permission_program = skel->progs.xenoid_lsm_inode_permission;
		break;
	case MODE_FMOD:
		path_program = skel->progs.xenoid_fmod_security_file_open;
		permission_program = skel->progs.xenoid_fmod_security_inode_permission;
		break;
	default:
		path_program = skel->progs.xenoid_kprobe_security_file_open;
		permission_program = skel->progs.xenoid_kprobe_security_inode_permission;
		break;
	}
	path_link = bpf_program__attach(path_program);
	err = libbpf_get_error(path_link);
	if (err) {
		path_link = NULL;
		goto out;
	}
	permission_link = bpf_program__attach(permission_program);
	err = libbpf_get_error(permission_link);
	if (err) {
		permission_link = NULL;
		goto out;
	}
	uname_entry = bpf_program__attach(skel->progs.xenoid_k_newuname);
	err = libbpf_get_error(uname_entry);
	if (err) {
		uname_entry = NULL;
		goto out;
	}
	uname_return = bpf_program__attach(skel->progs.xenoid_kret_newuname);
	err = libbpf_get_error(uname_return);
	if (err) {
		uname_return = NULL;
		goto out;
	}
	{
		struct bpf_program *programs[] = {
			path_program,
			permission_program,
			skel->progs.xenoid_k_newuname,
			skel->progs.xenoid_kret_newuname,
		};
		size_t i;

		for (i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
			struct bpf_prog_info info = {};
			uint32_t length = sizeof(info);

			if (bpf_obj_get_info_by_fd(bpf_program__fd(programs[i]), &info,
						   &length) < 0) {
				err = -errno;
				goto out;
			}
			identity.program_ids[i] = info.id;
			memcpy(identity.program_tags[i], info.tag, sizeof(info.tag));
		}
	}
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.policy_identity), &key,
				&identity, BPF_ANY) < 0) {
		err = -errno;
		goto out;
	}
	err = pin_link(path_link, dir, "path_link");
	if (!err) err = pin_link(permission_link, dir, "selinux_permission_link");
	if (!err) err = pin_link(uname_entry, dir, "uname_entry_link");
	if (!err) err = pin_link(uname_return, dir, "uname_return_link");
	if (!err) err = pin_map(skel->maps.deny_count, dir, "deny_count");
	if (!err) err = pin_map(skel->maps.policy_identity, dir, "policy_identity");
out:
	if (err)
		clear_pin_dir(dir);
	bpf_link__destroy(path_link);
	bpf_link__destroy(permission_link);
	bpf_link__destroy(uname_entry);
	bpf_link__destroy(uname_return);
	xenoid_pathhide_bpf__destroy(skel);
	return err;
}

static int transaction_dir(char out[PATH_CAP], const char *transaction)
{
	if (!valid_hex(transaction, 32))
		return -EINVAL;
	return pin_path(out, PIN_TRANSACTIONS, transaction);
}

static int reconcile_transactions(void)
{
	DIR *directory;
	struct dirent *entry;
	int err = 0;

	directory = opendir(PIN_TRANSACTIONS);
	if (!directory)
		return errno == ENOENT ? 0 : -errno;
	while ((entry = readdir(directory)) != NULL) {
		char path[PATH_CAP];
		const char *transaction = entry->d_name;

		if (!strcmp(transaction, ".") || !strcmp(transaction, ".."))
			continue;
		if (!strncmp(transaction, "rollback-", 9)) {
			transaction += 9;
			if (!valid_hex(transaction, 32) ||
			    snprintf(path, sizeof(path), "%s/%s", PIN_TRANSACTIONS,
				     entry->d_name) >= (int)sizeof(path)) {
				err = -EINVAL;
				break;
			}
			if (access(PIN_CURRENT, F_OK) == 0) {
				if (clear_pin_dir(path)) {
					err = -EIO;
					break;
				}
			}
			else if (rename(path, PIN_CURRENT) < 0) {
				err = -errno;
				break;
			}
			continue;
		}
		if (!valid_hex(transaction, 32) ||
		    transaction_dir(path, transaction)) {
			err = -EINVAL;
			break;
		}
		/* A stage is never authoritative until activation. Its complete pin
		 * inventory can therefore be detached and rebuilt deterministically. */
		if (clear_pin_dir(path)) {
			err = -EIO;
			break;
		}
	}
	closedir(directory);
	return err;
}

static int transactions_empty(void)
{
	DIR *directory;
	struct dirent *entry;
	int empty = 1;

	directory = opendir(PIN_TRANSACTIONS);
	if (!directory)
		return errno == ENOENT;
	while ((entry = readdir(directory)) != NULL)
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
			empty = 0;
			break;
		}
	closedir(directory);
	return empty;
}

static int discard_all_transactions(void)
{
	DIR *directory;
	struct dirent *entry;
	int err = 0;

	directory = opendir(PIN_TRANSACTIONS);
	if (!directory)
		return errno == ENOENT ? 0 : -errno;
	while ((entry = readdir(directory)) != NULL) {
		char path[PATH_CAP];
		const char *transaction = entry->d_name;

		if (!strcmp(transaction, ".") || !strcmp(transaction, ".."))
			continue;
		if (!strncmp(transaction, "rollback-", 9))
			transaction += 9;
		if (!valid_hex(transaction, 32) ||
		    snprintf(path, sizeof(path), "%s/%s", PIN_TRANSACTIONS,
			     entry->d_name) >= (int)sizeof(path)) {
			err = -EINVAL;
			break;
		}
		if (clear_pin_dir(path)) {
			err = -EIO;
			break;
		}
	}
	closedir(directory);
	return err;
}
static int cmd_stage(const char *transaction, const char *digest,
		     const char *artifact_digest)
{
	char dir[PATH_CAP];
	char current_digest[65] = {};
	char current_artifact[65] = {};
	uint32_t current_mode = 0;
	enum attach_mode mode;
	int err;
	int current_loaded;

	if (!valid_hex(digest, 64) || !valid_hex(artifact_digest, 64) ||
	    transaction_dir(dir, transaction)) {
		emit_status(0, 0, NULL, NULL, NULL, "ebpf_request_invalid", 0);
		return 2;
	}
	err = ensure_pin_roots();
	if (err || reconcile_transactions()) {
		emit_status(0, 0, NULL, NULL, NULL,
			    err ? "ebpf_pin_root_invalid" : "ebpf_transaction_conflict",
			    0);
		return 1;
	}
	if (clear_pin_dir(dir)) {
		emit_status(0, 0, NULL, NULL, NULL,
			    "ebpf_transaction_discard_unverified", 0);
		return 1;
	}
	current_loaded = status_for_dir(PIN_CURRENT, current_digest,
					current_artifact, &current_mode);
	for (mode = MODE_LSM; mode <= MODE_KPROBE; mode++) {
		if (mode == MODE_LSM && !bpf_lsm_active())
			continue;
		if (ensure_directory(dir, 0700))
			continue;
		err = try_one_mode(mode, dir, digest, artifact_digest);
		if (!err) {
			if (!status_for_dir(
				    dir,
				    current_digest,
				    current_artifact,
				    &current_mode)) {
				clear_pin_dir(dir);
				continue;
			}
			emit_status(1, 1, digest, artifact_digest,
				    attach_name(mode), NULL, 0);
			return 0;
		}
	}
	emit_status(0, current_loaded,
		    current_loaded ? current_digest : NULL,
		    current_loaded ? current_artifact : NULL,
		    current_loaded ? attach_name(current_mode) : NULL,
		    current_loaded ? "ebpf_attach_not_coexistent" :
		    "ebpf_attach_failed", current_loaded);
	return 1;
}

static unsigned long long deny_count_for_dir(const char *dir)
{
	char path[PATH_CAP];
	uint32_t key = 0;
	uint64_t value = 0;
	int fd;

	if (pin_path(path, dir, "deny_count"))
		return 0;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return 0;
	bpf_map_lookup_elem(fd, &key, &value);
	close(fd);
	return (unsigned long long)value;
}

static int run_unprivileged_deny_proof(void)
{
	char name[96];
	unsigned char random[16];
	struct stat info;
	pid_t child;
	int directory_fd;
	int status;
	int fd;
	size_t prefix_length;
	size_t i;

	if (getrandom(random, sizeof(random), 0) != sizeof(random))
		return -EIO;
	strcpy(name, ".xenoid-ebpf-deny-proof-");
	prefix_length = strlen(name);
	for (i = 0; i < sizeof(random); i++)
		snprintf(name + prefix_length + i * 2,
			 sizeof(name) - prefix_length - i * 2,
			 "%02x", random[i]);
	directory_fd = open("/var/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
			    O_NOFOLLOW);
	if (directory_fd < 0)
		return -errno;
	fd = openat(directory_fd, name, O_CREAT | O_EXCL | O_NOFOLLOW |
		    O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		close(directory_fd);
		return -errno;
	}
	if (fchmod(fd, 0644) < 0) {
		close(fd);
		unlinkat(directory_fd, name, 0);
		close(directory_fd);
		return -errno;
	}
	if (fstat(fd, &info) < 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
	    info.st_nlink != 1 || (info.st_mode & 0777) != 0644 ||
	    write(fd, "x", 1) != 1) {
		close(fd);
		unlinkat(directory_fd, name, 0);
		close(directory_fd);
		return -EIO;
	}
	close(fd);
	child = fork();
	if (child < 0) {
		unlinkat(directory_fd, name, 0);
		close(directory_fd);
		return -errno;
	}
	if (child == 0) {
		int proof_fd;
		if (setresgid(10000, 10000, 10000) ||
		    setresuid(10000, 10000, 10000))
			_exit(3);
		errno = 0;
		proof_fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC |
				  O_NOFOLLOW);
		if (proof_fd >= 0) {
			close(proof_fd);
			_exit(2);
		}
		_exit(errno == ENOENT || errno == EACCES ? 0 : 4);
	}
	if (waitpid(child, &status, 0) < 0) {
		unlinkat(directory_fd, name, 0);
		close(directory_fd);
		return -errno;
	}
	if (unlinkat(directory_fd, name, 0) < 0 ||
	    fstatat(directory_fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 ||
	    errno != ENOENT) {
		close(directory_fd);
		return -EIO;
	}
	close(directory_fd);
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EPERM;
}

static int cmd_prove(const char *transaction, const char *expected_digest,
		     const char *expected_artifact)
{
	char dir[PATH_CAP];
	char digest[65] = {};
	char artifact[65] = {};
	uint32_t mode = 0;
	unsigned long long before;
	unsigned long long after;

	if (!valid_hex(expected_digest, 64) ||
	    !valid_hex(expected_artifact, 64) ||
	    transaction_dir(dir, transaction) ||
	    !status_for_dir(dir, digest, artifact, &mode) ||
	    strcmp(digest, expected_digest) ||
	    strcmp(artifact, expected_artifact)) {
		emit_status(0, 0, NULL, NULL, NULL, "ebpf_stage_invalid", 0);
		return 1;
	}
	before = deny_count_for_dir(dir);
	if (run_unprivileged_deny_proof()) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_deny_proof_failed", 0);
		return 1;
	}
	after = deny_count_for_dir(dir);
	if (after <= before) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_deny_proof_failed", 0);
		return 1;
	}
	emit_status(1, 1, digest, artifact, attach_name(mode), NULL, 0);
	return 0;
}

static int cmd_activate(const char *transaction, const char *expected_digest,
			const char *expected_artifact)
{
	char stage[PATH_CAP];
	char rollback[PATH_CAP];
	char digest[65] = {};
	char artifact[65] = {};
	uint32_t mode = 0;
	int had_current;

	if (!valid_hex(expected_digest, 64) ||
	    !valid_hex(expected_artifact, 64) ||
	    transaction_dir(stage, transaction) ||
	    snprintf(rollback, sizeof(rollback), "%s/rollback-%s",
		     PIN_TRANSACTIONS, transaction) >= (int)sizeof(rollback) ||
	    !status_for_dir(stage, digest, artifact, &mode) ||
	    strcmp(digest, expected_digest) ||
	    strcmp(artifact, expected_artifact)) {
		emit_status(0, 0, NULL, NULL, NULL, "ebpf_stage_invalid", 0);
		return 1;
	}
	if (clear_pin_dir(rollback)) {
		emit_status(0, 0, NULL, NULL, NULL,
			    "ebpf_rollback_unverified", 0);
		return 1;
	}
	had_current = access(PIN_CURRENT, F_OK) == 0;
	if (had_current && rename(PIN_CURRENT, rollback) < 0) {
		emit_status(0, 1, NULL, NULL, NULL,
			    "ebpf_atomic_swap_unavailable", 1);
		return 1;
	}
	if (rename(stage, PIN_CURRENT) < 0) {
		if (had_current && rename(rollback, PIN_CURRENT) < 0)
			emit_status(0, 0, NULL, NULL, NULL,
				    "ebpf_rollback_unverified", 0);
		else
			emit_status(0, had_current, NULL, NULL, NULL,
				    "ebpf_atomic_swap_unavailable", 1);
		return 1;
	}
	memset(digest, 0, sizeof(digest));
	memset(artifact, 0, sizeof(artifact));
	if (!status_for_dir(PIN_CURRENT, digest, artifact, &mode) ||
	    strcmp(digest, expected_digest) ||
	    strcmp(artifact, expected_artifact)) {
		clear_pin_dir(PIN_CURRENT);
		if (had_current && rename(rollback, PIN_CURRENT) < 0)
			emit_status(0, 0, NULL, NULL, NULL,
				    "ebpf_rollback_unverified", 0);
		else
			emit_status(0, had_current, NULL, NULL, NULL,
				    "ebpf_activation_unverified", 0);
		return 1;
	}
	if (had_current && clear_pin_dir(rollback)) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_rollback_unverified", 0);
		return 1;
	}
	if (clear_legacy_pins()) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_legacy_detach_unverified", 0);
		return 1;
	}
	emit_status(1, 1, digest, artifact, attach_name(mode), NULL, 0);
	return 0;
}

static int cmd_discard(const char *transaction)
{
	char dir[PATH_CAP];

	if (transaction_dir(dir, transaction)) {
		emit_status(0, 0, NULL, NULL, NULL, "ebpf_request_invalid", 0);
		return 2;
	}
	if (clear_pin_dir(dir) || access(dir, F_OK) == 0 || errno != ENOENT) {
		emit_status(0, 0, NULL, NULL, NULL,
			    "ebpf_transaction_discard_unverified", 0);
		return 1;
	}
	emit_status(1, 0, NULL, NULL, NULL, NULL, 0);
	return 0;
}

static int cmd_status(void)
{
	char digest[65] = {};
	char artifact[65] = {};
	uint32_t mode = 0;
	unsigned long long before;

	if (!status_for_dir(PIN_CURRENT, digest, artifact, &mode)) {
		emit_status(0, 0, NULL, NULL, NULL, "ebpf_not_loaded", 0);
		return 1;
	}
	if (!transactions_empty()) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_transaction_pending", 0);
		return 1;
	}
	before = deny_count_for_dir(PIN_CURRENT);
	if (run_unprivileged_deny_proof() ||
	    deny_count_for_dir(PIN_CURRENT) <= before) {
		emit_status(0, 1, digest, artifact, attach_name(mode),
			    "ebpf_deny_proof_failed", 0);
		return 1;
	}
	emit_status(1, 1, digest, artifact, attach_name(mode), NULL, 0);
	return 0;
}

static void clear_transactions(void)
{
	rmdir(PIN_TRANSACTIONS);
}

static int cmd_unload(void)
{
	if (discard_all_transactions()) {
		emit_status(0, 1, NULL, NULL, NULL,
			    "ebpf_transaction_conflict", 0);
		return 1;
	}
	if (clear_pin_dir(PIN_CURRENT)) {
		emit_status(0, 1, NULL, NULL, NULL,
			    "ebpf_unload_unverified", 0);
		return 1;
	}
	clear_transactions();
	if (clear_legacy_pins()) {
		emit_status(0, 1, NULL, NULL, NULL,
			    "ebpf_unload_unverified", 0);
		return 1;
	}
	rmdir(PIN_BASE);
	if (access(PIN_BASE, F_OK) == 0 ||
	    access(PIN_CURRENT, F_OK) == 0 ||
	    access(LEGACY_PIN_DIR, F_OK) == 0) {
		emit_status(0, 1, NULL, NULL, NULL,
			    "ebpf_unload_unverified", 0);
		return 1;
	}
	emit_status(1, 0, NULL, NULL, NULL, NULL, 0);
	return 0;
}

static int cmd_load(const char *digest, const char *artifact_digest)
{
	char transaction[33];
	unsigned long long value =
		((unsigned long long)time(NULL) << 32) ^
		(unsigned long long)getpid();

	snprintf(transaction, sizeof(transaction), "%032llx", value);
	if (cmd_stage(transaction, digest, artifact_digest))
		return 1;
	if (cmd_prove(transaction, digest, artifact_digest)) {
		cmd_discard(transaction);
		return 1;
	}
	if (cmd_activate(transaction, digest, artifact_digest)) {
		cmd_discard(transaction);
		return 1;
	}
	return 0;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s stage TX INPUT ARTIFACT|prove TX INPUT ARTIFACT|"
		"activate TX INPUT ARTIFACT|discard TX|load INPUT ARTIFACT|"
		"status|unload\n", program);
}

int main(int argc, char **argv)
{
	int lock_fd;
	struct stat lock_stat;
	int result = 2;

	lock_fd = open(LOCK_PATH, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0 || fstat(lock_fd, &lock_stat) < 0 ||
	    !S_ISREG(lock_stat.st_mode) || lock_stat.st_uid != 0 ||
	    (lock_stat.st_mode & 0777) != 0600 || lock_stat.st_nlink != 1 ||
	    flock(lock_fd, LOCK_EX) < 0) {
		if (lock_fd >= 0)
			close(lock_fd);
		emit_status(0, 0, NULL, NULL, NULL,
			    "ebpf_loader_lock_failed", 0);
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);
	if (argc == 2 && !strcmp(argv[1], "status"))
		result = cmd_status();
	else if (argc == 2 && !strcmp(argv[1], "unload"))
		result = cmd_unload();
	else if (argc == 3 && !strcmp(argv[1], "discard"))
		result = cmd_discard(argv[2]);
	else if (argc == 4 && !strcmp(argv[1], "load"))
		result = cmd_load(argv[2], argv[3]);
	else if (argc == 5 && !strcmp(argv[1], "stage"))
		result = cmd_stage(argv[2], argv[3], argv[4]);
	else if (argc == 5 && !strcmp(argv[1], "prove"))
		result = cmd_prove(argv[2], argv[3], argv[4]);
	else if (argc == 5 && !strcmp(argv[1], "activate"))
		result = cmd_activate(argv[2], argv[3], argv[4]);
	else
		usage(argv[0]);
	flock(lock_fd, LOCK_UN);
	close(lock_fd);
	return result;
}
