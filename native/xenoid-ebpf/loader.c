// Minimal libbpf loader for xenoid_pathhide.
// Commands: load | status | unload
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xenoid_pathhide.skel.h"

#define PIN_DIR "/sys/fs/bpf/xenoid"
#define PIN_LINK PIN_DIR "/pathhide_link"
#define PIN_MAP PIN_DIR "/deny_count"
#define PIN_UNAME_LINK PIN_DIR "/uname_link"
#define PIN_UNAME_K_LINK PIN_DIR "/uname_k_link"
#define STATE_PATH "/var/tmp/xenoid-ebpf-state.json"

static void json_escape(char *dst, size_t n, const char *s)
{
	size_t j = 0;
	if (!s) { snprintf(dst, n, "null"); return; }
	if (n < 3) { dst[0] = 0; return; }
	dst[j++] = '"';
	for (; *s && j + 2 < n; s++) {
		if (*s == '"' || *s == '\\') {
			if (j + 3 >= n) break;
			dst[j++] = '\\';
		}
		dst[j++] = *s;
	}
	dst[j++] = '"';
	dst[j] = 0;
}

static void emit_json(int ok, int loaded, const char *attach, const char *note,
		      const char *error, unsigned long long denies)
{
	char ebuf[320];
	json_escape(ebuf, sizeof(ebuf), error);
	printf("{\"ok\":%s,\"loaded\":%s,\"attach\":\"%s\",\"pinDir\":\"%s\","
	       "\"links\":{\"path\":%s,\"unameEntry\":%s,\"unameReturn\":%s},"
	       "\"denyCount\":%llu,\"note\":\"%s\",\"error\":%s}\n",
	       ok ? "true" : "false",
	       loaded ? "true" : "false",
	       attach ? attach : "",
	       PIN_DIR,
	       access(PIN_LINK, F_OK) == 0 ? "true" : "false",
	       access(PIN_UNAME_K_LINK, F_OK) == 0 ? "true" : "false",
	       access(PIN_UNAME_LINK, F_OK) == 0 ? "true" : "false",
	       denies,
	       note ? note : "",
	       error ? ebuf : "null");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int ensure_bpffs_pin_dir(void)
{
	if (access("/sys/fs/bpf", F_OK) != 0)
		return -ENOENT;
	if (mkdir(PIN_DIR, 0755) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static void write_state(const char *attach, const char *note)
{
	FILE *f = fopen(STATE_PATH, "w");
	if (!f)
		return;
	fprintf(f, "{\"attach\":\"%s\",\"note\":\"%s\",\"pinLink\":\"%s\"}\n",
		attach ? attach : "", note ? note : "", PIN_LINK);
	fclose(f);
}

static unsigned long long read_deny_count(void)
{
	int fd = bpf_obj_get(PIN_MAP);
	__u32 key = 0;
	__u64 val = 0;
	if (fd < 0)
		return 0;
	bpf_map_lookup_elem(fd, &key, &val);
	close(fd);
	return (unsigned long long)val;
}

static int already_loaded(char *attach_out, size_t n)
{
	if (access(PIN_LINK, F_OK) != 0 ||
	    access(PIN_UNAME_K_LINK, F_OK) != 0 ||
	    access(PIN_UNAME_LINK, F_OK) != 0 ||
	    access(PIN_MAP, F_OK) != 0)
		return 0;
	FILE *f = fopen(STATE_PATH, "r");
	if (f) {
		char buf[256] = {};
		if (fgets(buf, sizeof(buf), f)) {
			const char *p = strstr(buf, "\"attach\":\"");
			if (p) {
				p += 10;
				size_t i = 0;
				while (*p && *p != '"' && i + 1 < n)
					attach_out[i++] = *p++;
				attach_out[i] = 0;
			}
		}
		fclose(f);
	}
	if (!attach_out[0])
		snprintf(attach_out, n, "pinned");
	return 1;
}

static void clear_pins(void)
{
	unlink(PIN_LINK);
	unlink(PIN_MAP);
	unlink(PIN_UNAME_LINK);
	unlink(PIN_UNAME_K_LINK);
	unlink(STATE_PATH);
}

enum attach_mode {
	MODE_LSM = 0,
	MODE_FMOD = 1,
	MODE_KPROBE = 2,
};

static int try_one_mode(enum attach_mode mode, const char **attach_name, const char **note)
{
	struct xenoid_pathhide_bpf *skel;
	struct bpf_link *link = NULL;
	struct bpf_program *prog = NULL;
	int err;

	skel = xenoid_pathhide_bpf__open();
	if (!skel)
		return -errno;

	bpf_program__set_autoload(skel->progs.xenoid_lsm_file_open, mode == MODE_LSM);
	bpf_program__set_autoload(skel->progs.xenoid_fmod_security_file_open, mode == MODE_FMOD);
	bpf_program__set_autoload(skel->progs.xenoid_kprobe_security_file_open, mode == MODE_KPROBE);

	err = xenoid_pathhide_bpf__load(skel);
	if (err) {
		xenoid_pathhide_bpf__destroy(skel);
		return err;
	}

	switch (mode) {
	case MODE_LSM:
		prog = skel->progs.xenoid_lsm_file_open;
		*attach_name = "lsm/file_open";
		*note = "LSM BPF attach ok";
		break;
	case MODE_FMOD:
		prog = skel->progs.xenoid_fmod_security_file_open;
		*attach_name = "fmod_ret/security_file_open";
		*note = "LSM BPF inactive or unavailable; attached via fmod_ret";
		break;
	case MODE_KPROBE:
		prog = skel->progs.xenoid_kprobe_security_file_open;
		*attach_name = "kprobe/security_file_open";
		*note = "Attached via kprobe override (CONFIG_BPF_KPROBE_OVERRIDE)";
		break;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		xenoid_pathhide_bpf__destroy(skel);
		return err;
	}

	switch (mode) {
	case MODE_LSM:
		skel->links.xenoid_lsm_file_open = link;
		break;
	case MODE_FMOD:
		skel->links.xenoid_fmod_security_file_open = link;
		break;
	case MODE_KPROBE:
		skel->links.xenoid_kprobe_security_file_open = link;
		break;
	}

	/* Path blocking and uname shaping are one protection unit. */
	{
		struct bpf_link *ul1 = bpf_program__attach(skel->progs.xenoid_k_newuname);
		struct bpf_link *ul2;

		err = libbpf_get_error(ul1);
		if (err) {
			xenoid_pathhide_bpf__destroy(skel);
			return err;
		}
		skel->links.xenoid_k_newuname = ul1;
		ul2 = bpf_program__attach(skel->progs.xenoid_kret_newuname);
		err = libbpf_get_error(ul2);
		if (err) {
			xenoid_pathhide_bpf__destroy(skel);
			return err;
		}
		skel->links.xenoid_kret_newuname = ul2;
	}

	clear_pins();
	err = bpf_link__pin(skel->links.xenoid_k_newuname, PIN_UNAME_K_LINK);
	if (!err)
		err = bpf_link__pin(skel->links.xenoid_kret_newuname, PIN_UNAME_LINK);
	if (!err)
		err = bpf_link__pin(link, PIN_LINK);
	if (!err)
		err = bpf_map__pin(skel->maps.deny_count, PIN_MAP);
	if (err) {
		clear_pins();
		xenoid_pathhide_bpf__destroy(skel);
		return err;
	}

	/* Destroying the skeleton drops local references; pins retain all links. */
	xenoid_pathhide_bpf__destroy(skel);
	return 0;
}

static int cmd_unload(void)
{
	clear_pins();
	rmdir(PIN_DIR);
	emit_json(1, 0, "none", "unpinned", NULL, 0);
	return 0;
}

static int cmd_status(void)
{
	char attach[64] = {};
	int loaded = already_loaded(attach, sizeof(attach));
	unsigned long long denies = read_deny_count();
	emit_json(loaded, loaded, loaded ? attach : "none",
		  loaded ? "all mandatory links present" : "one or more mandatory links are absent",
		  loaded ? NULL : "protection is not fully loaded", denies);
	return loaded ? 0 : 1;
}

static int cmd_load(void)
{
	const char *attach = "none";
	const char *note = "";
	int err;
	enum attach_mode mode;

	libbpf_set_print(libbpf_print_fn);


	err = ensure_bpffs_pin_dir();
	if (err) {
		emit_json(0, 0, "none", "", "bpffs /sys/fs/bpf unavailable", 0);
		return 1;
	}
	clear_pins();

	for (mode = MODE_LSM; mode <= MODE_KPROBE; mode++) {
		const char *a = "none";
		const char *n = "";
		err = try_one_mode(mode, &a, &n);
		if (err == 0) {
			attach = a;
			note = n;
			write_state(attach, note);
			emit_json(1, 1, attach, note, NULL, 0);
			return 0;
		}
	}

	emit_json(0, 0, "none",
		  "all attach modes failed; boot with lsm=...,bpf for LSM or check fmod_ret/kprobe support",
		  "attach failed", 0);
	return 1;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s load|status|unload\n", argv0);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "load") == 0)
		return cmd_load();
	if (strcmp(argv[1], "status") == 0)
		return cmd_status();
	if (strcmp(argv[1], "unload") == 0)
		return cmd_unload();
	usage(argv[0]);
	return 2;
}
