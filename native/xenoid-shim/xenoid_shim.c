#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#if __has_include(<link.h>)
#include <link.h>
#define XENOID_HAS_LINK_H 1
#else
#define XENOID_HAS_LINK_H 0
#endif
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if __has_include(<sys/prctl.h>)
#include <sys/prctl.h>
#define XENOID_HAS_PRCTL 1
#else
#define XENOID_HAS_PRCTL 0
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#endif
#include <sys/utsname.h>
#if __has_include(<sys/auxv.h>)
#include <sys/auxv.h>
#endif
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#if defined(__linux__)
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <sched.h>
#endif
#ifdef XENOID_ENABLE_IOCTL
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#define XENOID_DEFAULT_PROFILE_DIR "/data/local/tmp/xenoid-profile"
#define XENOID_DEFAULT_BOOT_ID "b9b36666-6eb6-4613-9ad6-edc7bb5630f9\n"
#define XENOID_DEFAULT_MAC "02:33:44:55:66:77\n"
static char *cached_boot_id;
static char *cached_mac_text;
static int zygote_identity_scope;
#ifndef AT_PLATFORM
#define AT_PLATFORM 15
#endif
#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif

typedef int (*openat_t)(int,const char*,int,...);
typedef int (*open_t)(const char*,int,...);
typedef int (*access_t)(const char*,int);
typedef int (*faccessat_t)(int,const char*,int,int);
typedef int (*fstatat_t)(int,const char*,struct stat*,int);
typedef int (*stat_t)(const char*,struct stat*);
typedef int (*lstat_t)(const char*,struct stat*);
typedef ssize_t (*readlink_t)(const char*,char*,size_t);
typedef ssize_t (*readlinkat_t)(int,const char*,char*,size_t);
typedef ssize_t (*read_t)(int,void*,size_t);
typedef struct dirent *(*readdir_t)(DIR*);
typedef int (*getdents64_t)(unsigned int, void*, unsigned int);
typedef int (*uname_t)(struct utsname*);
typedef void *(*dlopen_t)(const char*, int);
typedef void *(*android_dlopen_ext_t)(const char*, int, const void*);
typedef long (*sysconf_t)(int);
typedef unsigned long (*getauxval_t)(unsigned long);
#if XENOID_HAS_LINK_H
typedef int (*dl_iterate_phdr_t)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
#endif

#ifdef XENOID_ENABLE_PROPERTY_GET
typedef int (*prop_get_t)(const char*, char*);
#endif

static int str_contains_any(const char *s, const char **needles) {
  if (!s) return 0;
  for (int i = 0; needles[i]; i++) if (strstr(s, needles[i])) return 1;
  return 0;
}

static int hidden_path(const char *p){
  const char *test_marker = getenv("XENOID_TEST_HIDE_PATH");
  if (test_marker && test_marker[0] && p && strcmp(p, test_marker)==0) return 1;
  /* The system-wide zygote shim also maps into dev.xenoid.daemon. Do not hide
     the daemon's own installed APK root from its class loader; this is a narrow
     package-root exemption, not a /data/app or /data/data prefix exemption. */
  if (p && strstr(p, "/data/app/") && strstr(p, "/dev.xenoid.daemon-")) return 0;
  if (p && (strstr(p, "/data/data/dev.xenoid.daemon/") ||
            strstr(p, "/data/user/0/dev.xenoid.daemon/") ||
            strstr(p, "/data/user_de/0/dev.xenoid.daemon/"))) return 0;
  static const char *n[]={
    "/system/xbin/su","/system/bin/su","/system/bin/.ext/.su","/sbin/su","/su/bin/su","/vendor/bin/su",
    "xenoid","libxenoid","shim",".fs64",".netd-helper","magisk","zygisk","frida","gum-js-loop","gmain","gdbus","xposed","lsposed","substrate","riru",
    "/sys/module/vboxsf","/sys/module/vboxguest","/sys/module/vmw_pvscsi","/system/lib/vboxguest.ko","/system/lib64/vboxguest.ko",
    "/data/system/.core/",
    "/init.android_x86.rc","/ueventd.android_x86.rc","/fstab.android_x86","/dev/qemu_pipe","/dev/qemu_trace","/sys/qemu_trace","/sys/hypervisor","/sys/class/dmi","/sys/devices/virtual/dmi","/sys/firmware/dmi","/sys/module/virtio","/sys/module/xen","/sys/module/vbox","/sys/module/vmw",
    "/dev/socket/adbd",
    NULL};
  return str_contains_any(p,n);
}

static int hidden_dirent(const char *name) {
  const char *test_marker = getenv("XENOID_TEST_HIDE_DIRENT");
  if (test_marker && test_marker[0] && name && strcmp(name, test_marker)==0) return 1;
  static const char *n[]={"su","magisk","zygisk","frida","xposed","lsposed","riru","gum-js-loop","gmain","gdbus","vda","vdb","virtio","virtio_blk","virtio_pci","virtio_net","virtio_scsi","virtio_mmio","xen","xen_blkfront","xen_netfront","vbox","vmw","dmi",NULL};
  return str_contains_any(name,n);
}

static char *read_file_real(const char *p){
  open_t ro=(open_t)dlsym(RTLD_NEXT,"open"); read_t rr=(read_t)dlsym(RTLD_NEXT,"read");
  if(!ro||!rr)return strdup("");
  int fd=ro(p,O_RDONLY|O_CLOEXEC); if(fd<0)return strdup("");
  size_t cap=65536,n=0; char*b=calloc(1,cap+1); if(!b){close(fd); return strdup("");}
  for(;;){ if(n+4096>=cap){cap*=2; char*nb=realloc(b,cap+1); if(!nb)break; b=nb;} ssize_t r=rr(fd,b+n,4096); if(r<=0)break; n+=r;}
  close(fd); b[n]=0; return b;
}

static char *read_first_or_default(const char *path, const char *fallback) {
  char *s = read_file_real(path);
  if (!s || !s[0]) { free(s); return strdup(fallback); }
  size_t n = strcspn(s, "\r\n");
  char *out = calloc(1, n + 2);
  if (!out) { free(s); return strdup(fallback); }
  memcpy(out, s, n); out[n] = '\n'; out[n+1] = 0;
  free(s); return out;
}

static const char *profile_dir(void) {
  const char *d = getenv("XENOID_PROFILE_DIR");
  return (d && d[0]) ? d : XENOID_DEFAULT_PROFILE_DIR;
}

static void join_profile_path(char *buf, size_t bufsz, const char *leaf) {
  snprintf(buf, bufsz, "%s/%s", profile_dir(), leaf);
}

static char *load_boot_id(void) {
  char p[512];
  join_profile_path(p, sizeof(p), "boot_id");
  return read_first_or_default(p, XENOID_DEFAULT_BOOT_ID);
}
static char *load_mac_text(void) {
  char p[512];
  const char *env = getenv("XENOID_MAC");
  if (env && env[0]) {
    size_t n = strlen(env);
    char *out = calloc(1, n + 2);
    memcpy(out, env, n);
    if (n == 0 || env[n - 1] != '\n') out[n++] = '\n';
    out[n] = 0;
    return out;
  }
  join_profile_path(p, sizeof(p), "mac_address");
  return read_first_or_default(p, XENOID_DEFAULT_MAC);
}
static char *fake_boot_id(void) {
  return cached_boot_id ? strdup(cached_boot_id) : load_boot_id();
}
static char *fake_mac_text(void) {
  return cached_mac_text ? strdup(cached_mac_text) : load_mac_text();
}
__attribute__((unused)) static void fake_mac_bytes(unsigned char mac[6]) { char *s=fake_mac_text(); unsigned int b[6]={2,0xaa,0xbb,0xcc,0xdd,0xee}; sscanf(s,"%x:%x:%x:%x:%x:%x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]); for(int i=0;i<6;i++) mac[i]=(unsigned char)b[i]; free(s); }


static int line_hidden(const char *l) {
  static const char *tcp_ports[]={":15B3",":69A2",":69A3",":494D",":494E",":494F",":90ED",":9999",NULL};
  static const char *markers[]={"xenoid","libxenoid","shim",".fs64",".netd-helper","frida","gum-js-loop","gmain","gdbus","magisk","zygisk","xposed","lsposed","/su","/system/xbin/su","docker","containerd","overlayfs","upperdir=","workdir=","lowerdir=","/var/lib/","xenoid-overlay","xenoid-data","virtio","xen","vbox","vmw","/data/local/tmp","/data/asan","asan.","OpenStack","KVM","QEMU","PCI Bus","PCI-MSIX","virtio-pci","xen_","amd_","epyc","jdwp","libadbconnection","@jdwp",NULL};
  return str_contains_any(l,tcp_ports) || str_contains_any(l,markers);
}

static int is_maps_text_path(const char *path) {
  if (!path) return 0;
  const char *test_path = getenv("XENOID_TEST_MAPS_PATH");
  if (test_path && test_path[0] && !strcmp(path, test_path)) return 1;
  if (!strcmp(path, "/proc/self/__unused_maps")) return 1;
  const char *name = strrchr(path, '/');
  name = name ? name + 1 : path;
  return !strcmp(name, "maps") || !strcmp(name, "smaps") ||
         !strcmp(name, "smaps_rollup");
}

static int maps_line_hidden(const char *line) {
  if (!line) return 0;

  static const char *dex_like[] = {".dex", ".jar", ".oat", ".vdex", ".odex", NULL};
  int is_dex_like = str_contains_any(line, dex_like);
  if (is_dex_like && strstr(line, "(deleted)")) return 1;

  /* A maps line starts with five whitespace-delimited metadata fields. */
  const char *mapped_name = line;
  for (int field = 0; field < 5; field++) {
    mapped_name += strspn(mapped_name, " \t");
    mapped_name += strcspn(mapped_name, " \t");
  }
  mapped_name += strspn(mapped_name, " \t");
  if (is_dex_like &&
      (!strncmp(mapped_name, "memfd:", 6) ||
       !strncmp(mapped_name, "/memfd:", 7))) {
    return 1;
  }

  if (strstr(line, "[anon:swiftshader_jit]")) return 1;
  if (strstr(line, "[anon:dalvik-") && !strstr(line, ".art") &&
      (strstr(line, ".dex") || strstr(line, ".jar") ||
       strstr(line, "classes") || strstr(line, "framework/"))) {
    return 1;
  }
  return 0;
}

static int xenoid_reader_is_app_uid(void) {
  static int cached_app_uid;
  const char *force;
  if (cached_app_uid) return 1;
  force = getenv("XENOID_TEST_FORCE_APP_UID");
  if ((force && !strcmp(force, "1")) || getuid() >= 10000) {
    cached_app_uid = 1;
    return 1;
  }
  return 0;
}
static int xenoid_runtime_identity_scope(void) {
  return zygote_identity_scope || xenoid_reader_is_app_uid();
}

/* The shim is preloaded into zygote, so it also maps into system_server.
   Only app UIDs get path/content interposition; privileged processes must see
   the real filesystem or package/framework initialization can break. */
static int path_hidden_for_reader(const char *path) {
  static char cache_path[384];
  static int cache_valid;
  static int cache_app_uid;
  static int cache_result;
  int app_uid = xenoid_reader_is_app_uid();
  int result;
  if (path && cache_valid && cache_app_uid == app_uid && !strcmp(path, cache_path))
    return cache_result;
  result = app_uid && hidden_path(path);
  if (path) {
    size_t n = strlen(path);
    if (n < sizeof(cache_path)) {
      memcpy(cache_path, path, n + 1);
      cache_app_uid = app_uid;
      cache_result = result;
      cache_valid = 1;
    } else {
      cache_valid = 0;
    }
  }
  return result;
}

static void rewrite_maps_line(char *line) {
  const char *from = "/system/product/";
  const char *to = "/product/";
  char *p;
  if (!line) return;
  p = strstr(line, from);
  if (!p) return;
  memmove(p + strlen(to), p + strlen(from), strlen(p + strlen(from)) + 1);
  memcpy(p, to, strlen(to));
}

static char *filter_lines(const char *p){
  char*s=read_file_real(p); size_t slen=strlen(s); char*out=calloc(1,slen+64); if(!out){free(s); return strdup("");}
  int is_status = p && strstr(p,"/status");
  int filter_app_maps = xenoid_reader_is_app_uid() && is_maps_text_path(p);
  size_t off=0; char*save=NULL;
  for(char*l=strtok_r(s,"\n",&save);l;l=strtok_r(NULL,"\n",&save)){
    if (filter_app_maps) rewrite_maps_line(l);
    int hidden = line_hidden(l);
    /* Keep real .so rows visible in maps: Launch compares the .so-only hash of
       libc fopen() with a raw SVC read. Hiding our preload libraries makes that
       anti-filter check look like a hook. The paths are legitimate /system/lib64
       files and do not trigger its injection-name rules. */
    if (filter_app_maps && hidden && strstr(l, ".so")) hidden = 0;
    if(!hidden && !(filter_app_maps && maps_line_hidden(l))){
      size_t n;
      /* Shape CPU visibility in proc status files to match the faked 8-core
         cpuinfo/sysfs overlays (host may expose 4 or 128 cores). */
      if(is_status && strncmp(l,"Cpus_allowed:\t",13)==0){ l=(char*)"Cpus_allowed:\tff"; }
      else if(is_status && strncmp(l,"Cpus_allowed_list:\t",19)==0){ l=(char*)"Cpus_allowed_list:\t0-7"; }
      n=strlen(l);
      if(off+n+2>slen+63) break;
      memcpy(out+off,l,n); off+=n; out[off++]='\n'; out[off]=0;
    }
  }
  free(s); return out;
}


static int make_fake_len(const char*d,size_t n){
  /* memfd has no capacity limit; a pipe deadlocks when fake content exceeds
     its 64KiB buffer because no reader owns the read end yet. */
#ifdef SYS_memfd_create
  int mfd=(int)syscall(SYS_memfd_create,"xenoid-fake",0);
  if(mfd>=0){ size_t off=0; while(off<n){ ssize_t w=write(mfd,d+off,n-off); if(w<=0)break; off+=(size_t)w; } lseek(mfd,0,SEEK_SET); return mfd; }
#endif
  int fds[2]; if(pipe(fds))return -1;
  size_t off=0; while(off<n){ ssize_t w=write(fds[1],d+off,n-off); if(w<=0) break; off+=(size_t)w; }
  close(fds[1]); return fds[0];
}
static int make_fake(const char*d){ return make_fake_len(d,strlen(d)); }
static const char *test_path(const char *env_name, const char *fallback) {
  const char *v = getenv(env_name);
  return (v && v[0]) ? v : fallback;
}
static int path_eq(const char*p,const char*q){ return p&&strcmp(p,q)==0; }



static int is_comm_file(const char *p){ return p && strstr(p,"/comm"); }
static int comm_hidden_content(const char *p){ char *s=read_file_real(p); int h=line_hidden(s); free(s); return h; }

static int is_auxv_file(const char *p){ return p && strstr(p,"/auxv"); }
static int is_environ_file(const char *p){ return p && strstr(p,"/environ"); }
static int is_limits_file(const char *p){ return p && strstr(p,"/limits"); }
static const char *fake_limits_text(void){ return "Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax file size             unlimited            unlimited            bytes     \nMax data size             unlimited            unlimited            bytes     \nMax stack size            8388608              8388608              bytes     \nMax core file size        0                    0                    bytes     \nMax resident set          unlimited            unlimited            bytes     \nMax processes             32768                32768                processes \nMax open files            32768                32768                files     \nMax locked memory         8388608              8388608              bytes     \nMax address space         unlimited            unlimited            bytes     \n"; }

static int is_kernel_text(const char *p){ return p && (strcmp(p,"/proc/interrupts")==0 || strcmp(p,"/proc/iomem")==0 || strcmp(p,"/proc/ioports")==0 || strcmp(p,"/proc/kallsyms")==0); }
static const char *fake_kernel_text(const char *p){
  if(!p) return "";
  if(strcmp(p,"/proc/interrupts")==0) return "           CPU0       CPU1       CPU2       CPU3\n 17:       1024          0          0          0     GICv3  30 Level     arch_timer\n 45:        128          0          0          0     GICv3  98 Level     msm_serial\n 88:       4096          0          0          0     GICv3 204 Level     kgsl-3d0\n";
  if(strcmp(p,"/proc/iomem")==0) return "00000000-00000fff : reserved\n80000000-ffffffff : System RAM\n  80200000-82ffffff : Kernel code\n";
  if(strcmp(p,"/proc/ioports")==0) return "0000-0000 : reserved\n";
  if(strcmp(p,"/proc/kallsyms")==0) return "0000000000000000 T _text\n0000000000000000 T start_kernel\n0000000000000000 T rest_init\n";
  return "";
}

static int is_proc_net_file(const char*p){ return p && strstr(p,"/net/") && (strstr(p,"/tcp") || strstr(p,"/udp") || strstr(p,"/unix") || strstr(p,"/raw")); }
static int is_tcp(const char*p){ return p&&(strcmp(p,"/proc/net/tcp")==0||strcmp(p,"/proc/net/tcp6")==0); }
static int is_proc_filter_file(const char*p){
  return p&&(strcmp(p,"/proc/net/tcp")==0||strcmp(p,"/proc/net/tcp6")==0||strstr(p,"/maps")||strstr(p,"/smaps")||strstr(p,"/mountinfo")||strstr(p,"/mounts")||strstr(p,"/cgroup")||strstr(p,"/comm")||strcmp(p,"/proc/modules")==0||strcmp(p,"/proc/interrupts")==0||strcmp(p,"/proc/iomem")==0||strcmp(p,"/proc/ioports")==0||strcmp(p,"/proc/kallsyms")==0||strstr(p,"/cmdline")||strstr(p,"/status"));
}
static int proc_pid_from_path(const char *path);
static int hidden_proc_pid(int pid);
static int is_fdinfo_file(const char *p){ return p && strncmp(p,"/proc/",6)==0 && strstr(p,"/fdinfo/"); }
static int is_mac_addr_path(const char *p){ return p && strstr(p,"/sys/class/net/") && strstr(p,"/address"); }

static int fake_cpufreq_fd(const char *path) {
  /* Provide profile-consistent per-CPU frequency nodes when the base runtime
     does not expose them. */
  if (!path) return -2;
  const char *p = strstr(path, "/sys/devices/system/cpu/cpu");
  if (!p) return -2;
  p += strlen("/sys/devices/system/cpu/cpu");
  if (*p < '0' || *p > '9') return -2;
  int cpu = 0; while (*p >= '0' && *p <= '9') { cpu = cpu * 10 + (*p - '0'); p++; }
  if (cpu < 0 || cpu > 7) return -2;
  if (strncmp(p, "/cpufreq/", 9) != 0) return -2;
  const char *leaf = p + 9;
  long maxf = cpu < 6 ? 2995000 : 2850000;
  long minf = 300000;
  long curf = 1500000 + (long)cpu * 70000; /* vary so allSame=false */
  char buf[64];
  if (!strcmp(leaf, "cpuinfo_max_freq")) snprintf(buf, sizeof(buf), "%ld\n", maxf);
  else if (!strcmp(leaf, "cpuinfo_min_freq")) snprintf(buf, sizeof(buf), "%ld\n", minf);
  else if (!strcmp(leaf, "scaling_cur_freq")) snprintf(buf, sizeof(buf), "%ld\n", curf);
  else if (!strcmp(leaf, "scaling_governor")) snprintf(buf, sizeof(buf), "schedutil\n");
  else return -2;
  return make_fake(buf);
}

static int open_virtual(const char *path) {
  int reader_is_app = xenoid_reader_is_app_uid();
  if (!reader_is_app) return -2;
  /* Fast path for timing-sensitive ordinary files: virtual views only exist
     under /proc, /sys, and host-test /tmp fixtures. */
  if (!path || (strncmp(path, "/proc/", 6) && strncmp(path, "/sys/", 5) && strncmp(path, "/tmp/", 5))) {
    if (!getenv("XENOID_TEST_BOOT_ID_PATH") && !getenv("XENOID_TEST_TCP_PATH") &&
        !getenv("XENOID_TEST_MAPS_PATH") && !getenv("XENOID_TEST_MAC_PATH")) return -2;
  }
  { int cfd = fake_cpufreq_fd(path); if (cfd != -2) return cfd; }
  if (is_fdinfo_file(path) && hidden_proc_pid(proc_pid_from_path(path))) return make_fake("pos:\t0\nflags:\t0100000\nmnt_id:\t0\nino:\t0\n");
  if (is_comm_file(path) && comm_hidden_content(path)) return make_fake("main\n");
  if (is_auxv_file(path)) { unsigned long long z[2]={0,0}; return make_fake_len((const char*)z,sizeof(z)); }
  if (path && strcmp(path,"/sys/fs/selinux/enforce")==0) return make_fake("1\n");
  if (path && strcmp(path,"/sys/fs/selinux/policyvers")==0) return make_fake("33\n");
  if (is_environ_file(path)) return make_fake("");
  if (is_limits_file(path)) return make_fake(fake_limits_text());
  if (path_eq(path,test_path("XENOID_TEST_BOOT_ID_PATH","/proc/sys/kernel/random/boot_id"))) { char *d=fake_boot_id(); int fd=make_fake(d); free(d); return fd; }
  if (is_mac_addr_path(path) || path_eq(path,test_path("XENOID_TEST_MAC_PATH","/sys/class/net/__unused__/address"))) { char *d=fake_mac_text(); int fd=make_fake(d); free(d); return fd; }
  if (is_kernel_text(path)) return make_fake(fake_kernel_text(path));
  if (is_tcp(path) || is_proc_net_file(path) || is_proc_filter_file(path) || path_eq(path,test_path("XENOID_TEST_TCP_PATH","/proc/net/__unused_tcp")) || path_eq(path,test_path("XENOID_TEST_MAPS_PATH","/proc/self/__unused_maps"))) { char*d=filter_lines(path); int fd=make_fake(d); free(d); return fd; }
  return -2;
}

int open64(const char*path,int flags,...);
int openat64(int dirfd,const char*path,int flags,...);
int openat(int dirfd,const char*path,int flags,...){
  static openat_t real;
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
  mode_t mode=0; if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} if(!real) real=(openat_t)dlsym(RTLD_NEXT,"openat"); return (flags&O_CREAT)?real(dirfd,path,flags,mode):real(dirfd,path,flags);
}
int open(const char*path,int flags,...){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
  mode_t mode=0; if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} open_t real=(open_t)dlsym(RTLD_NEXT,"open"); return (flags&O_CREAT)?real(path,flags,mode):real(path,flags);
}
int __open_2(const char*path,int flags){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
#ifdef SYS_openat
  return (int)syscall(SYS_openat,AT_FDCWD,path,flags,0);
#else
  open_t real=(open_t)dlsym(RTLD_NEXT,"__open_2");
  return real?real(path,flags):-1;
#endif
}
int __openat_2(int dirfd,const char*path,int flags){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
#ifdef SYS_openat
  return (int)syscall(SYS_openat,dirfd,path,flags,0);
#else
  openat_t real=(openat_t)dlsym(RTLD_NEXT,"__openat_2");
  return real?real(dirfd,path,flags):-1;
#endif
}
int open64(const char*path,int flags,...){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
  mode_t mode=0; if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} open_t real=(open_t)dlsym(RTLD_NEXT,"open64"); if(!real) real=(open_t)dlsym(RTLD_NEXT,"open"); return (flags&O_CREAT)?real(path,flags,mode):real(path,flags);
}
int openat64(int dirfd,const char*path,int flags,...){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(!(flags&O_WRONLY) && !(flags&O_RDWR)){ int v=open_virtual(path); if(v!=-2) return v; }
  mode_t mode=0; if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} openat_t real=(openat_t)dlsym(RTLD_NEXT,"openat64"); if(!real) real=(openat_t)dlsym(RTLD_NEXT,"openat"); return (flags&O_CREAT)?real(dirfd,path,flags,mode):real(dirfd,path,flags);
}
int access(const char*path,int mode){ static access_t real; if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} if(!real) real=(access_t)dlsym(RTLD_NEXT,"access"); return real(path,mode);}
int faccessat(int dirfd,const char*path,int mode,int flags){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} faccessat_t real=(faccessat_t)dlsym(RTLD_NEXT,"faccessat"); return real?real(dirfd,path,mode,flags):-1;}
int stat(const char*path,struct stat*st){ static stat_t real; if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} if(!real) real=(stat_t)dlsym(RTLD_NEXT,"stat"); return real(path,st);}
int fstatat(int dirfd,const char*path,struct stat*st,int flags){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} fstatat_t real=(fstatat_t)dlsym(RTLD_NEXT,"fstatat"); return real?real(dirfd,path,st,flags):-1;}

int newfstatat(int dirfd,const char*path,struct stat*st,int flags){ return fstatat(dirfd,path,st,flags); }
int __newfstatat(int dirfd,const char*path,struct stat*st,int flags){ return fstatat(dirfd,path,st,flags); }
int __fstatat(int dirfd,const char*path,struct stat*st,int flags){ return fstatat(dirfd,path,st,flags); }
int statx(int dirfd, const char *path, int flags, unsigned int mask, void *stx){
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  typedef int (*statx_t)(int,const char*,int,unsigned int,void*);
  statx_t real=(statx_t)dlsym(RTLD_NEXT,"statx");
  return real?real(dirfd,path,flags,mask,stx):-1;
}

int fstatat64(int dirfd,const char*path,struct stat64*st,int flags){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} typedef int (*fstatat64_t)(int,const char*,struct stat64*,int); fstatat64_t real=(fstatat64_t)dlsym(RTLD_NEXT,"fstatat64"); return real?real(dirfd,path,st,flags):-1; }
int __stat64(const char*path,struct stat64*st){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} typedef int (*stat64_t)(const char*,struct stat64*); stat64_t real=(stat64_t)dlsym(RTLD_NEXT,"__stat64"); if(!real) real=(stat64_t)dlsym(RTLD_NEXT,"stat64"); return real?real(path,st):-1; }
int __lstat64(const char*path,struct stat64*st){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} typedef int (*stat64_t)(const char*,struct stat64*); stat64_t real=(stat64_t)dlsym(RTLD_NEXT,"__lstat64"); if(!real) real=(stat64_t)dlsym(RTLD_NEXT,"lstat64"); return real?real(path,st):-1; }
int lstat(const char*path,struct stat*st){ if(path_hidden_for_reader(path)){errno=ENOENT;return -1;} lstat_t real=(lstat_t)dlsym(RTLD_NEXT,"lstat"); return real(path,st);}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  typedef int (*connect_t)(int,const struct sockaddr*,socklen_t);
  if(xenoid_reader_is_app_uid() && addr && addrlen >= (socklen_t)sizeof(sa_family_t) && addr->sa_family == AF_UNIX){
    const struct sockaddr_un *un = (const struct sockaddr_un*)addr;
    /* pathname unix socket */
    if(un->sun_path[0] != '\0'){
      if(path_hidden_for_reader(un->sun_path)){ errno = ENOENT; return -1; }
    } else {
      /* abstract namespace: sun_path[0]=='\\0', name follows */
      size_t n = 0;
      if(addrlen > (socklen_t)offsetof(struct sockaddr_un, sun_path))
        n = (size_t)addrlen - (size_t)offsetof(struct sockaddr_un, sun_path);
      if(n > 1){
        char name[108];
        size_t copy = n - 1; if(copy > sizeof(name)-1) copy = sizeof(name)-1;
        memcpy(name, un->sun_path + 1, copy); name[copy] = 0;
        if(strstr(name, "jdwp") || strstr(name, "adbd")){ errno = ENOENT; return -1; }
      }
    }
  }
  connect_t real = (connect_t)dlsym(RTLD_NEXT, "connect");
  return real ? real(sockfd, addr, addrlen) : -1;
}


static int proc_pid_from_path(const char *path) {
  if(!path || strncmp(path,"/proc/",6)!=0) return -1;
  const char *p=path+6; int pid=0; if(*p<'0'||*p>'9') return -1;
  while(*p>='0'&&*p<='9'){ pid=pid*10+(*p-'0'); p++; }
  return pid;
}
static int hidden_proc_pid(int pid) {
  if(pid<=0) return 0;
  char p[64]; snprintf(p,sizeof(p),"/proc/%d/cmdline",pid);
  char *s=read_file_real(p); int h=line_hidden(s); free(s); return h;
}
static int is_proc_fd_path(const char *path) { return path && strncmp(path,"/proc/",6)==0 && strstr(path,"/fd/"); }
static ssize_t fake_readlink_result(char *buf, size_t bufsiz, const char *value) {
  size_t n=strlen(value); if(n>bufsiz) n=bufsiz; memcpy(buf,value,n); return (ssize_t)n;
}
static int benign_android_memfd(const char *target, size_t n) {
  /* Launch ModuleInjection treats ordinary ART/WebView memfds as foreign FDs.
     Rewrite those to system paths; leave other memfds for Frida inject. */
  if(!target || n < 6 || !memmem(target, n, "memfd:", 6)) return 0;
  if(memmem(target, n, "fontMap", 7)) return 1;
  if(memmem(target, n, "shared_memory/", 14)) return 1;
  /* UUID-like ashmem/memfd names from WebView/Chromium */
  if(memmem(target, n, "(deleted)", 9) && n >= 20) {
    const char *p = (const char*)memmem(target, n, "memfd:", 6);
    if(p){
      p += 6; size_t left = (size_t)(target + n - p);
      /* 8-4-4-4-12 uuid */
      int hex=0, dash=0; for(size_t i=0;i<left && i<64;i++){
        char c=p[i];
        if(c=='-') dash++;
        else if((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) hex++;
        else if(c==' '||c=='(') break;
        else return 0;
      }
      if(dash>=4 && hex>=20) return 1;
    }
  }
  return 0;
}
static ssize_t sanitize_readlink_result(const char *path, char *buf, size_t bufsiz, ssize_t r) {
  if(r<=0 || !buf) return r;
  if((size_t)r>=bufsiz && bufsiz>0) r=(ssize_t)bufsiz;
  /* Keep proc fd memfd targets intact so Frida/gadget inject via
     dlopen("/proc/self/fd/N") continues to work under LD_PRELOAD —
     except known-benign Android memfds that Launch flags as foreign. */
  if(is_proc_fd_path(path)) {
    int pid=proc_pid_from_path(path);
    if(hidden_proc_pid(pid) && (memmem(buf,(size_t)r,"socket:",7) || memmem(buf,(size_t)r,"pipe:",5) || memmem(buf,(size_t)r,"anon_inode",10)))
      return fake_readlink_result(buf,bufsiz,"/dev/null");
    if(benign_android_memfd(buf, (size_t)r))
      return fake_readlink_result(buf,bufsiz,"/system/fonts/Roboto-Regular.ttf");
    return r;
  }
  int target_hidden = path_hidden_for_reader(buf) || line_hidden(buf) || memmem(buf,(size_t)r,"memfd:",6) || memmem(buf,(size_t)r,"deleted",7);
  if(target_hidden) return fake_readlink_result(buf,bufsiz,"/dev/null");
  return r;
}

ssize_t readlink(const char*path,char*buf,size_t bufsiz){
  readlink_t real=(readlink_t)dlsym(RTLD_NEXT,"readlink");
  if(!xenoid_reader_is_app_uid()) return real?real(path,buf,bufsiz):-1;
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(path && (strcmp(path,"/sys/block/vda")==0 || strcmp(path,"/sys/block/vdb")==0)) {
    const char *fake = "../devices/platform/soc/1d84000.ufshc/mmc_host/mmc0/mmc0:0001/block/mmcblk0";
    size_t n=strlen(fake); if(n>bufsiz) n=bufsiz; memcpy(buf,fake,n); return (ssize_t)n;
  }
  ssize_t r=real?real(path,buf,bufsiz):-1;
  if(r>0 && buf && (memmem(buf,(size_t)r,"virtio",6) || memmem(buf,(size_t)r,"pci",3))) { errno=ENOENT; return -1; }
  return sanitize_readlink_result(path,buf,bufsiz,r);
}


#if XENOID_HAS_PRCTL
int prctl(int option, ...) {
  va_list ap; va_start(ap, option);
  unsigned long a2=va_arg(ap,unsigned long), a3=va_arg(ap,unsigned long), a4=va_arg(ap,unsigned long), a5=va_arg(ap,unsigned long);
  va_end(ap);
  /* Scudo names fresh mappings with prctl while the dynamic linker may hold its
   * symbol lock. Resolving prctl lazily with dlsym here deadlocks the allocator
   * and eventually ANRs the process. The syscall is the complete prctl ABI. */
  if(xenoid_reader_is_app_uid() && option==PR_SET_NAME && (const char*)a2 && line_hidden((const char*)a2)) a2=(unsigned long)"main";
  int r=(int)syscall(SYS_prctl,option,a2,a3,a4,a5);
  if(r==0 && option==PR_GET_NAME && (char*)a2 && line_hidden((const char*)a2)) {
    memset((char*)a2,0,16); snprintf((char*)a2,16,"main");
  }
  return r;
}


int pthread_getname_np(pthread_t thread, char *name, size_t len) {
  typedef int (*pthread_getname_np_t)(pthread_t,char*,size_t);
  pthread_getname_np_t real=(pthread_getname_np_t)dlsym(RTLD_NEXT,"pthread_getname_np");
  if(!xenoid_reader_is_app_uid()) return real?real(thread,name,len):22;
  if(!name || len==0) return 22;
  if(!pthread_equal(thread,pthread_self())) { snprintf(name,len,"main"); return 0; }
  char tmp[16]={0};
  prctl(PR_GET_NAME,(unsigned long)tmp,0,0,0);
  if(line_hidden(tmp)) snprintf(name,len,"main"); else snprintf(name,len,"%s",tmp);
  return 0;
}

#endif
int uname(struct utsname *buf) {
  uname_t real=(uname_t)dlsym(RTLD_NEXT,"uname");
  int r=real?real(buf):-1;
  if(r==0 && buf && xenoid_runtime_identity_scope()){
    snprintf(buf->sysname,sizeof(buf->sysname),"Linux");
    snprintf(buf->nodename,sizeof(buf->nodename),"localhost");
    snprintf(buf->release,sizeof(buf->release),"5.10.107-android13-4-00001-g6f2c7c7f0f0e-ab8977058");
    snprintf(buf->version,sizeof(buf->version),"#1 SMP PREEMPT Wed Oct 5 04:00:00 UTC 2022");
    snprintf(buf->machine,sizeof(buf->machine),"aarch64");
  }
  return r;
}



ssize_t readlinkat(int dirfd,const char*path,char*buf,size_t bufsiz){
  readlinkat_t real=(readlinkat_t)dlsym(RTLD_NEXT,"readlinkat");
  if(!xenoid_reader_is_app_uid()) return real?real(dirfd,path,buf,bufsiz):-1;
  if(path_hidden_for_reader(path)){errno=ENOENT;return -1;}
  if(path && (strcmp(path,"/sys/block/vda")==0 || strcmp(path,"/sys/block/vdb")==0 || strcmp(path,"vda")==0 || strcmp(path,"vdb")==0)) {
    const char *fake = "../devices/platform/soc/1d84000.ufshc/mmc_host/mmc0/mmc0:0001/block/mmcblk0";
    size_t n=strlen(fake); if(n>bufsiz) n=bufsiz; memcpy(buf,fake,n); return (ssize_t)n;
  }
  ssize_t r=real?real(dirfd,path,buf,bufsiz):-1;
  if(r>0 && buf && (memmem(buf,(size_t)r,"virtio",6) || memmem(buf,(size_t)r,"pci",3))) { errno=ENOENT; return -1; }
  return sanitize_readlink_result(path,buf,bufsiz,r);
}

struct xenoid_linux_dirent64 { unsigned long long d_ino; long long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };
int getdents64(unsigned int fd, void *dirp, unsigned int count) {
  getdents64_t real=(getdents64_t)dlsym(RTLD_NEXT,"getdents64");
  int nread=real?real(fd,dirp,count):-1;
  if(!xenoid_reader_is_app_uid()) return nread;
  if(nread<=0 || !dirp) return nread;
  int bpos=0,out=0;
  while(bpos<nread){
    struct xenoid_linux_dirent64 *d=(struct xenoid_linux_dirent64*)((char*)dirp+bpos);
    int reclen=d->d_reclen;
    if(reclen<=0) break;
    if(!hidden_dirent(d->d_name)) { if(out!=bpos) memmove((char*)dirp+out,d,reclen); out+=reclen; }
    bpos+=reclen;
  }
  return out;
}

struct dirent *readdir(DIR *dirp) { readdir_t real=(readdir_t)dlsym(RTLD_NEXT,"readdir"); if(!real) return NULL; if(!xenoid_reader_is_app_uid()) return real(dirp); struct dirent *e; do { e=real(dirp); } while(e && hidden_dirent(e->d_name)); return e; }






long sysconf(int name) {
  if(xenoid_reader_is_app_uid() && (name==_SC_NPROCESSORS_CONF || name==_SC_NPROCESSORS_ONLN)) return 8;
#ifdef _SC_PHYS_PAGES
  if(xenoid_reader_is_app_uid() && name==_SC_PHYS_PAGES) return 2031616; // 7.75 GiB / 4 KiB
#endif
  sysconf_t real=(sysconf_t)dlsym(RTLD_NEXT,"sysconf");
  return real?real(name):-1;
}

/* libc-level hooks for the surfaces the kernel module left to userland:
   affinity / sysinfo / statfs — safe, proven LD_PRELOAD territory. */
#if defined(__linux__)
typedef int (*sched_getaffinity_t)(pid_t, size_t, cpu_set_t *);
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
  (void)pid;
  if (xenoid_reader_is_app_uid() && mask && cpusetsize >= sizeof(unsigned long)) {
    CPU_ZERO(mask);
    *(unsigned long *)mask = 0xff; // 8 visible cores, aligned with cpuinfo/sysfs overlays
    return 0;
  }
  sched_getaffinity_t real=(sched_getaffinity_t)dlsym(RTLD_NEXT,"sched_getaffinity");
  return real?real(pid,cpusetsize,mask):-1;
}

typedef int (*sysinfo_t)(struct sysinfo *);
int sysinfo(struct sysinfo *info) {
  sysinfo_t real=(sysinfo_t)dlsym(RTLD_NEXT,"sysinfo");
  int r=real?real(info):-1;
  if(r==0 && info && xenoid_reader_is_app_uid()){
    info->totalram = 7936UL*1024*1024;      // 7.75 GiB, aligned with ActivityManager
    info->freeram  = 5UL*1024*1024*1024;
    info->totalswap = 4194300UL*1024;
    info->freeswap = 4194300UL*1024;
    info->mem_unit = 1;
  }
  return r;
}

typedef int (*statfs_t)(const char *, struct statfs *);
static void shape_statfs(struct statfs *st) {
  if(!st) return;
  if(st->f_type == 0x794c7630 /* OVERLAYFS_SUPER_MAGIC */ || st->f_type == 0x65735546 /* FUSE */)
    st->f_type = 0xEF53; /* EXT4_SUPER_MAGIC */
}
int statfs(const char *path, struct statfs *buf) {
  statfs_t real=(statfs_t)dlsym(RTLD_NEXT,"statfs");
  int r=real?real(path,buf):-1;
  if(r==0 && xenoid_reader_is_app_uid()) shape_statfs(buf);
  return r;
}

typedef int (*statfs64_t)(const char *, struct statfs64 *);
int statfs64(const char *path, struct statfs64 *buf) {
  statfs64_t real=(statfs64_t)dlsym(RTLD_NEXT,"statfs64");
  int r=real?real(path,buf):-1;
  if(r==0 && buf && xenoid_reader_is_app_uid() && (buf->f_type == 0x794c7630 || buf->f_type == 0x65735546)) buf->f_type = 0xEF53;
  return r;
}

typedef int (*fstatfs_t)(int, struct statfs *);
int fstatfs(int fd, struct statfs *buf) {
  fstatfs_t real=(fstatfs_t)dlsym(RTLD_NEXT,"fstatfs");
  int r=real?real(fd,buf):-1;
  if(r==0 && xenoid_reader_is_app_uid()) shape_statfs(buf);
  return r;
}

typedef int (*fstatfs64_t)(int, struct statfs64 *);
int fstatfs64(int fd, struct statfs64 *buf) {
  fstatfs64_t real=(fstatfs64_t)dlsym(RTLD_NEXT,"fstatfs64");
  int r=real?real(fd,buf):-1;
  if(r==0 && buf && xenoid_reader_is_app_uid() && (buf->f_type == 0x794c7630 || buf->f_type == 0x65735546)) buf->f_type = 0xEF53;
  return r;
}
#endif /* __linux__ */

unsigned long getauxval(unsigned long type) {
  static const char platform[] = "aarch64";
  if(!xenoid_reader_is_app_uid()) { getauxval_t real=(getauxval_t)dlsym(RTLD_NEXT,"getauxval"); return real?real(type):0; }
#ifdef AT_PLATFORM
  if(type==AT_PLATFORM) return (unsigned long)platform;
#endif
#ifdef AT_HWCAP
  if(type==AT_HWCAP) return 0x000000000000001full;
#endif
#ifdef AT_HWCAP2
  if(type==AT_HWCAP2) return 0;
#endif
  getauxval_t real=(getauxval_t)dlsym(RTLD_NEXT,"getauxval");
  return real?real(type):0;
}

static void audit_dlopen_block(const char *path) {
  (void)path;
  // Keep silent by default; writing audit logs would itself create an observable artifact.
}
static int inject_path(const char *p){
  /* Allow Frida/gadget inject via memfd descriptor paths while still hiding
     named frida/magisk libraries from normal app dlopen probes. */
  if(!p) return 0;
  if(!strncmp(p,"/proc/",6) && strstr(p,"/fd/")) return 1;
  const char *a=getenv("XENOID_ALLOW_INJECT");
  return a && a[0]=='1';
}
void *dlopen(const char *filename, int flags) {
  if(filename && path_hidden_for_reader(filename) && !inject_path(filename)) { audit_dlopen_block(filename); errno=ENOENT; return NULL; }
  dlopen_t real=(dlopen_t)dlsym(RTLD_NEXT,"dlopen");
  return real?real(filename,flags):NULL;
}
void *android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
  if(filename && path_hidden_for_reader(filename) && !inject_path(filename)) { audit_dlopen_block(filename); errno=ENOENT; return NULL; }
  android_dlopen_ext_t real=(android_dlopen_ext_t)dlsym(RTLD_NEXT,"android_dlopen_ext");
  return real?real(filename,flags,extinfo):NULL;
}

#if XENOID_HAS_LINK_H
struct xenoid_dl_ctx { int (*cb)(struct dl_phdr_info*, size_t, void*); void *data; };
static int xenoid_dl_cb(struct dl_phdr_info *info, size_t size, void *data) {
  struct xenoid_dl_ctx *ctx=(struct xenoid_dl_ctx*)data;
  if(info && info->dlpi_name && path_hidden_for_reader(info->dlpi_name)) return 0;
  return ctx->cb(info,size,ctx->data);
}
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*), void *data) {
  dl_iterate_phdr_t real=(dl_iterate_phdr_t)dlsym(RTLD_NEXT,"dl_iterate_phdr");
  if(!real || !callback) return 0;
  struct xenoid_dl_ctx ctx={callback,data};
  return real(xenoid_dl_cb,&ctx);
}
#endif


/* Remove the preload variable after initialization so child process
   environments contain only effective runtime configuration. */
extern char **environ;
__attribute__((constructor)) static void xenoid_shim_scrub_preload(void) {
  zygote_identity_scope = getenv("ANDROID_SOCKET_zygote") != NULL;
  if (zygote_identity_scope) {
    cached_boot_id = load_boot_id();
    cached_mac_text = load_mac_text();
  }
  for (char **e = environ; e && *e; ++e) {
    if (strncmp(*e, "LD_PRELOAD=", 11) == 0) {
      memset(*e, ' ', strlen(*e));
      break;
    }
  }
  unsetenv("LD_PRELOAD");
}

#ifdef XENOID_HOST_TEST
__attribute__((visibility("default"))) int xenoid_open_probe(const char *path, int flags) { return open(path, flags); }
__attribute__((visibility("default"))) int xenoid_access_probe(const char *path, int mode) { return access(path, mode); }
__attribute__((visibility("default"))) struct dirent *xenoid_readdir_probe(DIR *dirp) { return readdir(dirp); }
#endif

#ifdef XENOID_ENABLE_PROPERTY_GET
struct xenoid_prop_kv { const char *k; const char *v; };
static const struct xenoid_prop_kv xenoid_prop_spoofs[] = {
  {"ro.debuggable","0"},{"ro.secure","1"},{"ro.adb.secure","1"},
  {"service.adb.tcp.port","-1"},{"service.adb.tls.port","-1"},{"init.svc.adbd","stopped"},
  {"ro.product.brand","google"},{"ro.product.manufacturer","Google"},{"ro.product.model","Pixel 6 Pro"},{"ro.product.device","raven"},{"ro.product.name","raven"},
  {"ro.build.fingerprint","google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys"},{"ro.build.tags","release-keys"},{"ro.build.type","user"},
  {"ro.hardware","tensor"},{"ro.boot.hardware","gs101"},{"ro.hardware.sku","G1MNW"},
  {NULL,NULL}};
static const char *xenoid_prop_spoof(const char *name) {
  if (!name) return NULL;
  for (int i = 0; xenoid_prop_spoofs[i].k; i++) if (!strcmp(name, xenoid_prop_spoofs[i].k)) return xenoid_prop_spoofs[i].v;
  return NULL;
}
int __system_property_get(const char *name, char *value) {
  const char *spoof = xenoid_prop_spoof(name);
  if (spoof) { strcpy(value, spoof); return (int)strlen(spoof); }
  prop_get_t real=(prop_get_t)dlsym(RTLD_NEXT,"__system_property_get"); return real ? real(name,value) : 0;
}

typedef void (*xenoid_prop_cb_t)(void *cookie, const char *name, const char *value, uint32_t serial);
typedef void (*xenoid_prop_read_callback_t)(const void *pi, xenoid_prop_cb_t cb, void *cookie);
struct xenoid_prop_cb_wrap { xenoid_prop_cb_t cb; void *cookie; };
static void xenoid_prop_cb_wrap_call(void *cookie, const char *name, const char *value, uint32_t serial) {
  struct xenoid_prop_cb_wrap *w = (struct xenoid_prop_cb_wrap *)cookie;
  const char *spoof = xenoid_prop_spoof(name);
  w->cb(w->cookie, name, spoof ? spoof : value, serial);
}
void __system_property_read_callback(const void *pi, xenoid_prop_cb_t cb, void *cookie) {
  xenoid_prop_read_callback_t real = (xenoid_prop_read_callback_t)dlsym(RTLD_NEXT, "__system_property_read_callback");
  if (!real || !cb) { if (real) real(pi, cb, cookie); return; }
  struct xenoid_prop_cb_wrap w = {cb, cookie};
  real(pi, xenoid_prop_cb_wrap_call, &w);
}
#endif

#ifdef XENOID_ENABLE_IOCTL
typedef int (*ioctl_t)(int, int, ...);
int ioctl(int fd, int req, ...) {
  va_list ap; va_start(ap, req); void *arg = va_arg(ap, void*); va_end(ap);
  if (req == SIOCGIFHWADDR && arg) { struct ifreq *ifr=(struct ifreq*)arg; unsigned char mac[6]; fake_mac_bytes(mac); memcpy(ifr->ifr_hwaddr.sa_data,mac,6); return 0; }
  ioctl_t real=(ioctl_t)dlsym(RTLD_NEXT,"ioctl"); return real ? real(fd,req,arg) : -1;
}
#endif

#ifdef XENOID_ENABLE_NETLINK_SAFE
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
static int nl_fds[128];
static int nl_count = 0;
typedef int (*socket_t)(int,int,int);
int socket(int domain, int type, int protocol) {
  socket_t real=(socket_t)dlsym(RTLD_NEXT,"socket");
  int fd=real?real(domain,type,protocol):-1;
  if(fd>=0 && domain==AF_NETLINK && protocol==NETLINK_ROUTE && nl_count<128) nl_fds[nl_count++]=fd;
  return fd;
}
static int is_nl(int fd){ for(int i=0;i<nl_count;i++) if(nl_fds[i]==fd) return 1; return 0; }
static void patch_netlink_mac_safe(void *buf, ssize_t len) {
  unsigned char mac[6]; fake_mac_bytes(mac);
  for (struct nlmsghdr *nlh=(struct nlmsghdr*)buf; NLMSG_OK(nlh,(unsigned int)len); nlh=NLMSG_NEXT(nlh,len)) {
    if(nlh->nlmsg_type!=RTM_NEWLINK) continue;
    struct ifinfomsg *ifi=(struct ifinfomsg*)NLMSG_DATA(nlh);
    int attrlen=nlh->nlmsg_len-NLMSG_LENGTH(sizeof(*ifi));
    for(struct rtattr *rta=IFLA_RTA(ifi); RTA_OK(rta,attrlen); rta=RTA_NEXT(rta,attrlen)) {
      if((rta->rta_type==IFLA_ADDRESS || rta->rta_type==IFLA_BROADCAST) && RTA_PAYLOAD(rta)>=6) memcpy(RTA_DATA(rta),mac,6);
    }
  }
}
typedef ssize_t (*recvmsg_t)(int, struct msghdr*, int);
ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
  recvmsg_t real=(recvmsg_t)dlsym(RTLD_NEXT,"recvmsg");
  ssize_t r=real?real(fd,msg,flags):-1;
  if(r>0 && is_nl(fd) && msg && msg->msg_iov && msg->msg_iovlen>0) patch_netlink_mac_safe(msg->msg_iov[0].iov_base,r);
  return r;
}
#endif
