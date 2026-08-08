#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROP_BASE 128u
#define PROP_VALUE_MAX 92u
#define PROFILE_JSON "/data/local/tmp/xenoid-profile/effective.json"
static int g_patch_identity = 0;
static int g_verified = 0;
static char g_brand[PROP_VALUE_MAX] = "google";
static char g_manufacturer[PROP_VALUE_MAX] = "Google";
static char g_model[PROP_VALUE_MAX] = "Pixel 6 Pro";
static char g_device[PROP_VALUE_MAX] = "raven";
static char g_product[PROP_VALUE_MAX] = "raven";
static char g_fingerprint[PROP_VALUE_MAX] = "google/raven/raven:13/TP1A.221005.002/8977058:user/release-keys";
static char g_hardware[PROP_VALUE_MAX] = "tensor";
static char g_board[PROP_VALUE_MAX] = "raven";
static char g_bootloader[PROP_VALUE_MAX] = "slider-1.2-8977058";
static char g_security_patch[PROP_VALUE_MAX] = "2022-10-05";
static char g_first_api_level[PROP_VALUE_MAX] = "33";
static char g_sku[PROP_VALUE_MAX] = "G1MNW";
static char g_abi[PROP_VALUE_MAX] = "arm64-v8a";
static char g_abilist[PROP_VALUE_MAX] = "arm64-v8a";
static char g_abilist32[PROP_VALUE_MAX] = "";
static char g_abilist64[PROP_VALUE_MAX] = "arm64-v8a";
static char g_bionic_arch[PROP_VALUE_MAX] = "arm64";
static char g_dalvik_isa_arm64[PROP_VALUE_MAX] = "arm64";
static char g_dalvik_isa_arm[PROP_VALUE_MAX] = "";

static char *read_text_file(const char *path){
  int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) return NULL;
  struct stat st; size_t cap=65536; if(!fstat(fd,&st) && st.st_size>0 && st.st_size<1024*1024) cap=(size_t)st.st_size;
  char *b=calloc(1,cap+1); if(!b){close(fd); return NULL;}
  ssize_t n=read(fd,b,cap); close(fd); if(n<0){free(b); return NULL;} b[n]=0; return b;
}
static void json_copy_string(const char *json, const char *key, char *dst, size_t dstsz){
  if(!json || !key || !dst || dstsz==0) return;
  char needle[128]; snprintf(needle,sizeof(needle),"\"%s\"",key);
  const char *p=strstr(json,needle); if(!p) return;
  p=strchr(p+strlen(needle),':'); if(!p) return; p++;
  while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r') p++;
  if(*p!='\"') return; p++;
  size_t n=0;
  while(*p && !(*p=='\"' && (p==json || *(p-1)!='\\')) && n+1<dstsz){
    if(*p=='\\' && p[1]){
      p++;
      if(*p=='n') dst[n++]='\n';
      else if(*p=='r') dst[n++]='\r';
      else dst[n++]=*p;
      p++;
    } else {
      dst[n++]=*p++;
    }
  }
  dst[n]=0;
}
static void load_profile_values(void){
  char *j=read_text_file(PROFILE_JSON); if(!j) return;
  json_copy_string(j,"brand",g_brand,sizeof(g_brand));
  json_copy_string(j,"manufacturer",g_manufacturer,sizeof(g_manufacturer));
  json_copy_string(j,"model",g_model,sizeof(g_model));
  json_copy_string(j,"device",g_device,sizeof(g_device));
  json_copy_string(j,"product",g_product,sizeof(g_product));
  json_copy_string(j,"fingerprint",g_fingerprint,sizeof(g_fingerprint));
  json_copy_string(j,"hardware",g_hardware,sizeof(g_hardware));
  json_copy_string(j,"board",g_board,sizeof(g_board));
  json_copy_string(j,"bootloader",g_bootloader,sizeof(g_bootloader));
  json_copy_string(j,"security_patch",g_security_patch,sizeof(g_security_patch));
  json_copy_string(j,"first_api_level",g_first_api_level,sizeof(g_first_api_level));
  json_copy_string(j,"sku",g_sku,sizeof(g_sku));
  json_copy_string(j,"abi",g_abi,sizeof(g_abi));
  json_copy_string(j,"abilist",g_abilist,sizeof(g_abilist));
  json_copy_string(j,"abilist32",g_abilist32,sizeof(g_abilist32));
  json_copy_string(j,"abilist64",g_abilist64,sizeof(g_abilist64));
  json_copy_string(j,"bionic_arch",g_bionic_arch,sizeof(g_bionic_arch));
  json_copy_string(j,"dalvik_isa_arm64",g_dalvik_isa_arm64,sizeof(g_dalvik_isa_arm64));
  json_copy_string(j,"dalvik_isa_arm",g_dalvik_isa_arm,sizeof(g_dalvik_isa_arm));
  free(j);
}
typedef struct { unsigned char *m; size_t len; uint32_t bytes_used; const char *path; int patched; } area_t;
static uint32_t u32(const unsigned char *p){ uint32_t v; memcpy(&v,p,4); return v; }
static void w32(unsigned char *p,uint32_t v){ memcpy(p,&v,4); }
static int printable_name(const unsigned char *p, uint32_t n){ if(n>96) return 0; for(uint32_t i=0;i<n;i++) if(!(isalnum(p[i])||p[i]=='_'||p[i]=='-' )) return 0; return 1; }
static unsigned char *node_ptr(area_t *a, uint32_t off){ if(off >= a->bytes_used || PROP_BASE + off + 20 > a->len) return NULL; return a->m + PROP_BASE + off; }
static unsigned char *prop_ptr(area_t *a, uint32_t off){ if(off >= a->bytes_used || PROP_BASE + off + 4 + PROP_VALUE_MAX > a->len) return NULL; return a->m + PROP_BASE + off; }
static int patch_long_value(area_t *a, const char *full, const char *value){
  /* Long props (value > 63 chars) live in a long-value pool after the trie:
     records are `<fullkey>\0 <0-3 pad> <nul-terminated value>` — the value is
     4-byte aligned after the key's NUL, so the pad length varies with key
     length. Using a fixed +4 skips 3 bytes into the value for keys whose
     key+NUL is already 4-aligned (e.g. ro.system.build.fingerprint), leaving
     the old value's head ("red" from redroid) prepended to the new one. */
  size_t kl = strlen(full), vl = strlen(value);
  size_t voff = (kl + 1 + 3) & ~(size_t)3; /* 4-byte aligned offset of value */
  size_t i;
  /* Scan up to the mapped length, not bytes_used: dedicated small areas (e.g.
     fingerprint_prop, whose only prop's long pool record straddles bytes_used)
     place the pool record past the trie accounting. Reads stay within a->len
     (the mmap) and NUL-separated zeros never match a key. */
  for (i = PROP_BASE; i + kl + voff < a->len; i++) {
    if (memcmp(a->m + i, full, kl) == 0 && a->m[i+kl] == 0) {
      char *v = (char *)(a->m + i + voff);
      size_t room = strnlen(v, a->len - (i + voff));
      if (room == 0 || memcmp(v, "Must use", 8) == 0) continue;
      if (strlen(v) == vl && memcmp(v, value, vl) == 0) {
        g_verified++;
        return 0;
      }
      if (vl <= room) {
        memset(v, 0, room);
        memcpy(v, value, vl);
        printf("%s:long:%s=%s\n", a->path, full, value);
        a->patched++;
        g_verified++;
        return 1;
      }
      /* Wrong record (catalog/context entry) — keep scanning for the real
         pool record. */
    }
  }
  return 0;
}

static int normalized_serial(const char *full, uint32_t *counter){
  if(!strncmp(full,"ro.",3)){ *counter=0; return 1; }
  /* Zygote starts its ADB-JDWP watcher while init.svc.adbd has generation 2.
     App children inherit that expected generation. Out-of-band area writes
     cannot wake/update the inherited watcher, so any other generation makes
     every app spin in futex(EAGAIN). Keep the inherited generation while
     exposing "stopped"; init remains the owner of all other mutable serials. */
  if(!strcmp(full,"init.svc.adbd")){ *counter=2; return 1; }
  return 0;
}

static int patch_propinfo(area_t *a, uint32_t prop_off, const char *full, const char *value){
  unsigned char *pi=prop_ptr(a,prop_off); if(!pi) return 0;
  size_t vl=strlen(value); if(vl>=PROP_VALUE_MAX) return 0;
  uint32_t old=u32(pi);
  /* Long props: marker value "Must use __system_property_read_callback() to
     read". Never write a normal short patch over those — a length byte of
     64+ sets bionic's kLongFlag (bit 30) and sends readers into the pool with
     a mismatched record (getprop/__system_property_get segfaults). Patch the
     pool record instead. */
  if (memcmp(pi+4, "Must use __system_property", 26) == 0)
    return patch_long_value(a, full, value);
  if (vl > 63) return 0;
  if (strlen((char *)pi + 4) == vl && memcmp(pi + 4, value, vl) == 0) {
    uint32_t counter;
    if (normalized_serial(full, &counter) &&
        (old & 0x00ffffffu) != counter) {
      w32(pi, ((uint32_t)vl << 24) | counter);
      printf("%s:%s serial-normalized\n", a->path, full);
      a->patched++;
      g_verified++;
      return 1;
    }
    g_verified++;
    return 0;
  }
  memset(pi+4,0,PROP_VALUE_MAX);
  memcpy(pi+4,value,vl);
  uint32_t next;
  /* Only immutable properties and init.svc.adbd have a stable synthetic
     generation. Other mutable properties retain bionic's even counter. */
  if (!normalized_serial(full, &next))
    next = (old + 2) & 0x00fffffeu;
  w32(pi, ((uint32_t)vl<<24) | next);
  printf("%s:%s=%s\n", a->path, full, value);
  a->patched++;
  g_verified++;
  return 1;
}
static const char *desired_value(const char *full){
  if(!strcmp(full,"ro.debuggable")) return "0";
  if(!strcmp(full,"ro.secure")) return "1";
  if(!strcmp(full,"ro.adb.secure")) return "1";
  if(!strcmp(full,"ro.boot.hardware")) return "gs101"; /* Tensor HAL aliases make ro.hardware=tensor safe during graphics init; once boot_completed, normalize the app-visible boot platform to gs101. */
  if(!strcmp(full,"ro.boot.bootreason")) return "reboot,normal";
  if(!strcmp(full,"ro.bootloader")) return g_bootloader;
  if(!strcmp(full,"ro.build.version.security_patch")) return g_security_patch;
  if(!strcmp(full,"ro.vendor.build.security_patch")) return g_security_patch;
  if(!strcmp(full,"ro.product.first_api_level")) return g_first_api_level;
  if(!strcmp(full,"ro.oem_unlock_supported")) return "1";
  if(!strcmp(full,"sys.oem_unlock_allowed")) return "0";
  if(!strcmp(full,"ro.boot.warranty_bit")) return "0";
  if(!strcmp(full,"ro.warranty_bit")) return "0";
  if(!strcmp(full,"ro.bootmode")) return "normal";
  if(!strcmp(full,"ro.boot.mode")) return "normal";
  if(!strcmp(full,"ro.boot.serialno")) return "";
  if(!strcmp(full,"ro.serialno")) return "";
  if(!strcmp(full,"ro.boot.baseband")) return "msm";
  if(!strcmp(full,"ro.boot.hardware.sku")) return g_sku;
  if(strstr(full,"cpu.abilist64")) return g_abilist64;
  if(strstr(full,"cpu.abilist32")) return g_abilist32;
  if(strstr(full,"cpu.abilist")) return g_abilist;
  if(!strcmp(full,"ro.product.cpu.abi")) return g_abi;
  if(!strcmp(full,"ro.bionic.arch")) return g_bionic_arch;
  if(!strcmp(full,"ro.dalvik.vm.isa.arm64")) return g_dalvik_isa_arm64;
  if(!strcmp(full,"ro.dalvik.vm.isa.arm")) return g_dalvik_isa_arm;
  if(!strcmp(full,"dalvik.vm.isa.x86.variant")) return "";
  if(!strcmp(full,"dalvik.vm.isa.x86_64.variant")) return "";
  if(!strcmp(full,"ro.boot.verifiedbootstate")) return "green";
  if(!strcmp(full,"init.svc.adbd")) return ""; /* empty value + inherited serial 2 keeps ART's ADB-JDWP waiter blocked while app/raw readers observe no active adbd */
  if(!strcmp(full,"sys.usb.config")) return "mtp"; /* app-visible USB functions without adb; host still uses TCP adb forward */
  if(!strcmp(full,"sys.usb.state")) return "mtp";
  if(!strcmp(full,"persist.sys.usb.config")) return "mtp";
  /* Remove runtime implementation properties from the application-visible area. */
  if(strstr(full,"ro.boot.redroid_") || strstr(full,"ro.kernel.redroid.")) return "";
  if(!strcmp(full,"ro.boot.use_redroid_c2")) return "";
  if(!strcmp(full,"init.svc.redroid_net")) return "stopped";
  if(!strcmp(full,"ro.boot.flash.locked")) return "1";
  if(!strcmp(full,"ro.boot.vbmeta.device_state")) return "locked";
  if(!strcmp(full,"ro.boot.veritymode")) return "enforcing";
  if(!strcmp(full,"ro.boottime.apexd")) return "";
  if(!strcmp(full,"ro.build.tags")) return "release-keys";
  if(!strcmp(full,"ro.build.type")) return "user";
  if(!strcmp(full,"ro.hardware")) return g_hardware; /* Tensor HAL aliases exist in the runtime image; patching after boot_completed is safe and removes the last multi-source identity split. */
  if(strstr(full,".build.tags") && !strncmp(full,"ro.",3)) return "release-keys";
  if(strstr(full,".build.type") && !strncmp(full,"ro.",3)) return "user";
  if(!g_patch_identity) return NULL;
  if(!strcmp(full,"ro.build.fingerprint")) return g_fingerprint;
  if(strstr(full,".brand") && !strncmp(full,"ro.product",10)) return g_brand;
  if(strstr(full,".manufacturer") && !strncmp(full,"ro.product",10)) return g_manufacturer;
  if(strstr(full,".model") && !strncmp(full,"ro.product",10)) return g_model;
  if(strstr(full,".device") && !strncmp(full,"ro.product",10)) return g_device;
  if(strstr(full,".name") && !strncmp(full,"ro.product",10)) return g_product;
  if(strstr(full,".build.fingerprint") && !strncmp(full,"ro.",3)) return g_fingerprint;
  return NULL;
}
static void traverse(area_t *a, uint32_t off, const char *prefix, int depth){
  if(depth>32) return;
  unsigned char *n=node_ptr(a,off); if(!n) return;
  uint32_t namelen=u32(n), prop=u32(n+4), left=u32(n+8), right=u32(n+12), child=u32(n+16);
  if(left) traverse(a,left,prefix,depth+1);
  if(namelen<96 && PROP_BASE+off+20+namelen<=a->len && printable_name(n+20,namelen)){
    char seg[128]; memcpy(seg,n+20,namelen); seg[namelen]=0;
    char full[512];
    if(prefix && prefix[0]) snprintf(full,sizeof(full),"%s.%s",prefix,seg); else snprintf(full,sizeof(full),"%s",seg);
    const char *want=desired_value(full);
    if(want && prop) patch_propinfo(a,prop,full,want);
    if(child) traverse(a,child,full,depth+1);
  }
  if(right) traverse(a,right,prefix,depth+1);
}
static int patch_area(const char *path){
  int fd=open(path,O_RDWR|O_CLOEXEC); if(fd<0) return 0;
  struct stat st; if(fstat(fd,&st)){close(fd); return 0;}
  unsigned char *m=mmap(NULL,st.st_size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); if(m==MAP_FAILED){close(fd); return 0;}
  area_t a={.m=m,.len=(size_t)st.st_size,.bytes_used=u32(m),.path=path,.patched=0};
  if(a.bytes_used>0 && a.bytes_used < st.st_size-PROP_BASE) traverse(&a,0,"",0);
  msync(m,st.st_size,MS_SYNC); munmap(m,st.st_size); close(fd);
  return a.patched;
}
int main(int argc, char **argv){
  load_profile_values();
  for(int i=1;i<argc;i++) if(!strcmp(argv[i],"--identity")) g_patch_identity=1;
  int total=0;
  const char *files[]={
    "/dev/__properties__/u:object_r:userdebug_or_eng_prop:s0",
    "/dev/__properties__/u:object_r:build_prop:s0",
    "/dev/__properties__/u:object_r:fingerprint_prop:s0",
    "/dev/__properties__/u:object_r:build_odm_prop:s0",
    "/dev/__properties__/u:object_r:build_vendor_prop:s0",
    "/dev/__properties__/u:object_r:vendor_security_patch_level_prop:s0",
    "/dev/__properties__/u:object_r:build_bootimage_prop:s0",
    "/dev/__properties__/u:object_r:bootloader_prop:s0",
    "/dev/__properties__/u:object_r:exported_default_prop:s0",
    "/dev/__properties__/u:object_r:bootloader_boot_reason_prop:s0",
    "/dev/__properties__/u:object_r:boottime_prop:s0",
    "/dev/__properties__/u:object_r:boottime_public_prop:s0",
    "/dev/__properties__/u:object_r:system_prop:s0",
    "/dev/__properties__/u:object_r:build_system_prop:s0",
    "/dev/__properties__/u:object_r:system_prop:s0",
    "/dev/__properties__/u:object_r:dalvik_config_prop:s0",
    "/dev/__properties__/u:object_r:dalvik_prop:s0",
    "/dev/__properties__/u:object_r:exported_dalvik_prop:s0",
    "/dev/__properties__/u:object_r:bionic_prop:s0",
    "/dev/__properties__/u:object_r:runtime_prop:s0",
    "/dev/__properties__/u:object_r:vendor_default_prop:s0",
    "/dev/__properties__/u:object_r:init_service_status_prop:s0",
    "/dev/__properties__/u:object_r:usb_prop:s0",
    "/dev/__properties__/u:object_r:usb_control_prop:s0",
    "/dev/__properties__/u:object_r:usb_config_prop:s0",
    "/dev/__properties__/u:object_r:adbd_prop:s0",
    "/dev/__properties__/u:object_r:adbd_config_prop:s0",
    NULL};
  for(int i=0;files[i];i++) total+=patch_area(files[i]);
  /* Do NOT stop adbd or reset service.adb.tcp.port here. The host-side
     backend (ensure_android_adb_port) owns the internal adbd port lifecycle:
     it moves adbd to a non-5555 port first, then hides the property. Resetting
     the port to -1 here bounced adbd back to 5555 and broke the host mapping. */
  printf("total=%d\n",total);
  return g_verified>0?0:1;
}
