#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SECURE_FILE "/data/system/users/0/settings_secure.xml"

static int is_hex16(const unsigned char *p){ for(int i=0;i<16;i++) if(!isxdigit(p[i])) return 0; return 1; }
static int valid_value(const char *v){ return v && strlen(v)==16 && is_hex16((const unsigned char*)v); }
static void lower16(char out[17], const char *v){ for(int i=0;i<16;i++) out[i]=(char)tolower((unsigned char)v[i]); out[16]=0; }

static char *read_file(const char *path, off_t *sz){
  int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) return NULL;
  struct stat st; if(fstat(fd,&st)){ close(fd); return NULL; }
  char *buf=(char*)malloc((size_t)st.st_size+1); if(!buf){ close(fd); return NULL; }
  ssize_t n=read(fd,buf,(size_t)st.st_size); close(fd); if(n<0){ free(buf); return NULL; }
  buf[n]=0; if(sz) *sz=n; return buf;
}
static int write_file_same_mode(const char *path, const char *buf, size_t n){
  int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600); if(fd<0) return -1;
  ssize_t w=write(fd,buf,n); fsync(fd); close(fd);
  chown(path,1000,1000); chmod(path,0600);
  return w==(ssize_t)n?0:-1;
}


static char *replace_between(char *src, const char *start, const char *end, const char *value, int *count){
  size_t sl=strlen(start), el=strlen(end), vl=strlen(value);
  size_t cap=strlen(src)+4096, outn=0; char *out=(char*)calloc(1,cap); if(!out) return NULL;
  char *p=src;
  while(*p){
    char *a=strstr(p,start);
    if(!a){ size_t rest=strlen(p); if(outn+rest+1>cap){cap=outn+rest+1; out=realloc(out,cap);} memcpy(out+outn,p,rest); outn+=rest; break; }
    char *b=strstr(a+sl,end);
    if(!b){ size_t rest=strlen(p); if(outn+rest+1>cap){cap=outn+rest+1; out=realloc(out,cap);} memcpy(out+outn,p,rest); outn+=rest; break; }
    size_t pre=(size_t)(a-p)+sl;
    if(outn+pre+vl+el+2>cap){cap=(outn+pre+vl+el+2)*2; out=realloc(out,cap);} 
    memcpy(out+outn,p,pre); outn+=pre;
    memcpy(out+outn,value,vl); outn+=vl;
    memcpy(out+outn,b,el); outn+=el;
    p=b+el; if(count) (*count)++;
  }
  out[outn]=0; return out;
}

static int patch_secure_xml(const char *value){
  char v[17]; lower16(v,value);
  off_t sz=0; char *orig=read_file(SECURE_FILE,&sz);
  if(!orig){ if(errno==ENOENT) return 0; perror("read settings_secure"); return 1; }
  int count=0;
  char *patched=replace_between(orig,"name=\"android_id\" value=\"","\"",v,&count);
  if(!patched){ free(orig); return 1; }
  if(count==0){
    free(patched);
    patched=replace_between(orig,"name='android_id' value='","'",v,&count);
  }
  if(count==0){
    const char *insert="  <setting id=\"0\" name=\"android_id\" value=\"";
    const char *tail="\" package=\"android\" />\n";
    size_t need=(size_t)sz+strlen(insert)+16+strlen(tail)+8;
    patched=(char*)calloc(1,need);
    char *end=strstr(orig,"</settings>");
    if(end){ size_t pre=(size_t)(end-orig); memcpy(patched,orig,pre); snprintf(patched+pre,need-pre,"%s%s%s%s",insert,v,tail,end); }
    else { snprintf(patched,need,"<settings version=\"1\">\n%s%s%s</settings>\n",insert,v,tail); }
    count=1;
  }
  int rc=write_file_same_mode(SECURE_FILE,patched,strlen(patched));
  printf("patched_secure=%d file=%s value=%s\n",count,SECURE_FILE,v);
  free(orig); free(patched);
  return rc==0?0:1;
}

static int patch_all(const char *value){
  if(!valid_value(value)){ fprintf(stderr,"value must be 16 hex chars\n"); return 2; }
  return patch_secure_xml(value);
}
int main(int argc,char**argv){ if(argc<2){fprintf(stderr,"usage: %s <16hex-android-id>\n",argv[0]); return 64;} return patch_all(argv[1]); }
