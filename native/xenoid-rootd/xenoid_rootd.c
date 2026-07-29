#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TOKEN_PATH "/data/local/tmp/.xenoid-rootd.token"
#define TOKEN_ENV "XENOID_ROOTD_TOKEN"
#define MAX_TOKEN 256
#define MAX_REQ 8192
#define MAX_CMD 4096

static char g_token[MAX_TOKEN];

static void esc(FILE* f, const char* s) {
  static const char hex[] = "0123456789abcdef";
  fputc('"', f);
  if (s) for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      fputc('\\', f);
      fputc(c, f);
    } else if (c == '\b') {
      fputs("\\b", f);
    } else if (c == '\f') {
      fputs("\\f", f);
    } else if (c == '\n') {
      fputs("\\n", f);
    } else if (c == '\r') {
      fputs("\\r", f);
    } else if (c == '\t') {
      fputs("\\t", f);
    } else if (c < 0x20) {
      fputs("\\u00", f);
      fputc(hex[c >> 4], f);
      fputc(hex[c & 0x0f], f);
    } else {
      fputc(c, f);
    }
  }
  fputc('"', f);
}

static char hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

static void urldecode(char* s) {
  char* d = s;
  for (; *s; s++) {
    if (*s == '%' && s[1] && s[2]) { *d++ = (hexval(s[1]) << 4) | hexval(s[2]); s += 2; }
    else if (*s == '+') *d++ = ' ';
    else *d++ = *s;
  }
  *d = 0;
}

static void trim_inplace(char* s) {
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
  char* p = s;
  while (*p == ' ' || *p == '\t') p++;
  if (p != s) memmove(s, p, strlen(p) + 1);
}

static int load_token(void) {
  const char* e = getenv(TOKEN_ENV);
  if (e && *e) {
    snprintf(g_token, sizeof(g_token), "%s", e);
    trim_inplace(g_token);
    return g_token[0] != 0;
  }
  FILE* f = fopen(TOKEN_PATH, "r");
  if (!f) return 0;
  if (!fgets(g_token, sizeof(g_token), f)) { fclose(f); g_token[0] = 0; return 0; }
  fclose(f);
  trim_inplace(g_token);
  return g_token[0] != 0;
}

static char* run_cmd(const char* cmd, int* code) {
  char tmp[MAX_CMD + 16];
  snprintf(tmp, sizeof(tmp), "%s 2>&1", cmd);
  FILE* p = popen(tmp, "r");
  if (!p) { *code = -1; return strdup("popen failed"); }
  size_t cap = 8192, n = 0;
  char* buf = calloc(1, cap);
  int c;
  while ((c = fgetc(p)) != EOF) {
    if (n + 2 >= cap) { cap *= 2; buf = realloc(buf, cap); }
    buf[n++] = (char)c;
  }
  int st = pclose(p);
  *code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  buf[n] = 0;
  return buf;
}

static void http_json(FILE* out, int status, const char* status_text, const char* body) {
  fprintf(out,
          "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
          status, status_text, strlen(body), body);
}

static int header_eq_ci(const char* line, const char* name, char* value, size_t vsz) {
  size_t nlen = strlen(name);
  for (size_t i = 0; i < nlen; i++) {
    char a = line[i], b = name[i];
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
    if (a != b) return 0;
  }
  if (line[nlen] != ':') return 0;
  const char* v = line + nlen + 1;
  while (*v == ' ' || *v == '\t') v++;
  snprintf(value, vsz, "%s", v);
  trim_inplace(value);
  return 1;
}

/* Extract a query param value from the request-target (path?query). */
static int query_param(const char* target, const char* key, char* out, size_t outsz) {
  const char* q = strchr(target, '?');
  if (!q) return 0;
  q++;
  size_t klen = strlen(key);
  while (*q) {
    const char* amp = strchr(q, '&');
    size_t seglen = amp ? (size_t)(amp - q) : strlen(q);
    if (seglen > klen && !strncmp(q, key, klen) && q[klen] == '=') {
      size_t vlen = seglen - klen - 1;
      if (vlen >= outsz) vlen = outsz - 1;
      memcpy(out, q + klen + 1, vlen);
      out[vlen] = 0;
      urldecode(out);
      return 1;
    }
    if (!amp) break;
    q = amp + 1;
  }
  return 0;
}

static int authorized(const char* req) {
  if (!g_token[0]) return 0;
  char hdr[MAX_TOKEN] = {0};
  const char* p = strstr(req, "\r\n");
  if (p) {
    p += 2;
    while (*p && !(p[0] == '\r' && p[1] == '\n')) {
      const char* eol = strstr(p, "\r\n");
      if (!eol) break;
      char line[512];
      size_t n = (size_t)(eol - p);
      if (n >= sizeof(line)) n = sizeof(line) - 1;
      memcpy(line, p, n);
      line[n] = 0;
      if (header_eq_ci(line, "x-xenoid-token", hdr, sizeof(hdr))) break;
      p = eol + 2;
    }
  }
  return hdr[0] && !strcmp(hdr, g_token);
}

static void handle_client(int c) {
  char req[MAX_REQ];
  memset(req, 0, sizeof(req));
  ssize_t n = read(c, req, sizeof(req) - 1);
  FILE* out = fdopen(c, "w");
  if (!out) { close(c); return; }
  if (n <= 0) { http_json(out, 400, "Bad Request", "{\"ok\":false,\"error\":\"bad request\"}\n"); fclose(out); return; }

  char method[16] = {0}, target[2048] = {0};
  if (sscanf(req, "%15s %2047s", method, target) != 2) {
    http_json(out, 400, "Bad Request", "{\"ok\":false,\"error\":\"bad request\"}\n");
    fclose(out);
    return;
  }

  /* Mutating route: /exec (with or without query). Health stays public. */
  const char* path = target;
  int is_exec = !strncmp(path, "/exec", 5) && (path[5] == 0 || path[5] == '?' || path[5] == '#');
  if (!is_exec) {
    http_json(out, 200, "OK", "{\"ok\":true,\"service\":\"xenoid-rootd\"}\n");
    fclose(out);
    return;
  }

  if (!authorized(req)) {
    http_json(out, 401, "Unauthorized", "{\"ok\":false,\"error\":\"unauthorized\"}\n");
    fclose(out);
    return;
  }

  char cmd[MAX_CMD] = {0};
  if (!query_param(target, "cmd", cmd, sizeof(cmd)) || !cmd[0]) {
    http_json(out, 400, "Bad Request", "{\"ok\":false,\"error\":\"missing cmd\"}\n");
    fclose(out);
    return;
  }

  int rc = 0;
  char* res = run_cmd(cmd, &rc);
  char prefix[128];
  snprintf(prefix, sizeof(prefix), "{\"ok\":%s,\"exit\":%d,\"stdout\":", rc == 0 ? "true" : "false", rc);
  fprintf(out, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s", prefix);
  esc(out, res);
  fprintf(out, "}\n");
  free(res);
  fclose(out);
}

int main(int argc, char** argv) {
  int port = 18767; /* matches RootHelper.java / xenoid-up.sh */
  if (argc > 1) port = atoi(argv[1]);
  load_token();

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("socket"); return 1; }
  /* FD_CLOEXEC: popen children (e.g. frida-server via /exec) must not inherit the listen socket. */
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  /* Loopback only — rootd is reached in-container / via adb; do not expose on 0.0.0.0. */
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons((uint16_t)port);
  if (bind(fd, (struct sockaddr*)&a, sizeof(a)) || listen(fd, 16)) {
    perror("bind/listen");
    return 1;
  }

  for (;;) {
    int c = accept(fd, NULL, NULL);
    if (c < 0) continue;
    fcntl(c, F_SETFD, FD_CLOEXEC);
    handle_client(c);
  }
}
