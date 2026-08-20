#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/prctl.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef POLLRDHUP
#define POLLRDHUP 0
#endif

#define DEFAULT_PORT 18767
#define DEFAULT_RUN_DIR "/data/local/tmp/xenoid-rootd-run"
#define PROCESS_RECORD "process.json"
#define TOKEN_LENGTH 32
#define REQUEST_ID_LENGTH 32
#define MAX_HEADER_BYTES 8192
#define MAX_COMMAND_BYTES 4096
#define MAX_OUTPUT_BYTES (64 * 1024)
#define MAX_HANDLERS 8
#define HEADER_TIMEOUT_MS 5000
#define MIN_COMMAND_TIMEOUT_MS 100
#define MAX_COMMAND_TIMEOUT_MS 230000
#define TERMINATE_GRACE_MS 500
#define IO_POLL_MS 100

static unsigned char g_token[TOKEN_LENGTH];
static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_listen_fd = -1;
static pthread_mutex_t g_handler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_handler_cond = PTHREAD_COND_INITIALIZER;
static int g_handler_count = 0;
static char g_record_path[PATH_MAX];
static char g_record_bytes[256];

struct client_context {
  int fd;
};

struct exec_result {
  unsigned char output[MAX_OUTPUT_BYTES];
  size_t output_length;
  int exit_code;
  const char *error_code;
  int client_connected;
};

static void secure_zero(void *value, size_t length) {
  volatile unsigned char *bytes = (volatile unsigned char *)value;
  while (length-- > 0) *bytes++ = 0;
}

static int64_t monotonic_ms(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int remaining_ms(int64_t deadline_ms, int maximum) {
  int64_t remaining = deadline_ms - monotonic_ms();
  if (remaining <= 0) return 0;
  if (remaining > maximum) return maximum;
  return (int)remaining;
}

static int set_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  return flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0 ? -1 : 0;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

static int is_lower_hex(const char *value, size_t length) {
  size_t index;
  for (index = 0; index < length; index++) {
    char c = value[index];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return value[length] == '\0';
}

static int constant_time_token_equal(const char *candidate) {
  unsigned int difference = 0;
  size_t index;
  size_t length = strnlen(candidate, TOKEN_LENGTH + 1);
  difference |= (unsigned int)(length ^ TOKEN_LENGTH);
  for (index = 0; index < TOKEN_LENGTH; index++) {
    unsigned char byte = index < length ? (unsigned char)candidate[index] : 0;
    difference |= (unsigned int)(byte ^ g_token[index]);
  }
  return difference == 0;
}

static int read_token_from_stdin(void) {
  unsigned char input[TOKEN_LENGTH + 2];
  size_t offset = 0;
  int64_t deadline = monotonic_ms() + HEADER_TIMEOUT_MS;
  memset(input, 0, sizeof(input));
  while (offset < TOKEN_LENGTH + 1) {
    struct pollfd descriptor;
    int ready;
    descriptor.fd = STDIN_FILENO;
    descriptor.events = POLLIN | POLLHUP;
    descriptor.revents = 0;
    ready = poll(&descriptor, 1, remaining_ms(deadline, HEADER_TIMEOUT_MS));
    if (ready <= 0) {
      secure_zero(input, sizeof(input));
      return 0;
    }
    if (descriptor.revents & (POLLERR | POLLNVAL)) {
      secure_zero(input, sizeof(input));
      return 0;
    }
    {
      ssize_t count = read(STDIN_FILENO, input + offset, TOKEN_LENGTH + 1 - offset);
      if (count <= 0) {
        secure_zero(input, sizeof(input));
        return 0;
      }
      offset += (size_t)count;
    }
  }
  if (input[TOKEN_LENGTH] != '\n') {
    secure_zero(input, sizeof(input));
    return 0;
  }
  input[TOKEN_LENGTH] = '\0';
  if (!is_lower_hex((const char *)input, TOKEN_LENGTH)) {
    secure_zero(input, sizeof(input));
    return 0;
  }
  for (;;) {
    unsigned char extra = 0;
    struct pollfd descriptor;
    int ready;
    ssize_t count;
    descriptor.fd = STDIN_FILENO;
    descriptor.events = POLLIN | POLLHUP;
    descriptor.revents = 0;
    ready = poll(&descriptor, 1, remaining_ms(deadline, HEADER_TIMEOUT_MS));
    if (ready <= 0 || (descriptor.revents & (POLLERR | POLLNVAL))) {
      secure_zero(&extra, sizeof(extra));
      secure_zero(input, sizeof(input));
      return 0;
    }
    count = read(STDIN_FILENO, &extra, 1);
    if (count == 0) break;
    if (count > 0) {
      secure_zero(&extra, sizeof(extra));
      secure_zero(input, sizeof(input));
      return 0;
    }
    if (errno == EINTR) continue;
    secure_zero(&extra, sizeof(extra));
    secure_zero(input, sizeof(input));
    return 0;
  }
  memcpy(g_token, input, TOKEN_LENGTH);
  secure_zero(input, sizeof(input));
  close(STDIN_FILENO);
  return 1;
}

static void shutdown_handler(int signal_number) {
  int fd;
  (void)signal_number;
  g_shutdown = 1;
  fd = (int)g_listen_fd;
  g_listen_fd = -1;
  if (fd >= 0) close(fd);
}

static int send_all(int fd, const char *data, size_t length) {
  size_t offset = 0;
  while (offset < length && !g_shutdown) {
    ssize_t count = send(fd, data + offset, length - offset, 0);
    if (count > 0) {
      offset += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return 0;
  }
  return offset == length;
}

static void send_json(int fd, int status, const char *status_text, const char *body) {
  char header[256];
  int length = snprintf(header, sizeof(header),
      "HTTP/1.1 %d %s\r\n"
      "Content-Type: application/json; charset=utf-8\r\n"
      "Content-Length: %zu\r\n"
      "Connection: close\r\n\r\n",
      status, status_text, strlen(body));
  if (length <= 0 || (size_t)length >= sizeof(header)) return;
  if (send_all(fd, header, (size_t)length)) send_all(fd, body, strlen(body));
}

static void send_error(int fd, int status, const char *status_text, const char *error_code) {
  char body[256];
  int length = snprintf(body, sizeof(body),
      "{\"ok\":false,\"schema\":\"dev.xenoid.rootd-error/v1\",\"errorCode\":\"%s\"}\n",
      error_code);
  if (length > 0 && (size_t)length < sizeof(body)) send_json(fd, status, status_text, body);
}

static char *trim_ascii(char *value) {
  char *end;
  while (*value == ' ' || *value == '\t') value++;
  end = value + strlen(value);
  while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
  return value;
}

static int parse_decimal(const char *value, long *result) {
  unsigned long parsed = 0;
  const unsigned char *cursor = (const unsigned char *)value;
  if (!*cursor) return 0;
  while (*cursor) {
    if (*cursor < '0' || *cursor > '9') return 0;
    if (parsed > 100000000UL) return 0;
    parsed = parsed * 10 + (unsigned long)(*cursor - '0');
    cursor++;
  }
  if (parsed > 1000000000UL) return 0;
  *result = (long)parsed;
  return 1;
}

static int valid_utf8(const unsigned char *data, size_t length) {
  size_t index = 0;
  while (index < length) {
    unsigned char first = data[index++];
    unsigned int codepoint;
    size_t continuation;
    if (first < 0x80) continue;
    if ((first & 0xe0) == 0xc0) {
      codepoint = first & 0x1f;
      continuation = 1;
      if (codepoint < 2) return 0;
    } else if ((first & 0xf0) == 0xe0) {
      codepoint = first & 0x0f;
      continuation = 2;
    } else if ((first & 0xf8) == 0xf0) {
      codepoint = first & 0x07;
      continuation = 3;
    } else {
      return 0;
    }
    if (index + continuation > length) return 0;
    while (continuation-- > 0) {
      unsigned char next = data[index++];
      if ((next & 0xc0) != 0x80) return 0;
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if (codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0;
    if (codepoint < 0x80 || (codepoint < 0x800 && first >= 0xe0)
        || (codepoint < 0x10000 && first >= 0xf0)) return 0;
  }
  return 1;
}

static int wait_for_request_data(int fd, int64_t deadline) {
  struct pollfd descriptor;
  int ready;
  if (g_shutdown) return -1;
  descriptor.fd = fd;
  descriptor.events = POLLIN | POLLRDHUP;
  descriptor.revents = 0;
  ready = poll(&descriptor, 1, remaining_ms(deadline, IO_POLL_MS));
  if (g_shutdown) return -1;
  if (ready <= 0) return ready;
  if (descriptor.revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) return -1;
  return (descriptor.revents & POLLIN) ? 1 : 0;
}

static ssize_t find_header_end(const unsigned char *buffer, size_t length) {
  size_t index;
  if (length < 4) return -1;
  for (index = 0; index + 3 < length; index++) {
    if (buffer[index] == '\r' && buffer[index + 1] == '\n'
        && buffer[index + 2] == '\r' && buffer[index + 3] == '\n') {
      return (ssize_t)(index + 4);
    }
  }
  return -1;
}

static int read_http_request(int fd, char *request_id, long *timeout_ms,
    unsigned char *command, size_t *command_length, int *authorized) {
  unsigned char buffer[MAX_HEADER_BYTES + MAX_COMMAND_BYTES + 1];
  size_t used = 0;
  ssize_t header_end = -1;
  int64_t deadline = monotonic_ms() + HEADER_TIMEOUT_MS;
  long content_length = -1;
  char token[TOKEN_LENGTH + 1];
  int token_count = 0, request_id_count = 0, timeout_count = 0;
  int content_type_count = 0, content_length_count = 0;
  int unsupported_framing = 0;
  int token_format_valid = 1;
  char *line;
  char *next;
  memset(buffer, 0, sizeof(buffer));
  memset(token, 0, sizeof(token));
  *authorized = 0;
#define FINISH_REQUEST(code) do { \
    int request_status__ = (code); \
    secure_zero(token, sizeof(token)); \
    secure_zero(buffer, sizeof(buffer)); \
    return request_status__; \
  } while (0)

  while (header_end < 0) {
    int ready;
    ssize_t count;
    if (used >= MAX_HEADER_BYTES) FINISH_REQUEST(400);
    ready = wait_for_request_data(fd, deadline);
    if (ready < 0) FINISH_REQUEST(-1);
    if (ready == 0) {
      if (monotonic_ms() >= deadline) FINISH_REQUEST(408);
      continue;
    }
    count = recv(fd, buffer + used, sizeof(buffer) - used, 0);
    if (count <= 0) FINISH_REQUEST(-1);
    used += (size_t)count;
    header_end = find_header_end(buffer, used);
    if (header_end < 0 && used >= MAX_HEADER_BYTES) FINISH_REQUEST(400);
    if (header_end > MAX_HEADER_BYTES) FINISH_REQUEST(400);
  }

  buffer[header_end - 2] = '\0';
  line = (char *)buffer;
  next = strstr(line, "\r\n");
  if (!next) FINISH_REQUEST(400);
  *next = '\0';
  {
    char method[16], target[128], version[16], extra;
    if (sscanf(line, "%15s %127s %15s %c", method, target, version, &extra) != 3) {
      FINISH_REQUEST(400);
    }
    if (strcmp(version, "HTTP/1.1") != 0) FINISH_REQUEST(400);
    if (strcmp(target, "/health") == 0) {
      if (strcmp(method, "GET") != 0) FINISH_REQUEST(405);
      FINISH_REQUEST(204);
    }
    if (strcmp(target, "/exec") != 0) FINISH_REQUEST(404);
    if (strcmp(method, "POST") != 0) FINISH_REQUEST(405);
  }

  line = next + 2;
  while (*line) {
    char *colon;
    char *value;
    next = strstr(line, "\r\n");
    if (next) *next = '\0';
    if (*line == ' ' || *line == '\t') FINISH_REQUEST(400);
    colon = strchr(line, ':');
    if (!colon || colon == line) FINISH_REQUEST(400);
    *colon = '\0';
    value = trim_ascii(colon + 1);
    if (strcasecmp(line, "X-Xenoid-Token") == 0) {
      token_count++;
      if (token_count == 1) {
        if (strlen(value) == TOKEN_LENGTH) memcpy(token, value, TOKEN_LENGTH + 1);
        else token_format_valid = 0;
      }
    } else if (strcasecmp(line, "X-Xenoid-Request-Id") == 0) {
      request_id_count++;
      if (strlen(value) > REQUEST_ID_LENGTH) FINISH_REQUEST(400);
      memcpy(request_id, value, strlen(value) + 1);
    } else if (strcasecmp(line, "X-Xenoid-Timeout-Ms") == 0) {
      timeout_count++;
      if (!parse_decimal(value, timeout_ms)) FINISH_REQUEST(400);
    } else if (strcasecmp(line, "Content-Type") == 0) {
      content_type_count++;
      if (strcasecmp(value, "text/plain; charset=utf-8") != 0) FINISH_REQUEST(415);
    } else if (strcasecmp(line, "Content-Length") == 0) {
      content_length_count++;
      if (!parse_decimal(value, &content_length)) FINISH_REQUEST(400);
    } else if (strcasecmp(line, "Transfer-Encoding") == 0
        || strcasecmp(line, "Content-Encoding") == 0
        || strcasecmp(line, "Expect") == 0
        || strcasecmp(line, "Trailer") == 0
        || strcasecmp(line, "TE") == 0) {
      unsupported_framing = 1;
    }
    if (!next) break;
    line = next + 2;
  }

  if (unsupported_framing || request_id_count != 1 || timeout_count != 1
      || content_type_count != 1 || content_length_count != 1) FINISH_REQUEST(400);
  if (!is_lower_hex(request_id, REQUEST_ID_LENGTH)) FINISH_REQUEST(400);
  if (content_length <= 0 || content_length > MAX_COMMAND_BYTES) FINISH_REQUEST(413);
  if (*timeout_ms < MIN_COMMAND_TIMEOUT_MS) *timeout_ms = MIN_COMMAND_TIMEOUT_MS;
  if (*timeout_ms > MAX_COMMAND_TIMEOUT_MS) *timeout_ms = MAX_COMMAND_TIMEOUT_MS;

  {
    size_t body_offset = (size_t)header_end;
    size_t body_used = used - body_offset;
    if (body_used > (size_t)content_length) FINISH_REQUEST(400);
    if (body_used > 0) memcpy(command, buffer + body_offset, body_used);
    while (body_used < (size_t)content_length) {
      int ready = wait_for_request_data(fd, deadline);
      ssize_t count;
      if (ready < 0) FINISH_REQUEST(-1);
      if (ready == 0) {
        if (monotonic_ms() >= deadline) FINISH_REQUEST(408);
        continue;
      }
      count = recv(fd, command + body_used, (size_t)content_length - body_used, 0);
      if (count <= 0) FINISH_REQUEST(-1);
      body_used += (size_t)count;
    }
    command[body_used] = '\0';
    *command_length = body_used;
  }
  {
    int token_matches = constant_time_token_equal(token);
    secure_zero(token, sizeof(token));
    if (token_count == 0 || !token_format_valid || !token_matches) FINISH_REQUEST(401);
  }
  *authorized = 1;
  if (token_count != 1) FINISH_REQUEST(400);
  if (memchr(command, '\0', *command_length) != NULL
      || !valid_utf8(command, *command_length)) FINISH_REQUEST(400);
  FINISH_REQUEST(200);
#undef FINISH_REQUEST
}

static int client_disconnected(int fd, short revents) {
  unsigned char byte;
  ssize_t count;
  if (revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) return 1;
  if (!(revents & POLLIN)) return 0;
  count = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
  return count == 0 || count > 0 || (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
}

static int reap_child(pid_t child, int *status) {
  pid_t result;
  do {
    result = waitpid(child, status, WNOHANG);
  } while (result < 0 && errno == EINTR);
  return result == child;
}

static void terminate_process_group(pid_t child, int *status, int *reaped) {
  int64_t deadline;
  if (child <= 0) return;
  kill(-child, SIGTERM);
  deadline = monotonic_ms() + TERMINATE_GRACE_MS;
  while (monotonic_ms() < deadline) {
    struct timespec pause_time = {0, 20 * 1000 * 1000};
    if (!*reaped) *reaped = reap_child(child, status);
    if (kill(-child, 0) < 0 && errno == ESRCH) break;
    nanosleep(&pause_time, NULL);
  }
  kill(-child, SIGKILL);
  while (!*reaped) {
    pid_t result = waitpid(child, status, 0);
    if (result == child || (result < 0 && errno == ECHILD)) {
      *reaped = 1;
      break;
    }
    if (result < 0 && errno != EINTR) break;
  }
}

static void execute_command(int client_fd, const unsigned char *command,
    long timeout_ms, struct exec_result *result) {
  int output_pipe[2] = {-1, -1};
  pid_t child;
  int status = 0;
  int reaped = 0;
  int pipe_eof = 0;
  int64_t deadline = monotonic_ms() + timeout_ms;
  memset(result, 0, sizeof(*result));
  result->exit_code = -1;
  result->client_connected = 1;
  if (pipe(output_pipe) != 0) {
    result->error_code = "rootd_exec_failed";
    return;
  }
  set_cloexec(output_pipe[0]);
  set_cloexec(output_pipe[1]);
  child = fork();
  if (child < 0) {
    close(output_pipe[0]);
    close(output_pipe[1]);
    result->error_code = "rootd_exec_failed";
    return;
  }
  if (child == 0) {
    const char *shell = access("/system/bin/sh", X_OK) == 0 ? "/system/bin/sh" : "/bin/sh";
    setpgid(0, 0);
    dup2(output_pipe[1], STDOUT_FILENO);
    dup2(output_pipe[1], STDERR_FILENO);
    close(output_pipe[0]);
    close(output_pipe[1]);
    secure_zero(g_token, sizeof(g_token));
    execl(shell, shell, "-c", (const char *)command, (char *)NULL);
    _exit(127);
  }
  close(output_pipe[1]);
  output_pipe[1] = -1;
  setpgid(child, child);
  set_nonblocking(output_pipe[0]);

  while (!(reaped && pipe_eof)) {
    struct pollfd descriptors[2];
    int ready;
    descriptors[0].fd = output_pipe[0];
    descriptors[0].events = POLLIN | POLLHUP;
    descriptors[0].revents = 0;
    descriptors[1].fd = client_fd;
    descriptors[1].events = POLLIN | POLLRDHUP;
    descriptors[1].revents = 0;
    ready = poll(descriptors, 2, remaining_ms(deadline, IO_POLL_MS));
    if (ready < 0 && errno != EINTR) {
      result->error_code = "rootd_exec_failed";
      break;
    }
    if (g_shutdown) {
      result->error_code = "rootd_shutdown";
      break;
    }
    if (client_disconnected(client_fd, descriptors[1].revents)) {
      result->client_connected = 0;
      result->error_code = "rootd_cancelled";
      break;
    }
    if (descriptors[0].revents & (POLLIN | POLLHUP)) {
      for (;;) {
        unsigned char chunk[4096];
        ssize_t count = read(output_pipe[0], chunk, sizeof(chunk));
        if (count > 0) {
          size_t room = MAX_OUTPUT_BYTES - result->output_length;
          size_t copy = (size_t)count < room ? (size_t)count : room;
          if (copy > 0) {
            memcpy(result->output + result->output_length, chunk, copy);
            result->output_length += copy;
          }
          if ((size_t)count > copy) {
            result->error_code = "rootd_output_limit";
            break;
          }
          continue;
        }
        if (count == 0) pipe_eof = 1;
        if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          result->error_code = "rootd_exec_failed";
        }
        break;
      }
      if (result->error_code) break;
    }
    if (!reaped) reaped = reap_child(child, &status);
    if (monotonic_ms() >= deadline) {
      result->error_code = "rootd_command_timeout";
      break;
    }
    if (reaped && !pipe_eof && ready == 0) {
      unsigned char byte;
      ssize_t count = read(output_pipe[0], &byte, 1);
      if (count == 0) pipe_eof = 1;
      else if (count > 0) {
        if (result->output_length < MAX_OUTPUT_BYTES) {
          result->output[result->output_length++] = byte;
        } else {
          result->error_code = "rootd_output_limit";
          break;
        }
      }
    }
  }

  if (result->error_code) terminate_process_group(child, &status, &reaped);
  if (!reaped) reaped = reap_child(child, &status);
  if (!reaped) terminate_process_group(child, &status, &reaped);
  close(output_pipe[0]);
  if (!result->error_code) {
    if (WIFEXITED(status)) result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result->exit_code = 128 + WTERMSIG(status);
    if (result->exit_code != 0) result->error_code = "rootd_command_failed";
  }
}

static size_t escaped_json_length(
    const unsigned char *data, size_t length, int unicode_valid) {
  size_t result = 0;
  size_t index;
  for (index = 0; index < length; index++) {
    unsigned char value = data[index];
    if (value == '"' || value == '\\' || value == '\b' || value == '\f'
        || value == '\n' || value == '\r' || value == '\t') result += 2;
    else if (value < 0x20 || (value >= 0x80 && !unicode_valid)) result += 6;
    else result++;
  }
  return result;
}

static void append_escaped_json(char **cursor, const unsigned char *data,
    size_t length, int unicode_valid) {
  static const char hex[] = "0123456789abcdef";
  size_t index;
  for (index = 0; index < length; index++) {
    unsigned char value = data[index];
    switch (value) {
      case '"': *(*cursor)++ = '\\'; *(*cursor)++ = '"'; break;
      case '\\': *(*cursor)++ = '\\'; *(*cursor)++ = '\\'; break;
      case '\b': *(*cursor)++ = '\\'; *(*cursor)++ = 'b'; break;
      case '\f': *(*cursor)++ = '\\'; *(*cursor)++ = 'f'; break;
      case '\n': *(*cursor)++ = '\\'; *(*cursor)++ = 'n'; break;
      case '\r': *(*cursor)++ = '\\'; *(*cursor)++ = 'r'; break;
      case '\t': *(*cursor)++ = '\\'; *(*cursor)++ = 't'; break;
      default:
        if (value < 0x20 || (value >= 0x80 && !unicode_valid)) {
          *(*cursor)++ = '\\'; *(*cursor)++ = 'u'; *(*cursor)++ = '0'; *(*cursor)++ = '0';
          *(*cursor)++ = hex[value >> 4]; *(*cursor)++ = hex[value & 0x0f];
        } else {
          *(*cursor)++ = (char)value;
        }
    }
  }
}

static void send_exec_result(int fd, const char *request_id, const struct exec_result *result) {
  int unicode_valid = valid_utf8(result->output, result->output_length);
  size_t escaped = escaped_json_length(
      result->output, result->output_length, unicode_valid);
  size_t capacity = escaped + 512;
  char *body = (char *)malloc(capacity);
  char *cursor;
  int prefix;
  int suffix;
  if (!body) {
    send_error(fd, 500, "Internal Server Error", "rootd_response_failed");
    return;
  }
  prefix = snprintf(body, capacity,
      "{\"ok\":%s,\"schema\":\"dev.xenoid.rootd-exec/v1\","
      "\"requestId\":\"%s\",\"exitCode\":%d,\"stdout\":\"",
      result->error_code == NULL ? "true" : "false", request_id, result->exit_code);
  if (prefix <= 0 || (size_t)prefix >= capacity) {
    free(body);
    return;
  }
  cursor = body + prefix;
  append_escaped_json(
      &cursor, result->output, result->output_length, unicode_valid);
  if (result->error_code) {
    suffix = snprintf(cursor, capacity - (size_t)(cursor - body),
        "\",\"errorCode\":\"%s\"}\n", result->error_code);
  } else {
    suffix = snprintf(cursor, capacity - (size_t)(cursor - body), "\"}\n");
  }
  if (suffix > 0 && (size_t)suffix < capacity - (size_t)(cursor - body)) {
    send_json(fd, 200, "OK", body);
  }
  secure_zero(body, capacity);
  free(body);
}

static void handle_client(int fd) {
  char request_id[REQUEST_ID_LENGTH + 1];
  unsigned char command[MAX_COMMAND_BYTES + 1];
  size_t command_length = 0;
  long timeout_ms = 0;
  int authorized = 0;
  int status;
  memset(request_id, 0, sizeof(request_id));
  memset(command, 0, sizeof(command));
  status = read_http_request(fd, request_id, &timeout_ms, command, &command_length, &authorized);
  if (status == 204) {
    secure_zero(command, sizeof(command));
    send_json(fd, 200, "OK",
        "{\"ok\":true,\"schema\":\"dev.xenoid.rootd/v1\",\"service\":\"xenoid-rootd\"}\n");
    return;
  }
  if (status != 200) {
    secure_zero(command, sizeof(command));
    if (status < 0) return;
    if (status == 401) send_error(fd, 401, "Unauthorized", "rootd_unauthorized");
    else if (status == 404) send_error(fd, 404, "Not Found", "rootd_not_found");
    else if (status == 405) send_error(fd, 405, "Method Not Allowed", "rootd_method_not_allowed");
    else if (status == 408) send_error(fd, 408, "Request Timeout", "rootd_header_timeout");
    else if (status == 413) send_error(fd, 413, "Content Too Large", "rootd_command_too_large");
    else if (status == 415) send_error(fd, 415, "Unsupported Media Type", "rootd_content_type_invalid");
    else send_error(fd, 400, "Bad Request", "rootd_bad_request");
    return;
  }
  if (authorized) {
    struct exec_result result;
    execute_command(fd, command, timeout_ms, &result);
    secure_zero(command, sizeof(command));
    if (result.client_connected) send_exec_result(fd, request_id, &result);
    secure_zero(&result, sizeof(result));
  }
}


static void *client_thread(void *opaque) {
  struct client_context *context = (struct client_context *)opaque;
  int fd = context->fd;
  free(context);
  handle_client(fd);
  shutdown(fd, SHUT_RDWR);
  close(fd);
  pthread_mutex_lock(&g_handler_lock);
  g_handler_count--;
  pthread_cond_broadcast(&g_handler_cond);
  pthread_mutex_unlock(&g_handler_lock);
  return NULL;
}

static int acquire_handler_slot(void) {
  int acquired = 0;
  pthread_mutex_lock(&g_handler_lock);
  if (g_handler_count < MAX_HANDLERS) {
    g_handler_count++;
    acquired = 1;
  }
  pthread_mutex_unlock(&g_handler_lock);
  return acquired;
}

static void release_handler_slot(void) {
  pthread_mutex_lock(&g_handler_lock);
  g_handler_count--;
  pthread_cond_broadcast(&g_handler_cond);
  pthread_mutex_unlock(&g_handler_lock);
}

static int parse_port(const char *value, int *port) {
  long parsed;
  if (!parse_decimal(value, &parsed) || parsed <= 0 || parsed > 65535) return 0;
  *port = (int)parsed;
  return 1;
}

static int create_listener(int port) {
  int fd;
  int one = 1;
  struct sockaddr_in address;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  if (set_cloexec(fd) != 0) {
    close(fd);
    return -1;
  }
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons((uint16_t)port);
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0
      || listen(fd, MAX_HANDLERS) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static unsigned long long process_start_time(void) {
#if defined(__linux__) || defined(__ANDROID__)
  char buffer[1024];
  char *after_name;
  char *save = NULL;
  char *field;
  int number = 3;
  int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
  ssize_t length;
  if (fd < 0) return 0;
  length = read(fd, buffer, sizeof(buffer) - 1);
  close(fd);
  if (length <= 0) return 0;
  buffer[length] = '\0';
  after_name = strrchr(buffer, ')');
  if (!after_name || after_name[1] != ' ') return 0;
  field = strtok_r(after_name + 2, " ", &save);
  while (field && number < 22) {
    field = strtok_r(NULL, " ", &save);
    number++;
  }
  if (!field || number != 22) return 0;
  return strtoull(field, NULL, 10);
#else
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
  return (unsigned long long)value.tv_sec * 1000000000ULL + (unsigned long long)value.tv_nsec;
#endif
}

static int prepare_runtime_directory(const char *path, int *directory_fd) {
  struct stat metadata;
  if (mkdir(path, 0700) != 0 && errno != EEXIST) return 0;
  if (lstat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode)
      || S_ISLNK(metadata.st_mode) || metadata.st_uid != geteuid()) return 0;
  if ((metadata.st_mode & 0777) != 0700 && chmod(path, 0700) != 0) return 0;
  *directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  return *directory_fd >= 0;
}

static int write_process_record(const char *run_directory, int port) {
  int directory_fd = -1;
  int record_fd = -1;
  char temporary[64];
  struct stat metadata;
  unsigned long long start_time = process_start_time();
  int length;
  ssize_t written;
  (void)port;
  if (start_time == 0 || !prepare_runtime_directory(run_directory, &directory_fd)) return 0;
  length = snprintf(g_record_bytes, sizeof(g_record_bytes),
      "{\"schema\":\"dev.xenoid.rootd-process/v1\",\"pid\":%ld,\"startTime\":%llu}\n",
      (long)getpid(), start_time);
  if (length <= 0 || (size_t)length >= sizeof(g_record_bytes)) goto failed;
  if (snprintf(temporary, sizeof(temporary), ".process.%ld.tmp", (long)getpid()) <= 0) goto failed;
  unlinkat(directory_fd, temporary, 0);
  record_fd = openat(directory_fd, temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (record_fd < 0) goto failed;
  if (fstat(record_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)
      || metadata.st_uid != geteuid() || metadata.st_nlink != 1
      || (metadata.st_mode & 0777) != 0600) goto failed;
  written = write(record_fd, g_record_bytes, (size_t)length);
  if (written != length || fsync(record_fd) != 0) goto failed;
  if (close(record_fd) != 0) {
    record_fd = -1;
    goto failed;
  }
  record_fd = -1;
  if (linkat(directory_fd, temporary, directory_fd, PROCESS_RECORD, 0) != 0) goto failed;
  if (unlinkat(directory_fd, temporary, 0) != 0 || fsync(directory_fd) != 0) {
    unlinkat(directory_fd, PROCESS_RECORD, 0);
    goto failed;
  }
  close(directory_fd);
  if (snprintf(g_record_path, sizeof(g_record_path), "%s/%s", run_directory, PROCESS_RECORD)
      >= (int)sizeof(g_record_path)) return 0;
  return 1;

failed:
  if (record_fd >= 0) close(record_fd);
  if (directory_fd >= 0) {
    unlinkat(directory_fd, temporary, 0);
    close(directory_fd);
  }
  return 0;
}

static void remove_own_process_record(void) {
  int fd;
  char bytes[sizeof(g_record_bytes)];
  ssize_t length;
  if (!g_record_path[0] || !g_record_bytes[0]) return;
  fd = open(g_record_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return;
  length = read(fd, bytes, sizeof(bytes) - 1);
  close(fd);
  if (length <= 0) return;
  bytes[length] = '\0';
  if (strcmp(bytes, g_record_bytes) == 0) unlink(g_record_path);
  secure_zero(bytes, sizeof(bytes));
}

int main(int argc, char **argv) {
  int port = DEFAULT_PORT;
  const char *run_directory = DEFAULT_RUN_DIR;
  int listener;
  struct sigaction action;
  if (argc > 3 || (argc > 1 && !parse_port(argv[1], &port))) return 2;
  if (argc > 2) run_directory = argv[2];
  if (run_directory[0] != '/' || strlen(run_directory) >= PATH_MAX - 32) return 2;
  if (!read_token_from_stdin()) return 3;
#if defined(__linux__) || defined(__ANDROID__)
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    secure_zero(g_token, sizeof(g_token));
    return 4;
  }
#endif
  signal(SIGPIPE, SIG_IGN);
  listener = create_listener(port);
  if (listener < 0) {
    secure_zero(g_token, sizeof(g_token));
    return 5;
  }
  if (listener <= STDERR_FILENO) {
    int moved = fcntl(listener, F_DUPFD, STDERR_FILENO + 1);
    if (moved < 0 || set_cloexec(moved) != 0) {
      if (moved >= 0) close(moved);
      close(listener);
      secure_zero(g_token, sizeof(g_token));
      return 5;
    }
    close(listener);
    listener = moved;
  }
#if !defined(XENOID_ROOTD_FOREGROUND_TEST)
  if (daemon(0, 0) != 0) {
    close(listener);
    secure_zero(g_token, sizeof(g_token));
    return 6;
  }
#endif
  memset(&action, 0, sizeof(action));
  action.sa_handler = shutdown_handler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, &action, NULL);
  g_listen_fd = listener;
  if (!write_process_record(run_directory, port)) {
    listener = (int)g_listen_fd;
    g_listen_fd = -1;
    if (listener >= 0) close(listener);
    secure_zero(g_token, sizeof(g_token));
    return 7;
  }

  while (!g_shutdown) {
    int client = accept(listener, NULL, NULL);
    if (client < 0) {
      if (errno == EINTR) continue;
      if (g_shutdown || errno == EBADF || errno == EINVAL) break;
      continue;
    }
    set_cloexec(client);
    {
      struct timeval receive_timeout = {HEADER_TIMEOUT_MS / 1000,
          (HEADER_TIMEOUT_MS % 1000) * 1000};
      struct timeval send_timeout = {2, 0};
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout));
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    }
    if (!acquire_handler_slot()) {
      send_error(client, 503, "Service Unavailable", "rootd_busy");
      close(client);
      continue;
    }
    {
      struct client_context *context = (struct client_context *)malloc(sizeof(*context));
      pthread_t thread;
      if (!context) {
        release_handler_slot();
        send_error(client, 503, "Service Unavailable", "rootd_busy");
        close(client);
        continue;
      }
      context->fd = client;
      if (pthread_create(&thread, NULL, client_thread, context) != 0) {
        free(context);
        release_handler_slot();
        send_error(client, 503, "Service Unavailable", "rootd_busy");
        close(client);
        continue;
      }
      pthread_detach(thread);
    }
  }

  g_shutdown = 1;
  listener = (int)g_listen_fd;
  g_listen_fd = -1;
  if (listener >= 0) close(listener);
  pthread_mutex_lock(&g_handler_lock);
  while (g_handler_count > 0) pthread_cond_wait(&g_handler_cond, &g_handler_lock);
  pthread_mutex_unlock(&g_handler_lock);
  remove_own_process_record();
  secure_zero(g_token, sizeof(g_token));
  secure_zero(g_record_bytes, sizeof(g_record_bytes));
  return 0;
}
