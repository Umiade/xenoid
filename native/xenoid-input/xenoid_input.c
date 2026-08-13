// xenoid-input: Linux /dev/uinput touch injector for Android root environments.
// It writes to the input driver layer (/dev/uinput), not accessibility/instrumentation APIs.
// The virtual input device identity is profile-driven to avoid exposing xenoid/minitouch-style markers.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>

/* Keep the Android API 21 build compatible with older NDK input headers. */
#ifndef ABS_MT_TOUCH_MAJOR
#define ABS_MT_TOUCH_MAJOR 0x30
#endif
#ifndef ABS_MT_TOUCH_MINOR
#define ABS_MT_TOUCH_MINOR 0x31
#endif
#ifndef ABS_MT_WIDTH_MAJOR
#define ABS_MT_WIDTH_MAJOR 0x32
#endif
#ifndef ABS_MT_WIDTH_MINOR
#define ABS_MT_WIDTH_MINOR 0x33
#endif
#ifndef ABS_MT_ORIENTATION
#define ABS_MT_ORIENTATION 0x34
#endif

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void profile_json_path(char *out, size_t n) {
    const char *a = "/data/local/tmp/";
    const char *b = "xen";
    const char *c = "oid-profile/effective.json";
    snprintf(out, n, "%s%s%s", a, b, c);
}

struct input_profile {
    char name[UINPUT_MAX_NAME_SIZE];
    int bustype;
    int vendor;
    int product;
    int version;
    int x_min;
    int x_max;
    int y_min;
    int y_max;
    int pressure_min;
    int pressure_max;
    int tracking_min;
    int tracking_max;
};

static struct input_profile g_profile = {
    .name = "sec_touchscreen",
    .bustype = BUS_I2C,
    .vendor = 0x04e8,
    .product = 0x6860,
    .version = 0x0100,
    .x_min = 0,
    .x_max = 1439,
    .y_min = 0,
    .y_max = 3119,
    .pressure_min = 0,
    .pressure_max = 255,
    .tracking_min = 0,
    .tracking_max = 31,
};

static void reset_profile(void) {
    struct input_profile defaults = {
        .name = "sec_touchscreen",
        .bustype = BUS_I2C,
        .vendor = 0x04e8,
        .product = 0x6860,
        .version = 0x0100,
        .x_min = 0,
        .x_max = 1439,
        .y_min = 0,
        .y_max = 3119,
        .pressure_min = 0,
        .pressure_max = 255,
        .tracking_min = 0,
        .tracking_max = 31,
    };
    g_profile = defaults;
}

static char *read_text_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    size_t cap = 65536;
    if (!fstat(fd, &st) && st.st_size > 0 && st.st_size < 1024 * 1024) cap = (size_t)st.st_size;
    char *buf = (char *)calloc(1, cap + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, cap);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = 0;
    return buf;
}

static void json_copy_string(const char *json, const char *key, char *dst, size_t dstsz) {
    if (!json || !key || !dst || dstsz == 0) return;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p = strchr(p + strlen(needle), ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return;
    p++;
    size_t n = 0;
    while (*p && !(*p == '"' && (p == json || *(p - 1) != '\\')) && n + 1 < dstsz) {
        if (*p == '\\' && p[1]) {
            p++;
            if (*p == 'n') dst[n++] = '\n';
            else if (*p == 'r') dst[n++] = '\r';
            else dst[n++] = *p;
            p++;
        } else {
            dst[n++] = *p++;
        }
    }
    dst[n] = 0;
}

static int json_int_value(const char *json, const char *key, int fallback) {
    if (!json || !key) return fallback;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return fallback;
    p = strchr(p + strlen(needle), ':');
    if (!p) return fallback;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '"') p++;
    char *end = NULL;
    long base = 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) base = 16;
    long v = strtol(p, &end, (int)base);
    return end && end != p ? (int)v : fallback;
}

static void sanitize_name(char *s) {
    if (!s || !s[0]) return;
    for (char *p = s; *p; ++p) {
        if (*p == '\n' || *p == '\r' || *p == '\t') *p = ' ';
    }
    s[UINPUT_MAX_NAME_SIZE - 1] = 0;
    char bad0[16], bad1[16], bad2[16], bad3[16];
    snprintf(bad0, sizeof(bad0), "%s%s", "xen", "oid");
    snprintf(bad1, sizeof(bad1), "%s%s", "fr", "ida");
    snprintf(bad2, sizeof(bad2), "%s%s", "ui", "nput");
    snprintf(bad3, sizeof(bad3), "%s%s", "mini", "touch");
    if (strstr(s, bad0) || strstr(s, bad1) || strstr(s, bad2) || strstr(s, bad3)) {
        snprintf(s, UINPUT_MAX_NAME_SIZE, "%s", "sec_touchscreen");
    }
}

static char *read_profile_field(const char *field) {
    char path[PATH_MAX];
    profile_json_path(path, sizeof(path));
    char *name = strrchr(path, '/');
    if (!name) return NULL;
    name++;
    snprintf(name, sizeof(path) - (size_t)(name - path), "%s", field);
    char *value = read_text_file(path);
    if (!value) return NULL;
    size_t length = strlen(value);
    while (length > 0 && (value[length - 1] == ' ' || value[length - 1] == '\t'
            || value[length - 1] == '\r' || value[length - 1] == '\n')) {
        value[--length] = 0;
    }
    char *start = value;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (start != value) memmove(value, start, strlen(start) + 1);
    return value;
}

static int profile_field_int(const char *field, int fallback) {
    char *text = read_profile_field(field);
    if (!text || !text[0]) {
        free(text);
        return fallback;
    }
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 0);
    int result = errno == 0 && end && *end == 0 && value >= INT_MIN && value <= INT_MAX
            ? (int)value : fallback;
    free(text);
    return result;
}

static void profile_field_string(const char *field, char *out, size_t out_size) {
    char *text = read_profile_field(field);
    if (text && text[0]) snprintf(out, out_size, "%s", text);
    free(text);
}

static char *json_object_value(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return NULL;
    p = strchr(p + strlen(needle), ':');
    if (!p) return NULL;
    while (*++p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {}
    if (*p != '{') return NULL;
    int depth = 0;
    int in_string = 0;
    int escaped = 0;
    for (const char *end = p; *end; ++end) {
        if (in_string) {
            if (escaped) escaped = 0;
            else if (*end == '\\') escaped = 1;
            else if (*end == '"') in_string = 0;
            continue;
        }
        if (*end == '"') in_string = 1;
        else if (*end == '{') depth++;
        else if (*end == '}' && --depth == 0) {
            return strndup(p, (size_t)(end - p + 1));
        }
    }
    return NULL;
}

static void load_profile(void) {
    char path[256];
    profile_json_path(path, sizeof(path));
    char *json = read_text_file(path);
    if (json) {
        char *input = json_object_value(json, "input");
        if (input) {
            char *axis = NULL;
            json_copy_string(input, "name", g_profile.name, sizeof(g_profile.name));
            g_profile.bustype = json_int_value(input, "busType", g_profile.bustype);
            g_profile.vendor = json_int_value(input, "vendorId", g_profile.vendor);
            g_profile.product = json_int_value(input, "productId", g_profile.product);
            g_profile.version = json_int_value(input, "version", g_profile.version);
            axis = json_object_value(input, "x");
            if (axis) {
                g_profile.x_min = json_int_value(axis, "minimum", g_profile.x_min);
                g_profile.x_max = json_int_value(axis, "maximum", g_profile.x_max);
                free(axis);
            }
            axis = json_object_value(input, "y");
            if (axis) {
                g_profile.y_min = json_int_value(axis, "minimum", g_profile.y_min);
                g_profile.y_max = json_int_value(axis, "maximum", g_profile.y_max);
                free(axis);
            }
            axis = json_object_value(input, "pressure");
            if (axis) {
                g_profile.pressure_min = json_int_value(axis, "minimum", g_profile.pressure_min);
                g_profile.pressure_max = json_int_value(axis, "maximum", g_profile.pressure_max);
                free(axis);
            }
            axis = json_object_value(input, "trackingId");
            if (axis) {
                g_profile.tracking_min = json_int_value(axis, "minimum", g_profile.tracking_min);
                g_profile.tracking_max = json_int_value(axis, "maximum", g_profile.tracking_max);
                free(axis);
            }
        }
        free(input);
        free(json);
    }
    profile_field_string("input_name", g_profile.name, sizeof(g_profile.name));
    g_profile.bustype = profile_field_int("input_busType", g_profile.bustype);
    g_profile.vendor = profile_field_int("input_vendorId", g_profile.vendor);
    g_profile.product = profile_field_int("input_productId", g_profile.product);
    g_profile.version = profile_field_int("input_version", g_profile.version);
    g_profile.x_min = profile_field_int("input_x_minimum", g_profile.x_min);
    g_profile.x_max = profile_field_int("input_x_maximum", g_profile.x_max);
    g_profile.y_min = profile_field_int("input_y_minimum", g_profile.y_min);
    g_profile.y_max = profile_field_int("input_y_maximum", g_profile.y_max);
    g_profile.pressure_min = profile_field_int("input_pressure_minimum", g_profile.pressure_min);
    g_profile.pressure_max = profile_field_int("input_pressure_maximum", g_profile.pressure_max);
    g_profile.tracking_min = profile_field_int("input_trackingId_minimum", g_profile.tracking_min);
    g_profile.tracking_max = profile_field_int("input_trackingId_maximum", g_profile.tracking_max);

    sanitize_name(g_profile.name);
    if (g_profile.x_min < 0 || g_profile.x_max <= g_profile.x_min) {
        g_profile.x_min = 0; g_profile.x_max = 1439;
    }
    if (g_profile.y_min < 0 || g_profile.y_max <= g_profile.y_min) {
        g_profile.y_min = 0; g_profile.y_max = 3119;
    }
    if (g_profile.pressure_min < 0 || g_profile.pressure_max <= g_profile.pressure_min
            || g_profile.pressure_max > 65535) {
        g_profile.pressure_min = 0; g_profile.pressure_max = 255;
    }
    if (g_profile.tracking_min < 0 || g_profile.tracking_max <= g_profile.tracking_min
            || g_profile.tracking_max >= INT_MAX) {
        g_profile.tracking_min = 0; g_profile.tracking_max = 31;
    }
}

#define CONTACT_AXIS_MAX 31
#define ORIENTATION_MAX 90
#define MAX_GESTURE_DURATION_MS 15000

static int g_emit_failed;

static int emit_event(int fd, int type, int code, int value) {
    struct input_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    ev.code = code;
    ev.value = value;

    const unsigned char *src = (const unsigned char *)&ev;
    size_t remaining = sizeof(ev);
    while (remaining > 0) {
        ssize_t written = write(fd, src, remaining);
        if (written > 0) {
            src += written;
            remaining -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        g_emit_failed = 1;
        return -1;
    }
    return 0;
}

static int setup_abs(int fd, int code, int min, int max, int resolution) {
    struct uinput_abs_setup abs;
    memset(&abs, 0, sizeof(abs));
    abs.code = code;
    abs.absinfo.minimum = min;
    abs.absinfo.maximum = max;
    abs.absinfo.resolution = resolution;
    if (ioctl(fd, UI_ABS_SETUP, &abs) < 0) {
        perror("UI_ABS_SETUP");
        return -1;
    }
    return 0;
}

static int enable_bit(int fd, unsigned long request, int code) {
    if (ioctl(fd, request, code) < 0) {
        perror("uinput capability");
        return -1;
    }
    return 0;
}

static int create_device(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open /dev/uinput");
        return -1;
    }

    if (enable_bit(fd, UI_SET_EVBIT, EV_SYN)
            || enable_bit(fd, UI_SET_EVBIT, EV_KEY)
            || enable_bit(fd, UI_SET_KEYBIT, BTN_TOUCH)
            || enable_bit(fd, UI_SET_KEYBIT, BTN_TOOL_FINGER)
            || enable_bit(fd, UI_SET_EVBIT, EV_ABS)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_X)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_Y)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_PRESSURE)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_SLOT)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_POSITION_X)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_POSITION_Y)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_PRESSURE)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_TOUCH_MAJOR)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_TOUCH_MINOR)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_WIDTH_MAJOR)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_WIDTH_MINOR)
            || enable_bit(fd, UI_SET_ABSBIT, ABS_MT_ORIENTATION)
            || enable_bit(fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT)) {
        close(fd);
        return -1;
    }

    struct uinput_setup usetup;
    memset(&usetup, 0, sizeof(usetup));
    usetup.id.bustype = (unsigned short)g_profile.bustype;
    usetup.id.vendor = (unsigned short)g_profile.vendor;
    usetup.id.product = (unsigned short)g_profile.product;
    usetup.id.version = (unsigned short)g_profile.version;
    snprintf(usetup.name, sizeof(usetup.name), "%s", g_profile.name);
    if (ioctl(fd, UI_DEV_SETUP, &usetup) < 0) {
        perror("UI_DEV_SETUP");
        close(fd);
        return -1;
    }

    if (setup_abs(fd, ABS_X, g_profile.x_min, g_profile.x_max, 10)
            || setup_abs(fd, ABS_Y, g_profile.y_min, g_profile.y_max, 10)
            || setup_abs(fd, ABS_PRESSURE, g_profile.pressure_min, g_profile.pressure_max, 0)
            || setup_abs(fd, ABS_MT_SLOT, 0, 9, 0)
            || setup_abs(fd, ABS_MT_POSITION_X, g_profile.x_min, g_profile.x_max, 10)
            || setup_abs(fd, ABS_MT_POSITION_Y, g_profile.y_min, g_profile.y_max, 10)
            || setup_abs(fd, ABS_MT_TRACKING_ID, g_profile.tracking_min, g_profile.tracking_max, 0)
            || setup_abs(fd, ABS_MT_PRESSURE, g_profile.pressure_min, g_profile.pressure_max, 0)
            || setup_abs(fd, ABS_MT_TOUCH_MAJOR, 0, CONTACT_AXIS_MAX, 0)
            || setup_abs(fd, ABS_MT_TOUCH_MINOR, 0, CONTACT_AXIS_MAX, 0)
            || setup_abs(fd, ABS_MT_WIDTH_MAJOR, 0, CONTACT_AXIS_MAX, 0)
            || setup_abs(fd, ABS_MT_WIDTH_MINOR, 0, CONTACT_AXIS_MAX, 0)
            || setup_abs(fd, ABS_MT_ORIENTATION, -ORIENTATION_MAX, ORIENTATION_MAX, 0)) {
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        perror("UI_DEV_CREATE");
        close(fd);
        return -1;
    }
    usleep(200000);
    return fd;
}
#define INPUT_GROUP_ID 1004

static char g_event_node[PATH_MAX];

static int publish_event_node(int fd) {
    char sysname[64];
    memset(sysname, 0, sizeof(sysname));
    if (ioctl(fd, UI_GET_SYSNAME(sizeof(sysname)), sysname) < 0) {
        perror("UI_GET_SYSNAME");
        return -1;
    }

    char input_path[PATH_MAX];
    snprintf(input_path, sizeof(input_path), "/sys/class/input/%s", sysname);
    DIR *dir = opendir(input_path);
    if (!dir) {
        perror("open input sysfs");
        return -1;
    }

    char event_name[64] = {0};
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strncmp(entry->d_name, "event", 5) && entry->d_name[5] >= '0' && entry->d_name[5] <= '9') {
            snprintf(event_name, sizeof(event_name), "%s", entry->d_name);
            break;
        }
    }
    closedir(dir);
    if (!event_name[0]) {
        fprintf(stderr, "uinput event sysfs node missing\n");
        return -1;
    }

    char dev_path[PATH_MAX];
    snprintf(dev_path, sizeof(dev_path), "%s/%s/dev", input_path, event_name);
    char *dev_text = read_text_file(dev_path);
    if (!dev_text) {
        perror("read input device number");
        return -1;
    }
    unsigned int major_number = 0;
    unsigned int minor_number = 0;
    int parsed = sscanf(dev_text, "%u:%u", &major_number, &minor_number);
    free(dev_text);
    if (parsed != 2) {
        fprintf(stderr, "invalid input device number\n");
        return -1;
    }

    struct stat st;
    if (lstat("/dev/input", &st) < 0) {
        if (errno != ENOENT || mkdir("/dev/input", 0755) < 0) {
            perror("create /dev/input");
            return -1;
        }
    } else if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        fprintf(stderr, "/dev/input is not a real directory\n");
        return -1;
    }

    snprintf(g_event_node, sizeof(g_event_node), "/dev/input/%s", event_name);
    dev_t device_number = makedev(major_number, minor_number);
    if (lstat(g_event_node, &st) < 0) {
        if (errno != ENOENT || mknod(g_event_node, S_IFCHR | 0660, device_number) < 0) {
            perror("create input event node");
            g_event_node[0] = 0;
            return -1;
        }
    } else if (!S_ISCHR(st.st_mode) || st.st_rdev != device_number) {
        fprintf(stderr, "input event node collision\n");
        g_event_node[0] = 0;
        return -1;
    }
    if (chown(g_event_node, 0, INPUT_GROUP_ID) < 0 || chmod(g_event_node, 0660) < 0) {
        perror("configure input event node");
        unlink(g_event_node);
        g_event_node[0] = 0;
        return -1;
    }
    return 0;
}

static void unpublish_event_node(void) {
    if (g_event_node[0]) {
        unlink(g_event_node);
        g_event_node[0] = 0;
    }
}

static void destroy_device(int fd) {
    if (fd >= 0) {
        usleep(30000);
        if (ioctl(fd, UI_DEV_DESTROY) < 0) perror("UI_DEV_DESTROY");
        close(fd);
    }
}

static uint64_t g_rng = UINT64_C(0x9e3779b97f4a7c15);

static unsigned int rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (unsigned int)(g_rng >> 32);
}

static void seed_rng(void) {
    uint64_t seed = 0;
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        if (read(rfd, &seed, sizeof(seed)) != (ssize_t)sizeof(seed)) seed = 0;
        close(rfd);
    }
    if (seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_BOOTTIME, &ts);
        seed = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 21) ^ (uint64_t)getpid();
    }
    g_rng ^= seed;
    if (g_rng == 0) g_rng = UINT64_C(0x9e3779b97f4a7c15);
}

static int clamp_int(int value, int minimum, int maximum) {
    if (value < minimum) return minimum;
    if (value > maximum) return maximum;
    return value;
}

static int random_between(int minimum, int maximum) {
    return minimum + (int)(rnd() % (unsigned int)(maximum - minimum + 1));
}

static int random_jitter(int spread) {
    return random_between(-spread, spread);
}

static int valid_point(int x, int y) {
    return x >= g_profile.x_min && x <= g_profile.x_max
            && y >= g_profile.y_min && y <= g_profile.y_max;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        perror("clock_gettime");
        g_emit_failed = 1;
        return 0;
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void sleep_until_ns(uint64_t deadline_ns) {
    struct timespec deadline;
    deadline.tv_sec = (time_t)(deadline_ns / UINT64_C(1000000000));
    deadline.tv_nsec = (long)(deadline_ns % UINT64_C(1000000000));
    int result;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    } while (result == EINTR);
    if (result != 0) {
        errno = result;
        perror("clock_nanosleep");
        g_emit_failed = 1;
    }
}

static int pressure_percent(int percent) {
    int value = (g_profile.pressure_max * percent + 50) / 100;
    return clamp_int(value, 1, g_profile.pressure_max);
}

static void emit_position(int fd, int x, int y) {
    emit_event(fd, EV_ABS, ABS_X, x);
    emit_event(fd, EV_ABS, ABS_Y, y);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_X, x);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, y);
}

static void emit_contact(
        int fd,
        int pressure,
        int touch_major,
        int touch_minor,
        int width_major,
        int width_minor,
        int orientation) {
    emit_event(fd, EV_ABS, ABS_PRESSURE, pressure);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, pressure);
    emit_event(fd, EV_ABS, ABS_MT_TOUCH_MAJOR, touch_major);
    emit_event(fd, EV_ABS, ABS_MT_TOUCH_MINOR, touch_minor);
    emit_event(fd, EV_ABS, ABS_MT_WIDTH_MAJOR, width_major);
    emit_event(fd, EV_ABS, ABS_MT_WIDTH_MINOR, width_minor);
    emit_event(fd, EV_ABS, ABS_MT_ORIENTATION, orientation);
}

static void emit_shaped_contact(
        int fd,
        int pressure,
        int peak_pressure,
        int peak_touch_major,
        int peak_touch_minor,
        int width_major,
        int width_minor,
        int orientation) {
    int touch_major = 3 + (peak_touch_major - 3) * pressure / peak_pressure;
    int touch_minor = 2 + (peak_touch_minor - 2) * pressure / peak_pressure;
    touch_major = clamp_int(touch_major, 3, peak_touch_major);
    touch_minor = clamp_int(touch_minor, 2, touch_major - 1);
    emit_contact(
            fd,
            pressure,
            touch_major,
            touch_minor,
            width_major,
            clamp_int(width_minor, touch_minor + 1, width_major),
            clamp_int(orientation, -ORIENTATION_MAX, ORIENTATION_MAX));
}

static void sync_frame(int fd) {
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
}

static void begin_contact(int fd, int tracking_id) {
    emit_event(fd, EV_ABS, ABS_MT_SLOT, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 1);
}

static void end_contact(int fd) {
    emit_event(fd, EV_ABS, ABS_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_TOUCH_MAJOR, 0);
    emit_event(fd, EV_ABS, ABS_MT_TOUCH_MINOR, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 0);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 0);
    sync_frame(fd);
}

static int tap(int fd, FILE *out, int x, int y) {
    if (!valid_point(x, y)) {
        fprintf(
                out,
                "{\"ok\":false,\"error\":\"tap coordinates outside display\","
                "\"xMin\":%d,\"xMax\":%d,\"yMin\":%d,\"yMax\":%d}\n",
                g_profile.x_min, g_profile.x_max, g_profile.y_min, g_profile.y_max);
        return 64;
    }
    g_emit_failed = 0;

    int duration_ms = random_between(90, 145);
    int tracking = random_between(g_profile.tracking_min, g_profile.tracking_max);
    int peak_pressure = pressure_percent(random_between(32, 46));
    int down_pressure = clamp_int(peak_pressure * random_between(45, 58) / 100, 1, peak_pressure);
    int lift_pressure = clamp_int(peak_pressure * random_between(30, 42) / 100, 1, peak_pressure);
    int peak_touch_major = random_between(10, 15);
    int peak_touch_minor = peak_touch_major - random_between(2, 4);
    int width_major = clamp_int(peak_touch_major + random_between(6, 9), 1, CONTACT_AXIS_MAX);
    int width_minor = clamp_int(peak_touch_minor + random_between(5, 8), 1, width_major);
    int orientation = random_between(-18, 18);
    int px = clamp_int(x + random_jitter(2), g_profile.x_min, g_profile.x_max);
    int py = clamp_int(y + random_jitter(2), g_profile.y_min, g_profile.y_max);

    uint64_t start_ns = monotonic_ns();
    begin_contact(fd, tracking);
    emit_position(fd, px, py);
    emit_shaped_contact(
            fd, down_pressure, peak_pressure, peak_touch_major, peak_touch_minor,
            width_major, width_minor, orientation);
    sync_frame(fd);

    sleep_until_ns(start_ns + UINT64_C(20000000));
    px = clamp_int(x + random_jitter(1), g_profile.x_min, g_profile.x_max);
    py = clamp_int(y + random_jitter(1), g_profile.y_min, g_profile.y_max);
    emit_position(fd, px, py);
    emit_shaped_contact(
            fd, peak_pressure, peak_pressure, peak_touch_major, peak_touch_minor,
            width_major, width_minor, orientation + random_jitter(2));
    sync_frame(fd);

    sleep_until_ns(start_ns + (uint64_t)(duration_ms - 15) * UINT64_C(1000000));
    px = clamp_int(x + random_jitter(1), g_profile.x_min, g_profile.x_max);
    py = clamp_int(y + random_jitter(1), g_profile.y_min, g_profile.y_max);
    emit_position(fd, px, py);
    emit_shaped_contact(
            fd, lift_pressure, peak_pressure, peak_touch_major, peak_touch_minor,
            width_major, width_minor, orientation + random_jitter(2));
    sync_frame(fd);

    sleep_until_ns(start_ns + (uint64_t)duration_ms * UINT64_C(1000000));
    end_contact(fd);
    int result = g_emit_failed ? 3 : 0;
    if (result == 0) {
        fprintf(
                out,
                "{\"ok\":true,\"schema\":\"dev.input-action/v2\",\"kind\":\"tap\","
                "\"driverLayer\":true,\"contactDurationMs\":%d,\"frames\":4,"
                "\"pressurePeak\":%d,\"touchMajorPeak\":%d,\"touchMinorPeak\":%d,"
                "\"widthMajor\":%d,\"widthMinor\":%d}\n",
                duration_ms, peak_pressure, peak_touch_major, peak_touch_minor,
                width_major, width_minor);
    } else {
        fprintf(out, "{\"ok\":false,\"error\":\"uinput event write failed\"}\n");
    }
    return result;
}

static int swipe_pressure(double t, int start_pressure, int peak_pressure, int end_pressure) {
    double value;
    if (t < 0.18) {
        value = start_pressure + (peak_pressure - start_pressure) * (t / 0.18);
    } else {
        value = peak_pressure - (peak_pressure - end_pressure) * ((t - 0.18) / 0.82);
    }
    int pressure = (int)(value + 0.5) + random_jitter(clamp_int(peak_pressure / 40, 1, 3));
    return clamp_int(pressure, 1, g_profile.pressure_max);
}

static int swipe(int fd, FILE *out, int x1, int y1, int x2, int y2, int duration_ms) {
    if (!valid_point(x1, y1) || !valid_point(x2, y2)) {
        fprintf(
                out,
                "{\"ok\":false,\"error\":\"swipe coordinates outside display\","
                "\"xMin\":%d,\"xMax\":%d,\"yMin\":%d,\"yMax\":%d}\n",
                g_profile.x_min, g_profile.x_max, g_profile.y_min, g_profile.y_max);
        return 64;
    }
    if (x1 == x2 && y1 == y2) {
        fprintf(out, "{\"ok\":false,\"error\":\"swipe endpoints must differ\"}\n");
        return 64;
    }
    if (duration_ms < 16 || duration_ms > MAX_GESTURE_DURATION_MS) {
        fprintf(
                out,
                "{\"ok\":false,\"error\":\"swipe duration outside range\","
                "\"minimumMs\":16,\"maximumMs\":%d}\n",
                MAX_GESTURE_DURATION_MS);
        return 64;
    }
    g_emit_failed = 0;

    int dx = x2 - x1;
    int dy = y2 - y1;
    int span = abs(dx) > abs(dy) ? abs(dx) : abs(dy);
    int bend_limit = clamp_int(span / 32, 1, 24);
    int bend = random_jitter(bend_limit);
    int c1x = x1 + dx / 3 - dy * bend / span;
    int c1y = y1 + dy / 3 + dx * bend / span;
    int c2x = x1 + 2 * dx / 3 - dy * bend / span;
    int c2y = y1 + 2 * dy / 3 + dx * bend / span;
    int sample_period_ms = random_between(8, 11);
    int frames = duration_ms / sample_period_ms;
    if (frames < 4) frames = 4;

    int tracking = random_between(g_profile.tracking_min, g_profile.tracking_max);
    int peak_pressure = pressure_percent(random_between(34, 48));
    int start_pressure = clamp_int(peak_pressure * random_between(48, 62) / 100, 1, peak_pressure);
    int end_pressure = clamp_int(peak_pressure * random_between(28, 42) / 100, 1, peak_pressure);
    int peak_touch_major = random_between(9, 14);
    int peak_touch_minor = peak_touch_major - random_between(2, 4);
    int width_major = clamp_int(peak_touch_major + random_between(6, 9), 1, CONTACT_AXIS_MAX);
    int width_minor = clamp_int(peak_touch_minor + random_between(5, 8), 1, width_major);
    int orientation = random_between(-24, 24);
    int drift_x = 0;
    int drift_y = 0;

    uint64_t start_ns = monotonic_ns();
    begin_contact(fd, tracking);
    for (int i = 0; i < frames; i++) {
        uint64_t frame_ns = start_ns
                + (uint64_t)duration_ms * UINT64_C(1000000) * (uint64_t)i / (uint64_t)frames;
        sleep_until_ns(frame_ns);
        double t = (double)i / (double)(frames - 1);
        double u = t * t * (3.0 - 2.0 * t);
        double one = 1.0 - u;
        double bx = one * one * one * x1
                + 3.0 * one * one * u * c1x
                + 3.0 * one * u * u * c2x
                + u * u * u * x2;
        double by = one * one * one * y1
                + 3.0 * one * one * u * c1y
                + 3.0 * one * u * u * c2y
                + u * u * u * y2;
        int px = (int)(bx + 0.5);
        int py = (int)(by + 0.5);
        if (i > 0 && i + 1 < frames) {
            drift_x = clamp_int(drift_x + random_jitter(1), -2, 2);
            drift_y = clamp_int(drift_y + random_jitter(1), -2, 2);
            double envelope = 4.0 * u * (1.0 - u);
            px += (int)(drift_x * envelope);
            py += (int)(drift_y * envelope);
        }
        px = clamp_int(px, g_profile.x_min, g_profile.x_max);
        py = clamp_int(py, g_profile.y_min, g_profile.y_max);

        int pressure = swipe_pressure(t, start_pressure, peak_pressure, end_pressure);
        emit_position(fd, px, py);
        emit_shaped_contact(
                fd, pressure, peak_pressure, peak_touch_major, peak_touch_minor,
                width_major, width_minor, orientation + random_jitter(2));
        sync_frame(fd);
    }

    sleep_until_ns(start_ns + (uint64_t)duration_ms * UINT64_C(1000000));
    end_contact(fd);
    int result = g_emit_failed ? 3 : 0;
    if (result == 0) {
        fprintf(
                out,
                "{\"ok\":true,\"schema\":\"dev.input-action/v2\",\"kind\":\"swipe\","
                "\"driverLayer\":true,\"contactDurationMs\":%d,\"frames\":%d,"
                "\"samplePeriodMs\":%d,\"trajectory\":\"cubic-bezier+smoothstep\","
                "\"pressurePeak\":%d,\"touchMajorPeak\":%d,\"touchMinorPeak\":%d,"
                "\"widthMajor\":%d,\"widthMinor\":%d}\n",
                duration_ms, frames + 1, sample_period_ms, peak_pressure,
                peak_touch_major, peak_touch_minor, width_major, width_minor);
    } else {
        fprintf(out, "{\"ok\":false,\"error\":\"uinput event write failed\"}\n");
    }
    return result;
}

static int status(FILE *out) {
    fprintf(out, "{\"ok\":true,\"schema\":\"dev.input/v2\",\"name\":\"");
    for (char *p = g_profile.name; *p; ++p) {
        if (*p == '"' || *p == '\\') fputc('\\', out);
        fputc(*p, out);
    }
    fprintf(
            out,
            "\",\"bustype\":%d,\"vendor\":%d,\"product\":%d,\"version\":%d,"
            "\"xMin\":%d,\"xMax\":%d,\"yMin\":%d,\"yMax\":%d,"
            "\"pressureMin\":%d,\"pressureMax\":%d,"
            "\"trackingMin\":%d,\"trackingMax\":%d,"
            "\"driverLayer\":true,\"directTouch\":true,\"persistentDevice\":true,"
            "\"eventNode\":\"%s\",\"touchMajorMax\":%d,\"touchMinorMax\":%d,"
            "\"widthMajorMax\":%d,\"widthMinorMax\":%d,"
            "\"orientationMin\":%d,\"orientationMax\":%d}\n",
            g_profile.bustype,
            g_profile.vendor,
            g_profile.product,
            g_profile.version,
            g_profile.x_min,
            g_profile.x_max,
            g_profile.y_min,
            g_profile.y_max,
            g_profile.pressure_min,
            g_profile.pressure_max,
            g_profile.tracking_min,
            g_profile.tracking_max,
            g_event_node,
            CONTACT_AXIS_MAX,
            CONTACT_AXIS_MAX,
            CONTACT_AXIS_MAX,
            CONTACT_AXIS_MAX,
            -ORIENTATION_MAX,
            ORIENTATION_MAX);
    return 0;
}

static int parse_int_arg(const char *text, int *out) {
    if (!text || !text[0] || !out) return -1;
    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < INT_MIN || value > INT_MAX) return -1;
    *out = (int)value;
    return 0;
}

#define INPUT_SOCKET_PATH "/dev/socket/.inputd"

static volatile sig_atomic_t g_stop_service;

static void stop_service(int signal_number) {
    (void)signal_number;
    g_stop_service = 1;
}

static int reload_input_device(int *input_fd, FILE *out) {
    unpublish_event_node();
    destroy_device(*input_fd);
    *input_fd = -1;
    reset_profile();
    load_profile();

    int replacement = create_device();
    if (replacement < 0 || publish_event_node(replacement) < 0) {
        if (replacement >= 0) destroy_device(replacement);
        fprintf(out, "{\"ok\":false,\"error\":\"input device reload failed\"}\n");
        return 2;
    }
    *input_fd = replacement;
    return status(out);
}

static int handle_command(int *input_fd, FILE *out, char *line) {
    char *tokens[8];
    int count = 0;
    char *save = NULL;
    for (char *token = strtok_r(line, " \t\r\n", &save);
            token && count < (int)(sizeof(tokens) / sizeof(tokens[0]));
            token = strtok_r(NULL, " \t\r\n", &save)) {
        tokens[count++] = token;
    }

    if (count == 1 && !strcmp(tokens[0], "status")) return status(out);
    if (count == 1 && !strcmp(tokens[0], "reload")) return reload_input_device(input_fd, out);
    if (*input_fd < 0) {
        fprintf(out, "{\"ok\":false,\"error\":\"input driver unavailable\"}\n");
        return 2;
    }
    if (count == 3 && !strcmp(tokens[0], "tap")) {
        int x, y;
        if (!parse_int_arg(tokens[1], &x) && !parse_int_arg(tokens[2], &y)) {
            return tap(*input_fd, out, x, y);
        }
    }
    if (count == 6 && !strcmp(tokens[0], "swipe")) {
        int x1, y1, x2, y2, duration_ms;
        if (!parse_int_arg(tokens[1], &x1)
                && !parse_int_arg(tokens[2], &y1)
                && !parse_int_arg(tokens[3], &x2)
                && !parse_int_arg(tokens[4], &y2)
                && !parse_int_arg(tokens[5], &duration_ms)) {
            return swipe(*input_fd, out, x1, y1, x2, y2, duration_ms);
        }
    }
    fprintf(out, "{\"ok\":false,\"error\":\"invalid input command\"}\n");
    return 64;
}

static int run_service(void) {
    reset_profile();
    load_profile();
    seed_rng();

    int input_fd = create_device();
    if (input_fd < 0) return 2;
    if (publish_event_node(input_fd) < 0) {
        destroy_device(input_fd);
        return 2;
    }

    struct stat st;
    if (lstat(INPUT_SOCKET_PATH, &st) == 0) {
        if (!S_ISSOCK(st.st_mode) || unlink(INPUT_SOCKET_PATH) < 0) {
            fprintf(stderr, "input service socket collision\n");
            unpublish_event_node();
            destroy_device(input_fd);
            return 2;
        }
    } else if (errno != ENOENT) {
        perror("inspect input service socket");
        unpublish_event_node();
        destroy_device(input_fd);
        return 2;
    }

    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        perror("create input service socket");
        unpublish_event_node();
        destroy_device(input_fd);
        return 2;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", INPUT_SOCKET_PATH);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0
            || chmod(INPUT_SOCKET_PATH, 0600) < 0
            || listen(server_fd, 4) < 0) {
        perror("start input service socket");
        close(server_fd);
        unlink(INPUT_SOCKET_PATH);
        unpublish_event_node();
        destroy_device(input_fd);
        return 2;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_service;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    while (!g_stop_service) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept input command");
            break;
        }
        fcntl(client_fd, F_SETFD, FD_CLOEXEC);
        FILE *client = fdopen(client_fd, "r+");
        if (!client) {
            close(client_fd);
            continue;
        }
        setvbuf(client, NULL, _IOLBF, 0);
        char command[512];
        if (fgets(command, sizeof(command), client)) handle_command(&input_fd, client, command);
        fflush(client);
        fclose(client);
    }

    close(server_fd);
    unlink(INPUT_SOCKET_PATH);
    unpublish_event_node();
    destroy_device(input_fd);
    return g_stop_service ? 0 : 2;
}

static int run_client(int argc, char **argv) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        printf("{\"ok\":false,\"error\":\"input driver service unavailable\"}\n");
        return 2;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", INPUT_SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        printf("{\"ok\":false,\"error\":\"input driver service unavailable\"}\n");
        return 2;
    }

    FILE *server = fdopen(fd, "r+");
    if (!server) {
        close(fd);
        printf("{\"ok\":false,\"error\":\"input driver service unavailable\"}\n");
        return 2;
    }
    for (int i = 1; i < argc; i++) fprintf(server, "%s%s", i == 1 ? "" : " ", argv[i]);
    fputc('\n', server);
    fflush(server);

    char response[4096];
    int result = 2;
    if (fgets(response, sizeof(response), server)) {
        fputs(response, stdout);
        result = strstr(response, "\"ok\":true") ? 0 : 1;
    } else {
        printf("{\"ok\":false,\"error\":\"input driver service closed connection\"}\n");
    }
    fclose(server);
    return result;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "serve")) return run_service();
    if (argc >= 2) return run_client(argc, argv);
    fprintf(stderr, "usage: %s status | tap x y | swipe x1 y1 x2 y2 duration_ms\n", argv[0]);
    return 64;
}
