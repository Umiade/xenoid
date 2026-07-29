// xenoid-input: Linux /dev/uinput touch injector for Android root environments.
// It writes to the input driver layer (/dev/uinput), not accessibility/instrumentation APIs.
// The virtual input device identity is profile-driven to avoid exposing xenoid/minitouch-style markers.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>

/* API21 linux/input.h lacks some ABS_MT axes; define them from the kernel ABI. */
#ifndef ABS_MT_TOOL_MAJOR
#define ABS_MT_TOOL_MAJOR 0x30
#endif
#ifndef ABS_MT_TOUCH_MAJOR
#define ABS_MT_TOUCH_MAJOR 0x31
#endif
#ifndef ABS_MT_WIDTH_MAJOR
#define ABS_MT_WIDTH_MAJOR 0x32
#endif
#ifndef ABS_MT_HEIGHT_MAJOR
#define ABS_MT_HEIGHT_MAJOR 0x33
#endif
#ifndef ABS_MT_ORIENTATION
#define ABS_MT_ORIENTATION 0x34
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    int width;
    int height;
    int pressure_max;
    int tracking_max;
};

static struct input_profile g_profile = {
    .name = "sec_touchscreen",
    .bustype = BUS_I2C,
    .vendor = 0x04e8,
    .product = 0x6860,
    .version = 0x0100,
    .width = 1080,
    .height = 2400,
    .pressure_max = 255,
    .tracking_max = 65535,
};

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

static void load_profile(void) {
    char path[256]; profile_json_path(path, sizeof(path));
    char *j = read_text_file(path);
    if (!j) return;
    json_copy_string(j, "input_name", g_profile.name, sizeof(g_profile.name));
    json_copy_string(j, "touch_name", g_profile.name, sizeof(g_profile.name));
    json_copy_string(j, "input_device_name", g_profile.name, sizeof(g_profile.name));
    sanitize_name(g_profile.name);
    g_profile.bustype = json_int_value(j, "input_bustype", g_profile.bustype);
    g_profile.vendor = json_int_value(j, "input_vendor", g_profile.vendor);
    g_profile.product = json_int_value(j, "input_product", g_profile.product);
    g_profile.version = json_int_value(j, "input_version", g_profile.version);
    g_profile.width = json_int_value(j, "width", json_int_value(j, "display_width", g_profile.width));
    g_profile.height = json_int_value(j, "height", json_int_value(j, "display_height", g_profile.height));
    g_profile.pressure_max = json_int_value(j, "pressure_max", g_profile.pressure_max);
    g_profile.tracking_max = json_int_value(j, "tracking_max", g_profile.tracking_max);
    if (g_profile.width < 1) g_profile.width = 1080;
    if (g_profile.height < 1) g_profile.height = 2400;
    if (g_profile.pressure_max < 1) g_profile.pressure_max = 255;
    if (g_profile.tracking_max < 2) g_profile.tracking_max = 65535;
    free(j);
}

static int emit_event(int fd, int type, int code, int value) {
    struct input_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = type;
    ev.code = code;
    ev.value = value;
    return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int setup_abs(int fd, int code, int min, int max, int resolution) {
    struct uinput_abs_setup abs;
    memset(&abs, 0, sizeof(abs));
    abs.code = code;
    abs.absinfo.minimum = min;
    abs.absinfo.maximum = max;
    abs.absinfo.resolution = resolution;
    return ioctl(fd, UI_ABS_SETUP, &abs);
}

static int create_device(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        perror("open /dev/uinput");
        return -1;
    }
    ioctl(fd, UI_SET_EVBIT, EV_SYN);
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_KEYBIT, BTN_TOUCH);
    ioctl(fd, UI_SET_KEYBIT, BTN_TOOL_FINGER);
    ioctl(fd, UI_SET_EVBIT, EV_ABS);
    ioctl(fd, UI_SET_ABSBIT, ABS_X);
    ioctl(fd, UI_SET_ABSBIT, ABS_Y);
    ioctl(fd, UI_SET_ABSBIT, ABS_PRESSURE);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_SLOT);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_POSITION_X);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_POSITION_Y);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_PRESSURE);
    /* Human-realism axes: without these, MotionEvent toolMajor/touchMajor/orientation/size
       read 0, which is a robotic tell for behavior-class detection SDKs. */
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_TOOL_MAJOR);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_TOUCH_MAJOR);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_WIDTH_MAJOR);
    ioctl(fd, UI_SET_ABSBIT, ABS_MT_ORIENTATION);

    struct uinput_setup usetup;
    memset(&usetup, 0, sizeof(usetup));
    usetup.id.bustype = (unsigned short)g_profile.bustype;
    usetup.id.vendor = (unsigned short)g_profile.vendor;
    usetup.id.product = (unsigned short)g_profile.product;
    usetup.id.version = (unsigned short)g_profile.version;
    snprintf(usetup.name, sizeof(usetup.name), "%s", g_profile.name);
    if (ioctl(fd, UI_DEV_SETUP, &usetup) < 0) { perror("UI_DEV_SETUP"); close(fd); return -1; }
    setup_abs(fd, ABS_X, 0, g_profile.width, 10);
    setup_abs(fd, ABS_Y, 0, g_profile.height, 10);
    setup_abs(fd, ABS_PRESSURE, 0, g_profile.pressure_max, 0);
    setup_abs(fd, ABS_MT_SLOT, 0, 9, 0);
    setup_abs(fd, ABS_MT_POSITION_X, 0, g_profile.width, 10);
    setup_abs(fd, ABS_MT_POSITION_Y, 0, g_profile.height, 10);
    setup_abs(fd, ABS_MT_TRACKING_ID, 0, g_profile.tracking_max, 0);
    setup_abs(fd, ABS_MT_PRESSURE, 0, g_profile.pressure_max, 0);
    setup_abs(fd, ABS_MT_TOOL_MAJOR, 0, 31, 0);
    setup_abs(fd, ABS_MT_TOUCH_MAJOR, 0, 31, 0);
    setup_abs(fd, ABS_MT_WIDTH_MAJOR, 0, 31, 0);
    setup_abs(fd, ABS_MT_ORIENTATION, -90, 90, 0);
    if (ioctl(fd, UI_DEV_CREATE) < 0) { perror("UI_DEV_CREATE"); close(fd); return -1; }
    usleep(200000);
    return fd;
}

static void destroy_device(int fd) {
    if (fd >= 0) {
        ioctl(fd, UI_DEV_DESTROY);
        close(fd);
    }
}

static int tap(int x, int y) {
    int fd = create_device();
    if (fd < 0) return 2;
    emit_event(fd, EV_ABS, ABS_MT_SLOT, 0);
    emit_event(fd, EV_ABS, ABS_X, x);
    emit_event(fd, EV_ABS, ABS_Y, y);
    emit_event(fd, EV_ABS, ABS_PRESSURE, 80);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 80);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, 1);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_X, x);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, y);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 1);
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    usleep(80000);
    emit_event(fd, EV_KEY, BTN_TOUCH, 0);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 0);
    emit_event(fd, EV_ABS, ABS_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    destroy_device(fd);
    return 0;
}

static int swipe(int x1, int y1, int x2, int y2, int duration_ms) {
    int fd = create_device();
    if (fd < 0) return 2;
    int steps = duration_ms / 16;
    if (steps < 2) steps = 2;
    emit_event(fd, EV_ABS, ABS_MT_SLOT, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, 1);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 1);
    for (int i = 0; i <= steps; i++) {
        int x = x1 + (x2 - x1) * i / steps;
        int y = y1 + (y2 - y1) * i / steps;
        emit_event(fd, EV_ABS, ABS_X, x);
        emit_event(fd, EV_ABS, ABS_Y, y);
        emit_event(fd, EV_ABS, ABS_PRESSURE, 80);
        emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 80);
        emit_event(fd, EV_ABS, ABS_MT_POSITION_X, x);
        emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, y);
        emit_event(fd, EV_SYN, SYN_REPORT, 0);
        usleep((duration_ms * 1000) / steps);
    }
    emit_event(fd, EV_KEY, BTN_TOUCH, 0);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 0);
    emit_event(fd, EV_ABS, ABS_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    destroy_device(fd);
    return 0;
}

/* ---- human-behavior touch injection (P3b) ---- */
/* A robotic tap is a perfect point with fixed pressure and zero contact area; real
   fingers produce a small contact ellipse, a pressure ramp, slight position jitter,
   and a non-linear swipe trajectory with ease-out velocity. These helpers inject
   that shape so behavior-class detectors see human-like MotionEvent tuples. */
static unsigned long g_rng = 0x9e3779b97f4a7c15UL;
static unsigned int rnd(void){ g_rng^=g_rng<<13; g_rng^=g_rng>>7; g_rng^=g_rng<<17; return (unsigned int)(g_rng>>32); }
static void seed_rng(void) {
    unsigned long seed = 0;
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        if (read(rfd, &seed, sizeof(seed)) != (ssize_t)sizeof(seed)) seed = 0;
        close(rfd);
    }
    if (seed == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_BOOTTIME, &ts);
        seed = (unsigned long)ts.tv_nsec ^ ((unsigned long)ts.tv_sec << 21) ^ (unsigned long)getpid();
    }
    g_rng ^= seed;
    if (g_rng == 0) g_rng = 0x9e3779b97f4a7c15UL;
}
static int rj(int spread){ return (int)(rnd()%(2*spread+1))-spread; } /* jitter in [-spread,spread] */

static void finger_contact(int fd, int pressure, int area, int orient){
    emit_event(fd, EV_ABS, ABS_MT_TOOL_MAJOR, area);
    emit_event(fd, EV_ABS, ABS_MT_TOUCH_MAJOR, area);
    emit_event(fd, EV_ABS, ABS_MT_WIDTH_MAJOR, area);
    emit_event(fd, EV_ABS, ABS_MT_ORIENTATION, orient);
    emit_event(fd, EV_ABS, ABS_PRESSURE, pressure);
    emit_event(fd, EV_ABS, ABS_MT_PRESSURE, pressure);
}

static int htap(int x, int y) {
    int fd = create_device();
    if (fd < 0) return 2;
    int px = x + rj(3), py = y + rj(3);
    int tracking = 1 + (int)(rnd() % (unsigned int)(g_profile.tracking_max - 1));
    int peak = 70 + (int)(rnd()%31);
    int area = 6 + (int)(rnd()%7);
    int hold_ms = 85 + (int)(rnd()%55);
    emit_event(fd, EV_ABS, ABS_MT_SLOT, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, tracking);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 1);
    emit_event(fd, EV_ABS, ABS_X, px); emit_event(fd, EV_ABS, ABS_Y, py);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_X, px); emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, py);
    finger_contact(fd, peak/2, area, rj(8));
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    usleep(20000);
    px += rj(2); py += rj(2);
    emit_event(fd, EV_ABS, ABS_X, px); emit_event(fd, EV_ABS, ABS_Y, py);
    emit_event(fd, EV_ABS, ABS_MT_POSITION_X, px); emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, py);
    finger_contact(fd, peak, area, rj(8));
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    usleep(hold_ms * 1000);
    finger_contact(fd, peak/3, area, rj(8));
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    usleep(15000);
    emit_event(fd, EV_KEY, BTN_TOUCH, 0);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 0);
    emit_event(fd, EV_ABS, ABS_PRESSURE, 0); emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    destroy_device(fd);
    return 0;
}

static int hswipe(int x1, int y1, int x2, int y2, int duration_ms) {
    int fd = create_device();
    if (fd < 0) return 2;
    int steps = duration_ms / 14; if (steps < 4) steps = 4;
    int area = 5 + (int)(rnd()%4);
    int tracking = 1 + (int)(rnd() % (unsigned int)(g_profile.tracking_max - 1));
    int mx = (x1+x2)/2 + rj(30), my = (y1+y2)/2 + rj(30);
    emit_event(fd, EV_ABS, ABS_MT_SLOT, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, tracking);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 1);
    emit_event(fd, EV_KEY, BTN_TOUCH, 1);
    for (int i = 0; i <= steps; i++) {
        double t = (double)i / steps;
        double e = 1.0 - (1.0 - t) * (1.0 - t);
        double bx = (1.0-e)*(1.0-e)*x1 + 2.0*(1.0-e)*e*mx + e*e*x2;
        double by = (1.0-e)*(1.0-e)*y1 + 2.0*(1.0-e)*e*my + e*e*y2;
        int px = (int)bx + rj(2), py = (int)by + rj(2);
        int pressure = 70 + (int)(rnd()%25) - (int)(12*t);
        emit_event(fd, EV_ABS, ABS_X, px); emit_event(fd, EV_ABS, ABS_Y, py);
        emit_event(fd, EV_ABS, ABS_MT_POSITION_X, px); emit_event(fd, EV_ABS, ABS_MT_POSITION_Y, py);
        finger_contact(fd, pressure, area, rj(10));
        emit_event(fd, EV_SYN, SYN_REPORT, 0);
        usleep((duration_ms * 1000) / steps);
    }
    emit_event(fd, EV_KEY, BTN_TOUCH, 0);
    emit_event(fd, EV_KEY, BTN_TOOL_FINGER, 0);
    emit_event(fd, EV_ABS, ABS_PRESSURE, 0); emit_event(fd, EV_ABS, ABS_MT_PRESSURE, 0);
    emit_event(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    emit_event(fd, EV_SYN, SYN_REPORT, 0);
    destroy_device(fd);
    return 0;
}

static int status(void) {
    printf("{\"ok\":true,\"schema\":\"dev.input/v1\",\"name\":\"");
    for (char *p = g_profile.name; *p; ++p) { if (*p == '"' || *p == '\\') putchar('\\'); putchar(*p); }
    printf("\",\"bustype\":%d,\"vendor\":%d,\"product\":%d,\"version\":%d,\"width\":%d,\"height\":%d,\"pressureMax\":%d,\"trackingMax\":%d}\n",
        g_profile.bustype, g_profile.vendor, g_profile.product, g_profile.version, g_profile.width, g_profile.height, g_profile.pressure_max, g_profile.tracking_max);
    return 0;
}

int main(int argc, char **argv) {
    load_profile();
    seed_rng();
    if (argc < 2) {
        fprintf(stderr, "usage: %s status | tap x y | swipe x1 y1 x2 y2 duration_ms\n", argv[0]);
        return 64;
    }
    if (!strcmp(argv[1], "status")) return status();
    if (!strcmp(argv[1], "tap") && argc == 4) return tap(atoi(argv[2]), atoi(argv[3]));
    if (!strcmp(argv[1], "swipe") && argc == 7) return swipe(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
    if (!strcmp(argv[1], "htap") && argc == 4) return htap(atoi(argv[2]), atoi(argv[3]));
    if (!strcmp(argv[1], "hswipe") && argc == 7) return hswipe(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
    fprintf(stderr, "invalid arguments\n");
    return 64;
}
