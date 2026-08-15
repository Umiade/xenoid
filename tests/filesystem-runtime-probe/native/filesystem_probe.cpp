#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <cstdio>
#include <string>

namespace {

struct Operation {
    long result = -1;
    int error = 0;
    unsigned long type = 0;
    unsigned long bsize = 0;
    unsigned long blocks = 0;
    unsigned long bfree = 0;
    unsigned long bavail = 0;
    unsigned long files = 0;
    unsigned long ffree = 0;
    unsigned long namelen = 0;
    unsigned long flags = 0;
    int fsid[2] = {0, 0};
};

static std::string quote(const char *value) {
    std::string out = "\"";
    if (value != nullptr) {
        for (const unsigned char item : std::string(value)) {
            if (item == '\\' || item == '"') {
                out.push_back('\\');
                out.push_back(static_cast<char>(item));
            } else if (item >= 0x20 && item <= 0x7e) {
                out.push_back(static_cast<char>(item));
            }
        }
    }
    out.push_back('"');
    return out;
}

static std::string operationJson(const Operation &operation) {
    char type[32];
    std::snprintf(type, sizeof(type), "0x%lx", operation.type);
    std::string out = "{\"return\":" + std::to_string(operation.result)
            + ",\"errno\":" + std::to_string(operation.error)
            + ",\"type\":" + quote(type);
    if (operation.result == 0) {
        char fsid[24];
        std::snprintf(fsid, sizeof(fsid), "%08x%08x",
                      static_cast<unsigned int>(operation.fsid[0]),
                      static_cast<unsigned int>(operation.fsid[1]));
        out += ",\"bsize\":" + std::to_string(operation.bsize)
             + ",\"blocks\":" + std::to_string(operation.blocks)
             + ",\"bfree\":" + std::to_string(operation.bfree)
             + ",\"bavail\":" + std::to_string(operation.bavail)
             + ",\"files\":" + std::to_string(operation.files)
             + ",\"ffree\":" + std::to_string(operation.ffree)
             + ",\"namelen\":" + std::to_string(operation.namelen)
             + ",\"flags\":" + std::to_string(operation.flags)
             + ",\"fsid\":" + quote(fsid);
    }
    return out + "}";
}
static long directSyscall(long number, long arg0, long arg1,
                          long arg2 = 0, long arg3 = 0) {
#if defined(__aarch64__)
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x8 asm("x8") = number;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                 : "memory", "cc");
    return x0;
#else
    return syscall(number, arg0, arg1, arg2, arg3);
#endif
}

static bool rawError(long result) {
    return result < 0 && result >= -4095;
}


static void fillStatfsDetail(Operation &operation, const struct statfs &value) {
    if (operation.result != 0) return;
    operation.bsize = static_cast<unsigned long>(value.f_bsize);
    operation.blocks = static_cast<unsigned long>(value.f_blocks);
    operation.bfree = static_cast<unsigned long>(value.f_bfree);
    operation.bavail = static_cast<unsigned long>(value.f_bavail);
    operation.files = static_cast<unsigned long>(value.f_files);
    operation.ffree = static_cast<unsigned long>(value.f_ffree);
    operation.namelen = static_cast<unsigned long>(value.f_namelen);
    operation.flags = static_cast<unsigned long>(value.f_flags);
    memcpy(operation.fsid, &value.f_fsid, sizeof(operation.fsid));
}

static Operation libcStatfs(const char *path) {
    Operation operation;
    struct statfs value{};
    errno = 0;
    operation.result = statfs(path, &value);
    operation.error = operation.result == 0 ? 0 : errno;
    if (operation.result == 0) operation.type = static_cast<unsigned long>(value.f_type);
    fillStatfsDetail(operation, value);
    return operation;
}

static Operation rawStatfs(const char *path) {
    Operation operation;
    struct statfs value{};
    long result = directSyscall(__NR_statfs, reinterpret_cast<long>(path),
                                reinterpret_cast<long>(&value));
    if (rawError(result)) {
        operation.error = static_cast<int>(-result);
        return operation;
    }
    operation.result = result;
    operation.type = static_cast<unsigned long>(value.f_type);
    fillStatfsDetail(operation, value);
    return operation;
}

static Operation rawFstatfs(const char *path) {
    Operation operation;
    long fd = directSyscall(__NR_openat, AT_FDCWD, reinterpret_cast<long>(path),
                            O_RDONLY | O_CLOEXEC | O_DIRECTORY, 0);
    if (rawError(fd)) {
        operation.error = static_cast<int>(-fd);
        return operation;
    }
    struct statfs value{};
    long result = directSyscall(__NR_fstatfs, fd, reinterpret_cast<long>(&value));
    if (rawError(result)) {
        operation.error = static_cast<int>(-result);
    } else {
        operation.result = result;
        operation.type = static_cast<unsigned long>(value.f_type);
        fillStatfsDetail(operation, value);
    }
    directSyscall(__NR_close, fd, 0);
    return operation;
}

static std::string rawReadFile(const char *path) {
    std::string out;
    long fd = directSyscall(__NR_openat, AT_FDCWD, reinterpret_cast<long>(path),
                            O_RDONLY | O_CLOEXEC, 0);
    if (rawError(fd)) return out;
    char buffer[4096];
    for (;;) {
        long count = directSyscall(__NR_read, fd, reinterpret_cast<long>(buffer),
                                   sizeof(buffer));
        if (count <= 0) break;
        out.append(buffer, static_cast<size_t>(count));
        if (out.size() > (1u << 20)) break;
    }
    directSyscall(__NR_close, fd, 0);
    return out;
}

static std::string dataMountLine(const char *path) {
    std::string text = rawReadFile(path);
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(pos, end - pos);
        if (line.find(" /data ") != std::string::npos) return line;
        pos = end + 1;
    }
    return "";
}


static std::string pathJson(const char *path) {
    return "{\"path\":" + quote(path)
            + ",\"libc\":" + operationJson(libcStatfs(path))
            + ",\"raw\":" + operationJson(rawStatfs(path))
            + ",\"rawFd\":" + operationJson(rawFstatfs(path)) + "}";
}

static std::string dataPathJson(const char *path) {
    return "{\"path\":" + quote(path)
            + ",\"libc\":" + operationJson(libcStatfs(path))
            + ",\"raw\":" + operationJson(rawStatfs(path)) + "}";
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_org_example_filesystemruntimeprobe_ProbeActivity_nativeProbe(
        JNIEnv *env, jclass, jstring appDataPath) {
    const char *appData = appDataPath == nullptr
            ? "/data" : env->GetStringUTFChars(appDataPath, nullptr);
    char cryptoState[PROP_VALUE_MAX] = {};
    char cryptoType[PROP_VALUE_MAX] = {};
    __system_property_get("ro.crypto.state", cryptoState);
    __system_property_get("ro.crypto.type", cryptoType);
    std::string result = "{\"uid\":" + std::to_string(getuid())
            + ",\"cryptoState\":" + quote(cryptoState)
            + ",\"cryptoType\":" + quote(cryptoType)
            + ",\"appData\":" + pathJson(appData)
            + ",\"data\":" + dataPathJson("/data")
            + ",\"system\":" + pathJson("/system")
            + ",\"mountinfoData\":" + quote(dataMountLine("/proc/self/mountinfo").c_str())
            + ",\"mountsData\":" + quote(dataMountLine("/proc/self/mounts").c_str()) + "}";
    if (appDataPath != nullptr) env->ReleaseStringUTFChars(appDataPath, appData);
    return env->NewStringUTF(result.c_str());
}
