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
    return "{\"return\":" + std::to_string(operation.result)
            + ",\"errno\":" + std::to_string(operation.error)
            + ",\"type\":" + quote(type) + "}";
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


static Operation libcStatfs(const char *path) {
    Operation operation;
    struct statfs value{};
    errno = 0;
    operation.result = statfs(path, &value);
    operation.error = operation.result == 0 ? 0 : errno;
    if (operation.result == 0) operation.type = static_cast<unsigned long>(value.f_type);
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
    }
    directSyscall(__NR_close, fd, 0);
    return operation;
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
            + ",\"system\":" + pathJson("/system") + "}";
    if (appDataPath != nullptr) env->ReleaseStringUTFChars(appDataPath, appData);
    return env->NewStringUTF(result.c_str());
}
