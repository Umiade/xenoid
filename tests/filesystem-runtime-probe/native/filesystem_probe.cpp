#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
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
    errno = 0;
    operation.result = syscall(__NR_statfs, path, &value);
    operation.error = operation.result == 0 ? 0 : errno;
    if (operation.result == 0) operation.type = static_cast<unsigned long>(value.f_type);
    return operation;
}

static Operation rawFstatfs(const char *path) {
    Operation operation;
    errno = 0;
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path,
                                      O_RDONLY | O_CLOEXEC | O_DIRECTORY, 0));
    if (fd < 0) {
        operation.error = errno;
        return operation;
    }
    struct statfs value{};
    errno = 0;
    operation.result = syscall(__NR_fstatfs, fd, &value);
    operation.error = operation.result == 0 ? 0 : errno;
    if (operation.result == 0) operation.type = static_cast<unsigned long>(value.f_type);
    int saved = operation.error;
    syscall(__NR_close, fd);
    errno = saved;
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
    std::string result = "{\"uid\":" + std::to_string(getuid())
            + ",\"appData\":" + pathJson(appData)
            + ",\"data\":" + dataPathJson("/data")
            + ",\"system\":" + pathJson("/system") + "}";
    if (appDataPath != nullptr) env->ReleaseStringUTFChars(appDataPath, appData);
    return env->NewStringUTF(result.c_str());
}
