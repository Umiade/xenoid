#include <jni.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr int kNoError = -1;

struct LinuxDirent64 {
    uint64_t ino;
    int64_t off;
    unsigned short reclen;
    unsigned char type;
    char name[];
};

struct Operation {
    bool attempted = false;
    long value = -1;
    int error = 0;
    std::set<std::string> ifaces;
};

struct NetlinkResult {
    Operation socketOp;
    Operation bindOp;
    Operation sendOp;
    Operation receiveOp;
};

static std::string quote(const std::string &value) {
    std::string out = "\"";
    for (unsigned char item : value) {
        if (item == '\\' || item == '"') { out.push_back('\\'); out.push_back(static_cast<char>(item)); }
        else if (item >= 0x20 && item <= 0x7e) out.push_back(static_cast<char>(item));
    }
    out.push_back('"');
    return out;
}

static std::string array(const std::set<std::string> &values) {
    std::string out = "[";
    bool first = true;
    for (const std::string &value : values) {
        if (!first) out.push_back(',');
        first = false;
        out += quote(value);
    }
    out.push_back(']');
    return out;
}

static std::string operationJson(const Operation &operation) {
    return "{\"attempted\":" + std::string(operation.attempted ? "true" : "false")
            + ",\"return\":" + std::to_string(operation.value)
            + ",\"errno\":" + std::to_string(operation.error)
            + ",\"ifaces\":" + array(operation.ifaces) + "}";
}

static Operation socketAttempt(int domain, int type, int protocol) {
    Operation operation;
    operation.attempted = true;
    errno = 0;
    operation.value = syscall(__NR_socket, domain, type, protocol);
    operation.error = operation.value < 0 ? errno : 0;
    if (operation.value >= 0) {
        int saved = operation.error;
        syscall(__NR_close, static_cast<int>(operation.value));
        errno = saved;
    }
    return operation;
}

static Operation socketPairAttempt() {
    Operation operation;
    int fds[2] = {-1, -1};
    operation.attempted = true;
    errno = 0;
    operation.value = syscall(__NR_socketpair, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds);
    operation.error = operation.value < 0 ? errno : 0;
    if (operation.value == 0) {
        syscall(__NR_close, fds[0]);
        syscall(__NR_close, fds[1]);
    }
    return operation;
}

static Operation libcIfaddrsAttempt() {
    Operation operation;
    operation.attempted = true;
    errno = 0;
    ifaddrs *values = nullptr;
    operation.value = getifaddrs(&values);
    operation.error = operation.value != 0 ? errno : 0;
    if (operation.value == 0) {
        for (ifaddrs *item = values; item != nullptr; item = item->ifa_next) {
            if (item->ifa_name != nullptr) operation.ifaces.insert(item->ifa_name);
        }
        freeifaddrs(values);
    }
    return operation;
}

static Operation ioctlIfacesAttempt() {
    Operation operation;
    operation.attempted = true;
    errno = 0;
    int fd = static_cast<int>(syscall(__NR_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (fd < 0) {
        operation.value = -1;
        operation.error = errno;
        return operation;
    }
    std::vector<char> storage(16384);
    ifconf config{};
    config.ifc_len = static_cast<int>(storage.size());
    config.ifc_buf = storage.data();
    errno = 0;
    operation.value = syscall(__NR_ioctl, fd, SIOCGIFCONF, &config);
    operation.error = operation.value != 0 ? errno : 0;
    if (operation.value == 0) {
        const int count = config.ifc_len / static_cast<int>(sizeof(ifreq));
        const ifreq *items = reinterpret_cast<const ifreq *>(storage.data());
        for (int index = 0; index < count; index++) {
            if (items[index].ifr_name[0] != '\0') operation.ifaces.insert(items[index].ifr_name);
        }
    }
    int saved = operation.error;
    syscall(__NR_close, fd);
    errno = saved;
    return operation;
}

static NetlinkResult routeNetlinkAttempt(int requestType) {
    NetlinkResult result;
    result.socketOp.attempted = true;
    errno = 0;
    result.socketOp.value = syscall(__NR_socket, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    result.socketOp.error = result.socketOp.value < 0 ? errno : 0;
    if (result.socketOp.value < 0) return result;

    int fd = static_cast<int>(result.socketOp.value);
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    result.bindOp.attempted = true;
    errno = 0;
    result.bindOp.value = syscall(__NR_bind, fd, &local, sizeof(local));
    result.bindOp.error = result.bindOp.value != 0 ? errno : 0;
    if (result.bindOp.value != 0) {
        int saved = result.bindOp.error;
        syscall(__NR_close, fd);
        errno = saved;
        return result;
    }

    struct {
        nlmsghdr header;
        union {
            ifinfomsg link;
            ifaddrmsg address;
            rtgenmsg route;
        } message;
    } request{};
    size_t payloadSize = sizeof(ifinfomsg);
    if (requestType == RTM_GETADDR) payloadSize = sizeof(ifaddrmsg);
    else if (requestType == RTM_GETROUTE) payloadSize = sizeof(rtgenmsg);
    request.header.nlmsg_len = NLMSG_LENGTH(payloadSize);
    request.header.nlmsg_type = requestType;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 18765;
    request.message.route.rtgen_family = AF_UNSPEC;

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    result.sendOp.attempted = true;
    errno = 0;
    result.sendOp.value = syscall(__NR_sendto, fd, &request, request.header.nlmsg_len, 0,
                                  &kernel, sizeof(kernel));
    result.sendOp.error = result.sendOp.value < 0 ? errno : 0;
    if (result.sendOp.value < 0) {
        int saved = result.sendOp.error;
        syscall(__NR_close, fd);
        errno = saved;
        return result;
    }

    result.receiveOp.attempted = true;
    bool done = false;
    while (!done) {
        char buffer[32768];
        iovec iov{buffer, sizeof(buffer)};
        sockaddr_nl source{};
        msghdr message{};
        message.msg_name = &source;
        message.msg_namelen = sizeof(source);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        errno = 0;
        long received = syscall(__NR_recvmsg, fd, &message, 0);
        if (received <= 0) {
            result.receiveOp.value = received;
            result.receiveOp.error = received < 0 ? errno : 0;
            break;
        }
        result.receiveOp.value = 0;
        int remaining = static_cast<int>(received);
        for (nlmsghdr *header = reinterpret_cast<nlmsghdr *>(buffer);
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (header->nlmsg_type == NLMSG_ERROR) {
                nlmsgerr *error = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(header));
                result.receiveOp.value = -1;
                result.receiveOp.error = error != nullptr ? -error->error : EIO;
                done = true;
                break;
            }
            if (header->nlmsg_type == RTM_NEWLINK) {
                ifinfomsg *info = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(header));
                int attrLength = IFLA_PAYLOAD(header);
                for (rtattr *attr = IFLA_RTA(info); RTA_OK(attr, attrLength); attr = RTA_NEXT(attr, attrLength)) {
                    if (attr->rta_type != IFLA_IFNAME || RTA_PAYLOAD(attr) <= 1) continue;
                    const char *name = reinterpret_cast<const char *>(RTA_DATA(attr));
                    if (name[RTA_PAYLOAD(attr) - 1] == '\0') result.receiveOp.ifaces.insert(name);
                }
            } else if (header->nlmsg_type == RTM_NEWADDR) {
                ifaddrmsg *info = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(header));
                char name[IFNAMSIZ]{};
                if (if_indextoname(static_cast<unsigned int>(info->ifa_index), name) != nullptr) {
                    result.receiveOp.ifaces.insert(name);
                }
            } else if (header->nlmsg_type == RTM_NEWROUTE) {
                rtmsg *route = reinterpret_cast<rtmsg *>(NLMSG_DATA(header));
                if (route->rtm_dst_len != 0 || (route->rtm_family != AF_INET && route->rtm_family != AF_INET6)) continue;
                int attrLength = RTM_PAYLOAD(header);
                for (rtattr *attr = RTM_RTA(route); RTA_OK(attr, attrLength); attr = RTA_NEXT(attr, attrLength)) {
                    if (attr->rta_type != RTA_OIF || RTA_PAYLOAD(attr) != sizeof(int)) continue;
                    int index = *reinterpret_cast<int *>(RTA_DATA(attr));
                    char name[IFNAMSIZ]{};
                    if (if_indextoname(static_cast<unsigned int>(index), name) != nullptr) {
                        result.receiveOp.ifaces.insert(name);
                    }
                }
            }
        }
    }
    int saved = result.receiveOp.error;
    syscall(__NR_close, fd);
    errno = saved;
    return result;
}

static std::string netlinkJson(const NetlinkResult &result) {
    return "{\"socket\":" + operationJson(result.socketOp)
            + ",\"bind\":" + operationJson(result.bindOp)
            + ",\"sendto\":" + operationJson(result.sendOp)
            + ",\"receive\":" + operationJson(result.receiveOp) + "}";
}

static Operation rawReadAttempt(const char *path) {
    Operation operation;
    operation.attempted = true;
    errno = 0;
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
    if (fd < 0) {
        operation.error = errno;
        return operation;
    }
    std::string text;
    char buffer[4096];
    while (text.size() < 65536) {
        errno = 0;
        long count = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (count < 0) {
            operation.value = -1;
            operation.error = errno;
            break;
        }
        if (count == 0) {
            operation.value = 0;
            operation.error = 0;
            break;
        }
        text.append(buffer, static_cast<size_t>(count));
    }
    int saved = operation.error;
    syscall(__NR_close, fd);
    errno = saved;
    if (operation.value != 0) return operation;

    if (std::string(path) == "/proc/net/route") {
        size_t offset = 0;
        while (offset < text.size()) {
            size_t end = text.find('\n', offset);
            if (end == std::string::npos) end = text.size();
            std::string line = text.substr(offset, end - offset);
            char iface[IFNAMSIZ]{};
            char destination[16]{};
            if (sscanf(line.c_str(), "%15s %15s", iface, destination) == 2
                    && std::string(iface) != "Iface") operation.ifaces.insert(iface);
            offset = end + 1;
        }
    } else {
        size_t offset = 0;
        while (offset < text.size()) {
            size_t end = text.find('\n', offset);
            if (end == std::string::npos) end = text.size();
            std::string line = text.substr(offset, end - offset);
            char address[33]{}, index[9]{}, prefix[9]{}, scope[9]{}, flags[9]{}, iface[IFNAMSIZ]{};
            if (sscanf(line.c_str(), "%32s %8s %8s %8s %8s %15s", address, index, prefix, scope, flags, iface) == 6) {
                operation.ifaces.insert(iface);
            }
            offset = end + 1;
        }
    }
    return operation;
}

static Operation sysfsIfacesAttempt() {
    Operation operation;
    operation.attempted = true;
    errno = 0;
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, "/sys/class/net", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0));
    if (fd < 0) {
        operation.error = errno;
        return operation;
    }
    char buffer[8192];
    while (true) {
        errno = 0;
        long count = syscall(__NR_getdents64, fd, buffer, sizeof(buffer));
        if (count < 0) {
            operation.value = -1;
            operation.error = errno;
            break;
        }
        if (count == 0) {
            operation.value = 0;
            operation.error = 0;
            break;
        }
        long offset = 0;
        while (offset < count) {
            LinuxDirent64 *entry = reinterpret_cast<LinuxDirent64 *>(buffer + offset);
            if (entry->reclen == 0 || offset + entry->reclen > count) break;
            std::string name(entry->name);
            if (name != "." && name != "..") operation.ifaces.insert(name);
            offset += entry->reclen;
        }
    }
    int saved = operation.error;
    syscall(__NR_close, fd);
    errno = saved;
    return operation;
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_org_example_cellularruntimeprobe_ProbeActivity_nativeProbe(JNIEnv *env, jclass) {
    std::string out = "{\"uid\":" + std::to_string(getuid());
    out += ",\"sockets\":{";
    out += "\"inet\":" + operationJson(socketAttempt(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    out += ",\"inet6\":" + operationJson(socketAttempt(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    out += ",\"unix\":" + operationJson(socketPairAttempt());
    out += "}";
    out += ",\"getifaddrs\":" + operationJson(libcIfaddrsAttempt());
    out += ",\"ioctl\":" + operationJson(ioctlIfacesAttempt());
    out += ",\"netlink\":{";
    out += "\"getlink\":" + netlinkJson(routeNetlinkAttempt(RTM_GETLINK));
    out += ",\"getaddr\":" + netlinkJson(routeNetlinkAttempt(RTM_GETADDR));
    out += ",\"getroute\":" + netlinkJson(routeNetlinkAttempt(RTM_GETROUTE));
    out += "}";
    out += ",\"procRoutes\":" + operationJson(rawReadAttempt("/proc/net/route"));
    out += ",\"procIpv6\":" + operationJson(rawReadAttempt("/proc/net/if_inet6"));
    out += ",\"sysfs\":" + operationJson(sysfsIfacesAttempt());
    out += "}";
    return env->NewStringUTF(out.c_str());
}
