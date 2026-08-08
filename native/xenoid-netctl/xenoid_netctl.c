#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/route.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#ifndef IFLA_RTA
#define IFLA_RTA(r) ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif

#define NL_BUFSZ 8192

static void die_json(const char *op, int err) {
  printf("{\"ok\":false,\"op\":\"");
  for (const char *p = op; *p; ++p) { if (*p == '"' || *p == '\\') putchar('\\'); putchar(*p); }
  printf("\",\"errno\":%d,\"error\":\"%s\"}\n", err, strerror(err));
}

static int parse_mac(const char *s, unsigned char out[6]) {
  unsigned int b[6];
  if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return -1;
  for (int i = 0; i < 6; ++i) { if (b[i] > 255) return -1; out[i] = (unsigned char)b[i]; }
  /* Keep generated MACs locally administered/unicast; callers can still pass exact physical-like values. */
  return 0;
}

static void print_mac_json(const unsigned char m[6]) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen) {
  size_t len = RTA_LENGTH(alen);
  size_t newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  if (newlen > maxlen) return -1;
  struct rtattr *rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = (unsigned short)len;
  if (alen) memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = (unsigned int)newlen;
  return 0;
}

static int nl_ack(int fd) {
  char buf[NL_BUFSZ];
  ssize_t n = recv(fd, buf, sizeof(buf), 0);
  if (n < 0) return -errno;
  for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
    if (h->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);
      return e->error;
    }
  }
  return 0;
}

static int set_if_updown(const char *ifname, int up, short *old_flags) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { int e = -errno; close(fd); return e; }
  if (old_flags) *old_flags = ifr.ifr_flags;
  if (up) ifr.ifr_flags |= IFF_UP;
  else ifr.ifr_flags &= (short)~IFF_UP;
  int rc = ioctl(fd, SIOCSIFFLAGS, &ifr) < 0 ? -errno : 0;
  close(fd);
  return rc;
}

static int restore_flags(const char *ifname, short flags) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
  ifr.ifr_flags = flags;
  int rc = ioctl(fd, SIOCSIFFLAGS, &ifr) < 0 ? -errno : 0;
  close(fd);
  return rc;
}

static int rtnl_set_mac(const char *ifname, const unsigned char mac[6]) {
  int ifindex = if_nametoindex(ifname);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  char reqbuf[512];
  memset(reqbuf, 0, sizeof(reqbuf));
  struct nlmsghdr *nlh = (struct nlmsghdr *)reqbuf;
  struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
  nlh->nlmsg_type = RTM_SETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = 0x58454e4f; /* XENO */
  ifi->ifi_family = AF_UNSPEC;
  ifi->ifi_index = ifindex;
  if (addattr_l(nlh, sizeof(reqbuf), IFLA_ADDRESS, mac, 6) < 0) { close(fd); return -EMSGSIZE; }
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(fd); return e; }
  int ack = nl_ack(fd);
  close(fd);
  return ack;
}

static int get_ioctl_mac(const char *ifname, unsigned char mac[6]) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
  int rc = ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ? -errno : 0;
  if (rc == 0) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
  close(fd);
  return rc;
}

static int get_netlink_mac(const char *ifname, unsigned char mac[6]) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  struct { struct nlmsghdr n; struct ifinfomsg i; } req;
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.n.nlmsg_type = RTM_GETLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.i.ifi_family = AF_PACKET;
  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(fd); return e; }
  char buf[NL_BUFSZ];
  ssize_t n = recv(fd, buf, sizeof(buf), 0);
  if (n < 0) { int e = -errno; close(fd); return e; }
  int rc = -ENODEV;
  for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
    if (h->nlmsg_type != RTM_NEWLINK) continue;
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(h);
    int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    char name[IFNAMSIZ] = {0};
    unsigned char found[6] = {0};
    int have_mac = 0;
    for (struct rtattr *r = IFLA_RTA(ifi); RTA_OK(r, alen); r = RTA_NEXT(r, alen)) {
      if (r->rta_type == IFLA_IFNAME) snprintf(name, sizeof(name), "%s", (char *)RTA_DATA(r));
      if (r->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(r) >= 6) { memcpy(found, RTA_DATA(r), 6); have_mac = 1; }
    }
    if (strcmp(name, ifname) == 0 && have_mac) { memcpy(mac, found, 6); rc = 0; break; }
  }
  close(fd);
  return rc;
}

static int rtnl_rename(const char *old_name, const char *new_name) {
  int ifindex = (int)if_nametoindex(old_name);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  char reqbuf[512];
  memset(reqbuf, 0, sizeof(reqbuf));
  struct nlmsghdr *nlh = (struct nlmsghdr *)reqbuf;
  struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi));
  nlh->nlmsg_type = RTM_SETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = 0x524d4e54; /* RMNT */
  ifi->ifi_family = AF_UNSPEC;
  ifi->ifi_index = ifindex;
  if (addattr_l(nlh, sizeof(reqbuf), IFLA_IFNAME, new_name, strlen(new_name) + 1) < 0) {
    close(fd); return -EMSGSIZE;
  }
  struct sockaddr_nl address;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  if (sendto(fd, nlh, nlh->nlmsg_len, 0,
             (struct sockaddr *)&address, sizeof(address)) < 0) {
    int error = -errno; close(fd); return error;
  }
  int result = nl_ack(fd);
  close(fd);
  return result;
}

static int get_link_snapshot(const char *ifname, int *ifindex, int *mtu,
                             short *flags, unsigned char mac[6]) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -errno;
  struct ifreq request;
  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", ifname);
  if (ioctl(fd, SIOCGIFINDEX, &request) < 0) { int error = -errno; close(fd); return error; }
  *ifindex = request.ifr_ifindex;
  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", ifname);
  if (ioctl(fd, SIOCGIFMTU, &request) < 0) { int error = -errno; close(fd); return error; }
  *mtu = request.ifr_mtu;
  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", ifname);
  if (ioctl(fd, SIOCGIFFLAGS, &request) < 0) { int error = -errno; close(fd); return error; }
  *flags = request.ifr_flags;
  memset(&request, 0, sizeof(request));
  snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", ifname);
  if (ioctl(fd, SIOCGIFHWADDR, &request) < 0) { int error = -errno; close(fd); return error; }
  memcpy(mac, request.ifr_hwaddr.sa_data, 6);
  close(fd);
  return 0;
}

static int count_interface_addresses(const char *ifname) {
  unsigned int ifindex = if_nametoindex(ifname);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  struct { struct nlmsghdr n; struct ifaddrmsg a; } request;
  memset(&request, 0, sizeof(request));
  request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.a));
  request.n.nlmsg_type = RTM_GETADDR;
  request.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.n.nlmsg_seq = 0x41444452; /* ADDR */
  request.a.ifa_family = AF_UNSPEC;
  struct sockaddr_nl address;
  memset(&address, 0, sizeof(address));
  address.nl_family = AF_NETLINK;
  if (sendto(fd, &request, request.n.nlmsg_len, 0,
             (struct sockaddr *)&address, sizeof(address)) < 0) {
    int error = -errno; close(fd); return error;
  }
  int count = 0;
  for (;;) {
    char buffer[NL_BUFSZ];
    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received < 0) { int error = -errno; close(fd); return error; }
    for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
         NLMSG_OK(header, received); header = NLMSG_NEXT(header, received)) {
      if (header->nlmsg_type == NLMSG_DONE) { close(fd); return count; }
      if (header->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(header);
        int result = error->error ? error->error : -EIO;
        close(fd); return result;
      }
      if (header->nlmsg_type != RTM_NEWADDR) continue;
      struct ifaddrmsg *item = (struct ifaddrmsg *)NLMSG_DATA(header);
      if (item->ifa_index == ifindex
          && (item->ifa_family == AF_INET || item->ifa_family == AF_INET6)) count++;
    }
  }
}

static int count_interface_routes(const char *path, const char *ifname) {
  FILE *stream = fopen(path, "re");
  if (!stream) return errno == ENOENT ? 0 : -errno;
  char line[1024];
  int count = 0;
  while (fgets(line, sizeof(line), stream)) {
    char *cursor = line;
    while ((cursor = strstr(cursor, ifname)) != NULL) {
      char before = cursor == line ? ' ' : cursor[-1];
      char after = cursor[strlen(ifname)];
      if ((before == ' ' || before == '\t') &&
          (after == ' ' || after == '\t' || after == '\n' || after == '\0')) count++;
      cursor += strlen(ifname);
    }
  }
  int failed = ferror(stream) ? -EIO : count;
  fclose(stream);
  return failed;
}

#define CONTROL_RULE_PRIORITY 999
#define MAX_CONNECTED_PREFIXES 8

struct connected_prefix {
  unsigned char family;
  unsigned char prefix_len;
  unsigned char address[16];
};

static void mask_prefix(unsigned char *address, size_t length, unsigned int prefix_len) {
  size_t whole = prefix_len / 8;
  unsigned int remainder = prefix_len % 8;
  if (whole < length && remainder) {
    address[whole] &= (unsigned char)(0xffU << (8 - remainder));
    whole++;
  }
  if (whole < length) memset(address + whole, 0, length - whole);
}

#define MAX_SNAPSHOT_ADDRESSES 8

struct network_snapshot_address {
  int family;
  unsigned char prefix_length;
  unsigned char address[16];
};

struct network_snapshot {
  struct network_snapshot_address addresses[MAX_SNAPSHOT_ADDRESSES];
  size_t address_count;
  unsigned char ipv4_gateway[4];
  unsigned char ipv6_gateway[16];
  int have_ipv4_gateway;
  int have_ipv6_gateway;
};

static int netmask_prefix_length(const struct sockaddr *mask, int family) {
  const unsigned char *bytes = NULL;
  size_t length = 0;
  if (family == AF_INET) {
    bytes = (const unsigned char *)&((const struct sockaddr_in *)mask)->sin_addr;
    length = 4;
  } else if (family == AF_INET6) {
    bytes = (const unsigned char *)&((const struct sockaddr_in6 *)mask)->sin6_addr;
    length = 16;
  } else {
    return -EINVAL;
  }
  int prefix = 0;
  int saw_zero = 0;
  for (size_t i = 0; i < length; ++i) {
    for (int bit = 7; bit >= 0; --bit) {
      int set = (bytes[i] >> bit) & 1;
      if (saw_zero && set) return -EINVAL;
      if (set) ++prefix;
      else saw_zero = 1;
    }
  }
  return prefix;
}

static int parse_hex_address(const char *text, size_t bytes, unsigned char *address) {
  if (!text || strlen(text) != bytes * 2) return -EINVAL;
  for (size_t i = 0; i < bytes; ++i) {
    unsigned int value = 0;
    if (sscanf(text + i * 2, "%2x", &value) != 1) return -EINVAL;
    address[i] = (unsigned char)value;
  }
  return 0;
}

static int capture_default_gateways(const char *ifname, struct network_snapshot *snapshot) {
  FILE *routes = fopen("/proc/net/route", "re");
  if (routes) {
    char line[512];
    (void)fgets(line, sizeof(line), routes);
    while (fgets(line, sizeof(line), routes)) {
      char iface[IFNAMSIZ] = {0};
      unsigned long destination = 0, gateway = 0;
      unsigned int flags = 0;
      if (sscanf(line, "%15s %lx %lx %x", iface, &destination, &gateway, &flags) == 4 &&
          strcmp(iface, ifname) == 0 && destination == 0 && (flags & RTF_GATEWAY)) {
        uint32_t encoded = (uint32_t)gateway;
        memcpy(snapshot->ipv4_gateway, &encoded, sizeof(encoded));
        snapshot->have_ipv4_gateway = 1;
        break;
      }
    }
    fclose(routes);
  }

  routes = fopen("/proc/net/ipv6_route", "re");
  if (routes) {
    char line[768];
    while (fgets(line, sizeof(line), routes)) {
      char destination[33] = {0}, source[33] = {0}, gateway[33] = {0}, iface[IFNAMSIZ] = {0};
      unsigned int destination_prefix = 0, source_prefix = 0, metric = 0, refcount = 0, use = 0, flags = 0;
      int matched = sscanf(line, "%32s %x %32s %x %32s %x %x %x %x %15s",
                           destination, &destination_prefix, source, &source_prefix, gateway,
                           &metric, &refcount, &use, &flags, iface);
      if (matched == 10 && strcmp(iface, ifname) == 0 && destination_prefix == 0 &&
          strcmp(destination, "00000000000000000000000000000000") == 0 &&
          strcmp(gateway, "00000000000000000000000000000000") != 0 &&
          parse_hex_address(gateway, 16, snapshot->ipv6_gateway) == 0) {
        snapshot->have_ipv6_gateway = 1;
        break;
      }
    }
    fclose(routes);
  }
  return snapshot->have_ipv4_gateway || snapshot->have_ipv6_gateway ? 0 : -ENETUNREACH;
}

static int capture_network_snapshot(const char *ifname, struct network_snapshot *snapshot) {
  memset(snapshot, 0, sizeof(*snapshot));
  int have_ipv4 = 0, have_ipv6 = 0;
  struct ifaddrs *addresses = NULL;
  if (getifaddrs(&addresses) < 0) return -errno;
  for (struct ifaddrs *item = addresses; item; item = item->ifa_next) {
    if (!item->ifa_addr || !item->ifa_netmask || strcmp(item->ifa_name, ifname)) continue;
    int family = item->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) continue;
    if (family == AF_INET6) {
      const struct in6_addr *address = &((const struct sockaddr_in6 *)item->ifa_addr)->sin6_addr;
      if (IN6_IS_ADDR_LINKLOCAL(address) || IN6_IS_ADDR_LOOPBACK(address) || IN6_IS_ADDR_MULTICAST(address)) continue;
    }
    if (snapshot->address_count >= MAX_SNAPSHOT_ADDRESSES) {
      freeifaddrs(addresses);
      return -E2BIG;
    }
    int prefix = netmask_prefix_length(item->ifa_netmask, family);
    if (prefix < 0) {
      freeifaddrs(addresses);
      return prefix;
    }
    struct network_snapshot_address *saved = &snapshot->addresses[snapshot->address_count++];
    saved->family = family;
    saved->prefix_length = (unsigned char)prefix;
    if (family == AF_INET) {
      memcpy(saved->address, &((const struct sockaddr_in *)item->ifa_addr)->sin_addr, 4);
      have_ipv4 = 1;
    } else {
      memcpy(saved->address, &((const struct sockaddr_in6 *)item->ifa_addr)->sin6_addr, 16);
      have_ipv6 = 1;
    }
  }
  freeifaddrs(addresses);
  int gateway_rc = capture_default_gateways(ifname, snapshot);
  if (!have_ipv4 || !have_ipv6) return -EADDRNOTAVAIL;
  if (!snapshot->have_ipv4_gateway || !snapshot->have_ipv6_gateway) return -ENETUNREACH;
  return gateway_rc;
}

static int restore_snapshot_address(const char *ifname, const struct network_snapshot_address *address) {
  int ifindex = if_nametoindex(ifname);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  char request[512];
  memset(request, 0, sizeof(request));
  struct nlmsghdr *header = (struct nlmsghdr *)request;
  struct ifaddrmsg *message = (struct ifaddrmsg *)NLMSG_DATA(header);
  header->nlmsg_len = NLMSG_LENGTH(sizeof(*message));
  header->nlmsg_type = RTM_NEWADDR;
  header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
  header->nlmsg_seq = 0x58454e41;
  message->ifa_family = (unsigned char)address->family;
  message->ifa_prefixlen = address->prefix_length;
  message->ifa_scope = RT_SCOPE_UNIVERSE;
  message->ifa_index = (unsigned int)ifindex;
  size_t length = address->family == AF_INET ? 4u : 16u;
  if (addattr_l(header, sizeof(request), IFA_ADDRESS, address->address, length) < 0 ||
      (address->family == AF_INET && addattr_l(header, sizeof(request), IFA_LOCAL, address->address, length) < 0)) {
    close(fd);
    return -EMSGSIZE;
  }
  struct sockaddr_nl peer;
  memset(&peer, 0, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  if (sendto(fd, header, header->nlmsg_len, 0, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
    int error = -errno;
    close(fd);
    return error;
  }
  int result = nl_ack(fd);
  close(fd);
  return result == -EEXIST ? 0 : result;
}

static int restore_default_route(const char *ifname, int family, const unsigned char *gateway) {
  int ifindex = if_nametoindex(ifname);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  char request[512];
  memset(request, 0, sizeof(request));
  struct nlmsghdr *header = (struct nlmsghdr *)request;
  struct rtmsg *message = (struct rtmsg *)NLMSG_DATA(header);
  header->nlmsg_len = NLMSG_LENGTH(sizeof(*message));
  header->nlmsg_type = RTM_NEWROUTE;
  header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
  header->nlmsg_seq = 0x58454e52;
  message->rtm_family = (unsigned char)family;
  message->rtm_table = RT_TABLE_MAIN;
  message->rtm_protocol = RTPROT_BOOT;
  message->rtm_scope = RT_SCOPE_UNIVERSE;
  message->rtm_type = RTN_UNICAST;
  size_t length = family == AF_INET ? 4u : 16u;
  if (addattr_l(header, sizeof(request), RTA_GATEWAY, gateway, length) < 0 ||
      addattr_l(header, sizeof(request), RTA_OIF, &ifindex, sizeof(ifindex)) < 0) {
    close(fd);
    return -EMSGSIZE;
  }
  struct sockaddr_nl peer;
  memset(&peer, 0, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  if (sendto(fd, header, header->nlmsg_len, 0, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
    int error = -errno;
    close(fd);
    return error;
  }
  int result = nl_ack(fd);
  close(fd);
  return result == -EEXIST ? 0 : result;
}

static void wake_gateway(const char *ifname, int family, const unsigned char *gateway) {
  int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return;
  (void)setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1);
  unsigned char byte = 0;
  if (family == AF_INET) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(9);
    memcpy(&target.sin_addr, gateway, 4);
    (void)sendto(fd, &byte, sizeof(byte), 0, (struct sockaddr *)&target, sizeof(target));
  } else {
    struct sockaddr_in6 target;
    memset(&target, 0, sizeof(target));
    target.sin6_family = AF_INET6;
    target.sin6_port = htons(9);
    target.sin6_scope_id = if_nametoindex(ifname);
    memcpy(&target.sin6_addr, gateway, 16);
    (void)sendto(fd, &byte, sizeof(byte), 0, (struct sockaddr *)&target, sizeof(target));
  }
  close(fd);
}

static int wait_for_boot_complete(void) {
  const struct timespec interval = {.tv_sec = 0, .tv_nsec = 100000000L};
  for (int attempt = 0; attempt < 3000; ++attempt) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get("sys.boot_completed", value) > 0 && !strcmp(value, "1")) return 0;
    nanosleep(&interval, NULL);
  }
  return -ETIMEDOUT;
}

static int connected_prefixes(const char *ifname, struct connected_prefix *prefixes,
                              size_t capacity, int *have_v4, int *have_v6,
                              int *have_global_v6) {
  unsigned int ifindex = if_nametoindex(ifname);
  if (!ifindex) return -ENODEV;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  struct { struct nlmsghdr n; struct ifaddrmsg a; } request;
  memset(&request, 0, sizeof(request));
  request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.a));
  request.n.nlmsg_type = RTM_GETADDR;
  request.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.n.nlmsg_seq = 0x52554c45; /* RULE */
  request.a.ifa_family = AF_UNSPEC;
  struct sockaddr_nl peer;
  memset(&peer, 0, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  if (sendto(fd, &request, request.n.nlmsg_len, 0,
             (struct sockaddr *)&peer, sizeof(peer)) < 0) {
    int error = -errno; close(fd); return error;
  }
  size_t count = 0;
  *have_v4 = 0;
  *have_v6 = 0;
  *have_global_v6 = 0;
  for (;;) {
    char buffer[NL_BUFSZ];
    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received < 0) { int error = -errno; close(fd); return error; }
    for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
         NLMSG_OK(header, received); header = NLMSG_NEXT(header, received)) {
      if (header->nlmsg_type == NLMSG_DONE) { close(fd); return (int)count; }
      if (header->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(header);
        int result = error->error ? error->error : -EIO;
        close(fd); return result;
      }
      if (header->nlmsg_type != RTM_NEWADDR) continue;
      struct ifaddrmsg *item = (struct ifaddrmsg *)NLMSG_DATA(header);
      if (item->ifa_index != ifindex
          || (item->ifa_family != AF_INET && item->ifa_family != AF_INET6)) continue;
      size_t address_length = item->ifa_family == AF_INET ? 4U : 16U;
      unsigned char address[16] = {0};
      int found = 0;
      int attributes_length = header->nlmsg_len - NLMSG_LENGTH(sizeof(*item));
      for (struct rtattr *attribute = IFA_RTA(item); RTA_OK(attribute, attributes_length);
           attribute = RTA_NEXT(attribute, attributes_length)) {
        if ((attribute->rta_type == IFA_LOCAL || (!found && attribute->rta_type == IFA_ADDRESS))
            && RTA_PAYLOAD(attribute) >= address_length) {
          memcpy(address, RTA_DATA(attribute), address_length);
          found = 1;
          if (attribute->rta_type == IFA_LOCAL) break;
        }
      }
      if (!found) continue;
      mask_prefix(address, address_length, item->ifa_prefixlen);
      int duplicate = 0;
      for (size_t index = 0; index < count; ++index) {
        if (prefixes[index].family == item->ifa_family
            && prefixes[index].prefix_len == item->ifa_prefixlen
            && memcmp(prefixes[index].address, address, address_length) == 0) {
          duplicate = 1;
          break;
        }
      }
      if (duplicate) continue;
      if (count >= capacity) { close(fd); return -E2BIG; }
      prefixes[count].family = item->ifa_family;
      prefixes[count].prefix_len = item->ifa_prefixlen;
      memcpy(prefixes[count].address, address, address_length);
      if (item->ifa_family == AF_INET) {
        *have_v4 = 1;
      } else {
        *have_v6 = 1;
        if (!(address[0] == 0xfe && (address[1] & 0xc0U) == 0x80U)) *have_global_v6 = 1;
      }
      count++;
    }
  }
}

static int update_control_rule(const struct connected_prefix *prefix, int add) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  char request_buffer[256];
  memset(request_buffer, 0, sizeof(request_buffer));
  struct nlmsghdr *header = (struct nlmsghdr *)request_buffer;
  struct fib_rule_hdr *rule = (struct fib_rule_hdr *)NLMSG_DATA(header);
  header->nlmsg_len = NLMSG_LENGTH(sizeof(*rule));
  header->nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
  header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (add) header->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  header->nlmsg_seq = 0x4354524c; /* CTRL */
  rule->family = prefix->family;
  rule->dst_len = prefix->prefix_len;
  rule->table = RT_TABLE_MAIN;
  rule->action = FR_ACT_TO_TBL;
  size_t address_length = prefix->family == AF_INET ? 4U : 16U;
  unsigned int priority = CONTROL_RULE_PRIORITY;
  if (addattr_l(header, sizeof(request_buffer), FRA_DST, prefix->address, address_length) < 0
      || addattr_l(header, sizeof(request_buffer), FRA_PRIORITY,
                   &priority, sizeof(priority)) < 0) {
    close(fd); return -EMSGSIZE;
  }
  struct sockaddr_nl peer;
  memset(&peer, 0, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  if (sendto(fd, header, header->nlmsg_len, 0,
             (struct sockaddr *)&peer, sizeof(peer)) < 0) {
    int error = -errno; close(fd); return error;
  }
  int result = nl_ack(fd);
  close(fd);
  if (add && result == -EEXIST) return 1;
  if (!add && result == -ENOENT) return 0;
  return result;
}

static int ensure_control_rules(const char *ifname, struct connected_prefix *added,
                                int *added_count, int *rule_count) {
  struct connected_prefix prefixes[MAX_CONNECTED_PREFIXES];
  memset(prefixes, 0, sizeof(prefixes));
  int have_v4 = 0, have_v6 = 0, have_global_v6 = 0;
  int count = connected_prefixes(ifname, prefixes, MAX_CONNECTED_PREFIXES,
                                 &have_v4, &have_v6, &have_global_v6);
  if (count < 0) return count;
  if (!have_v4 || !have_v6) return -EADDRNOTAVAIL;
  *added_count = 0;
  *rule_count = count;
  for (int index = 0; index < count; ++index) {
    int result = update_control_rule(&prefixes[index], 1);
    if (result < 0) {
      for (int rollback = *added_count - 1; rollback >= 0; --rollback)
        update_control_rule(&added[rollback], 0);
      *added_count = 0;
      return result;
    }
    if (result == 0) added[(*added_count)++] = prefixes[index];
  }
  return 0;
}

static void remove_control_rules(const struct connected_prefix *added, int added_count) {
  for (int index = added_count - 1; index >= 0; --index)
    update_control_rule(&added[index], 0);
}

static int rule_priority_exists(int family, unsigned int priority) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -errno;
  struct { struct nlmsghdr n; struct fib_rule_hdr rule; } request;
  memset(&request, 0, sizeof(request));
  request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.rule));
  request.n.nlmsg_type = RTM_GETRULE;
  request.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.n.nlmsg_seq = 0x52454144; /* READ */
  request.rule.family = family;
  struct sockaddr_nl peer;
  memset(&peer, 0, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  if (sendto(fd, &request, request.n.nlmsg_len, 0,
             (struct sockaddr *)&peer, sizeof(peer)) < 0) {
    int error = -errno; close(fd); return error;
  }
  for (;;) {
    char buffer[NL_BUFSZ];
    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received < 0) { int error = -errno; close(fd); return error; }
    for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
         NLMSG_OK(header, received); header = NLMSG_NEXT(header, received)) {
      if (header->nlmsg_type == NLMSG_DONE) { close(fd); return 0; }
      if (header->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(header);
        int result = error->error ? error->error : -EIO;
        close(fd); return result;
      }
      if (header->nlmsg_type != RTM_NEWRULE) continue;
      struct fib_rule_hdr *rule = (struct fib_rule_hdr *)NLMSG_DATA(header);
      if (rule->family != family) continue;
      int attributes_length = header->nlmsg_len - NLMSG_LENGTH(sizeof(*rule));
      struct rtattr *attribute = (struct rtattr *)
          ((char *)rule + NLMSG_ALIGN(sizeof(*rule)));
      for (; RTA_OK(attribute, attributes_length);
           attribute = RTA_NEXT(attribute, attributes_length)) {
        if (attribute->rta_type == FRA_PRIORITY
            && RTA_PAYLOAD(attribute) >= sizeof(unsigned int)
            && *(unsigned int *)RTA_DATA(attribute) == priority) {
          close(fd);
          return 1;
        }
      }
    }
  }
}

static int wait_for_cellular_addresses(const char *ifname) {
  const struct timespec interval = {.tv_sec = 0, .tv_nsec = 100000000L};
  for (int attempt = 0; attempt < 300; ++attempt) {
    struct connected_prefix prefixes[MAX_CONNECTED_PREFIXES];
    int have_v4 = 0, have_v6 = 0, have_global_v6 = 0;
    int count = connected_prefixes(ifname, prefixes, MAX_CONNECTED_PREFIXES,
                                   &have_v4, &have_v6, &have_global_v6);
    if (count < 0) return count;
    if (have_v4 && have_v6 && have_global_v6) return 0;
    nanosleep(&interval, NULL);
  }
  return -ETIMEDOUT;
}

static int wait_for_android_route_rules(void) {
  const struct timespec interval = {.tv_sec = 0, .tv_nsec = 100000000L};
  for (int attempt = 0; attempt < 300; ++attempt) {
    int v4 = rule_priority_exists(AF_INET, 32000U);
    int v6 = rule_priority_exists(AF_INET6, 32000U);
    if (v4 < 0) return v4;
    if (v6 < 0) return v6;
    if (v4 == 1 && v6 == 1) return 0;
    nanosleep(&interval, NULL);
  }
  return -ETIMEDOUT;
}

static int cmd_cellular_init(void) {
  const char *old_name = "eth0";
  const char *new_name = "rmnet_data0";
  unsigned int old_index = if_nametoindex(old_name);
  unsigned int new_index = if_nametoindex(new_name);
  if (!old_index && new_index) {
    struct connected_prefix added[MAX_CONNECTED_PREFIXES];
    int added_count = 0, rule_count = 0;
    int rules = ensure_control_rules(new_name, added, &added_count, &rule_count);
    if (rules != 0) {
      die_json("cellular-init-control-rules", -rules);
      return 1;
    }
    printf("{\"ok\":true,\"op\":\"cellular-init\",\"ifname\":\"%s\",\"ifindex\":%u,"
           "\"controlRules\":%d,\"idempotent\":true}\n",
           new_name, new_index, rule_count);
    return 0;
  }
  if (!old_index || new_index) {
    die_json("cellular-init-interface", old_index ? EEXIST : ENODEV);
    return 1;
  }
  int before_index = 0, before_mtu = 0;
  short before_flags = 0;
  unsigned char before_mac[6] = {0};
  int before_addresses = count_interface_addresses(old_name);
  int before_v4_routes = count_interface_routes("/proc/net/route", old_name);
  int before_v6_routes = count_interface_routes("/proc/net/ipv6_route", old_name);
  int snapshot = get_link_snapshot(old_name, &before_index, &before_mtu,
                                   &before_flags, before_mac);
  if (snapshot != 0 || before_addresses < 0 || before_v4_routes < 0 || before_v6_routes < 0) {
    die_json("cellular-init-snapshot", snapshot ? -snapshot : EIO);
    return 1;
  }
  short ignored_flags = 0;
  int down = set_if_updown(old_name, 0, &ignored_flags);
  if (down != 0) { die_json("cellular-init-down", -down); return 1; }
  int renamed = rtnl_rename(old_name, new_name);
  if (renamed != 0) {
    restore_flags(old_name, before_flags);
    die_json("cellular-init-rename", -renamed);
    return 1;
  }
  int restored = restore_flags(new_name, before_flags);
  struct connected_prefix added[MAX_CONNECTED_PREFIXES];
  int added_count = 0, rule_count = 0;
  int rules = restored == 0
      ? ensure_control_rules(new_name, added, &added_count, &rule_count)
      : restored;
  if (rules != 0) {
    remove_control_rules(added, added_count);
    short ignored_after_flags = 0;
    set_if_updown(new_name, 0, &ignored_after_flags);
    if (rtnl_rename(new_name, old_name) == 0) restore_flags(old_name, before_flags);
    die_json("cellular-init-control-rules", -rules);
    return 1;
  }
  int after_index = 0, after_mtu = 0;
  short after_flags = 0;
  unsigned char after_mac[6] = {0};
  int verify = get_link_snapshot(new_name, &after_index, &after_mtu,
                                 &after_flags, after_mac);
  int after_addresses = count_interface_addresses(new_name);
  int after_v4_routes = count_interface_routes("/proc/net/route", new_name);
  int after_v6_routes = count_interface_routes("/proc/net/ipv6_route", new_name);
  int ok = restored == 0 && verify == 0
      && if_nametoindex(old_name) == 0
      && before_index == after_index
      && before_mtu == after_mtu
      && before_flags == after_flags
      && memcmp(before_mac, after_mac, sizeof(before_mac)) == 0
      && before_addresses == after_addresses
      && before_v4_routes == after_v4_routes
      && before_v6_routes == after_v6_routes;
  printf("{\"ok\":%s,\"op\":\"cellular-init\",\"ifname\":\"%s\","
         "\"ifindex\":%d,\"mtu\":%d,\"addresses\":%d,"
         "\"ipv4Routes\":%d,\"ipv6Routes\":%d,\"controlRules\":%d,"
         "\"idempotent\":false}\n",
         ok ? "true" : "false", new_name, after_index, after_mtu,
         after_addresses, after_v4_routes, after_v6_routes, rule_count);
  return ok ? 0 : 1;
}

static int cmd_cellular_ready(void) {
  int ready = wait_for_android_route_rules();
  if (ready != 0) {
    die_json("cellular-ready-netd", -ready);
    return 1;
  }
  ready = wait_for_cellular_addresses("rmnet_data0");
  if (ready != 0) {
    die_json("cellular-ready-addresses", -ready);
    return 1;
  }
  return cmd_cellular_init();
}

static int cmd_status(const char *ifname) {
  unsigned char ioctl_mac[6] = {0}, nl_mac[6] = {0};
  int ri = get_ioctl_mac(ifname, ioctl_mac);
  int rn = get_netlink_mac(ifname, nl_mac);
  printf("{\"ok\":%s,\"ifname\":\"%s\",", (ri == 0 || rn == 0) ? "true" : "false", ifname);
  printf("\"ioctl\":");
  if (ri == 0) { printf("\""); print_mac_json(ioctl_mac); printf("\""); } else printf("null");
  printf(",\"netlink\":");
  if (rn == 0) { printf("\""); print_mac_json(nl_mac); printf("\""); } else printf("null");
  printf(",\"ioctlErrno\":%d,\"netlinkErrno\":%d}\n", ri < 0 ? -ri : 0, rn < 0 ? -rn : 0);
  return (ri == 0 || rn == 0) ? 0 : 1;
}

static int cmd_set_mac(const char *ifname, const char *mac_s) {
  unsigned char mac[6];
  if (parse_mac(mac_s, mac) != 0) { die_json("parse-mac", EINVAL); return 2; }
  short old_flags = 0;
  int down = set_if_updown(ifname, 0, &old_flags);
  int rc = rtnl_set_mac(ifname, mac);
  if (old_flags & IFF_UP) restore_flags(ifname, old_flags);
  if (rc != 0 && down == 0) {
    /* Some kernels reject RTM_SETLINK address mutations; SIOCSIFHWADDR is the same kernel layer fallback. */
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
      struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
      snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
      ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
      memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
      short old2 = 0; set_if_updown(ifname, 0, &old2);
      rc = ioctl(fd, SIOCSIFHWADDR, &ifr) < 0 ? -errno : 0;
      if (old2 & IFF_UP) restore_flags(ifname, old2);
      close(fd);
    }
  }
  unsigned char verify[6] = {0};
  int vr = get_netlink_mac(ifname, verify);
  int ok = rc == 0 && vr == 0 && memcmp(verify, mac, 6) == 0;
  printf("{\"ok\":%s,\"op\":\"set-mac\",\"ifname\":\"%s\",\"requested\":\"", ok ? "true" : "false", ifname);
  print_mac_json(mac);
  printf("\",\"netlinkAfter\":");
  if (vr == 0) { printf("\""); print_mac_json(verify); printf("\""); } else printf("null");
  printf(",\"rtnlErrno\":%d,\"downErrno\":%d,\"verifyErrno\":%d}\n", rc < 0 ? -rc : 0, down < 0 ? -down : 0, vr < 0 ? -vr : 0);
  return ok ? 0 : 1;
}

static int cmd_cellular_watch(void) {
  const char *ifname = "rmnet_data0";
  const struct timespec interval = {.tv_sec = 0, .tv_nsec = 100000000L};
  struct network_snapshot snapshot;
  int captured = -EADDRNOTAVAIL;
  for (int attempt = 0; attempt < 300; ++attempt) {
    int initialized = cmd_cellular_init();
    if (initialized == 0) captured = capture_network_snapshot(ifname, &snapshot);
    if (initialized == 0 && captured == 0) break;
    nanosleep(&interval, NULL);
  }
  if (captured != 0) {
    die_json("cellular-watch-snapshot", -captured);
    return 1;
  }
  int booted = wait_for_boot_complete();
  if (booted != 0) {
    die_json("cellular-watch-boot", -booted);
    return 1;
  }
  int stable = 0, restore_error = -EAGAIN;
  for (int attempt = 0; attempt < 300 && stable < 30; ++attempt) {
    restore_error = 0;
    for (size_t i = 0; i < snapshot.address_count; ++i) {
      int restored = restore_snapshot_address(ifname, &snapshot.addresses[i]);
      if (restored != 0) { restore_error = restored; break; }
    }
    struct connected_prefix added[MAX_CONNECTED_PREFIXES];
    memset(added, 0, sizeof(added));
    int added_count = 0, rule_count = 0;
    if (restore_error == 0) {
      restore_error = ensure_control_rules(ifname, added, &added_count, &rule_count);
    }
    if (restore_error == 0 && snapshot.have_ipv4_gateway) {
      restore_error = restore_default_route(ifname, AF_INET, snapshot.ipv4_gateway);
    }
    if (restore_error == 0 && snapshot.have_ipv6_gateway) {
      restore_error = restore_default_route(ifname, AF_INET6, snapshot.ipv6_gateway);
    }
    if (restore_error == 0) ++stable;
    else stable = 0;
    if (stable < 30) nanosleep(&interval, NULL);
  }
  if (stable < 30) {
    die_json("cellular-watch-restore", -restore_error);
    return 1;
  }
  if (snapshot.have_ipv4_gateway) wake_gateway(ifname, AF_INET, snapshot.ipv4_gateway);
  if (snapshot.have_ipv6_gateway) wake_gateway(ifname, AF_INET6, snapshot.ipv6_gateway);
  printf("{\"ok\":true,\"op\":\"cellular-watch\",\"ifname\":\"%s\",\"addresses\":%zu}\n",
         ifname, snapshot.address_count);
  return 0;
}

static void usage(const char *argv0) {
  fprintf(stderr, "usage: %s cellular-init\n       %s cellular-ready\n       %s cellular-watch\n       %s status [ifname]\n       %s set-mac <ifname> <xx:xx:xx:xx:xx:xx>\n", argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "cellular-init") == 0) return cmd_cellular_init();
  if (argc == 2 && strcmp(argv[1], "cellular-ready") == 0) return cmd_cellular_ready();
  if (argc == 2 && strcmp(argv[1], "cellular-watch") == 0) return cmd_cellular_watch();
  if (argc >= 2 && strcmp(argv[1], "status") == 0) return cmd_status(argc >= 3 ? argv[2] : "rmnet_data0");
  if (argc == 4 && strcmp(argv[1], "set-mac") == 0) return cmd_set_mac(argv[2], argv[3]);
  usage(argv[0]);
  return 2;
}
