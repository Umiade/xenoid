#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

static void usage(const char *argv0) {
  fprintf(stderr, "usage: %s status [ifname]\n       %s set-mac <ifname> <xx:xx:xx:xx:xx:xx>\n", argv0, argv0);
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "status") == 0) return cmd_status(argc >= 3 ? argv[2] : "eth0");
  if (argc == 4 && strcmp(argv[1], "set-mac") == 0) return cmd_set_mac(argv[2], argv[3]);
  usage(argv[0]);
  return 2;
}
