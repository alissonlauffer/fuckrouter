#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/ipv6.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFLEN 8192
#define IPV6_PREFIX_LEN 64

volatile sig_atomic_t keep_running = 1;

void check_root(void) {
  if (geteuid() != 0) {
    fprintf(stderr, "This tool must be run as root.\n");
    exit(EXIT_FAILURE);
  }
}

void sig_handler(int signo) {
  if (signo == SIGINT) {
    printf("\nReceived SIGINT. Shutting down...\n");
    keep_running = 0;
  }
}

int send_netlink_command(int sock, struct nlmsghdr *nlh,
                         struct sockaddr_nl *sa) {
  struct iovec iov = {nlh, nlh->nlmsg_len};
  struct msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};
  return sendmsg(sock, &msg, 0);
}

int delete_ipv6_address(const char *interface, const char *ipv6_address) {
  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  struct {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
    char buf[256];
  } req = {0};

  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.nlh.nlmsg_flags = NLM_F_REQUEST;
  req.nlh.nlmsg_type = RTM_DELADDR;

  req.ifa.ifa_family = AF_INET6;
  req.ifa.ifa_prefixlen = IPV6_PREFIX_LEN;
  req.ifa.ifa_index = if_nametoindex(interface);

  struct rtattr *rta =
      (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH(16);

  inet_pton(AF_INET6, ipv6_address, RTA_DATA(rta));
  req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta->rta_len;

  struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
  if (send_netlink_command(sock, &req.nlh, &sa) < 0) {
    perror("send_netlink_command");
    close(sock);
    return -1;
  }

  close(sock);
  printf("Deleted IPv6 address: %s\n", ipv6_address);
  return 0;
}

int is_ipv6_address_assigned(const char *interface, const char *prefix) {
  struct ifaddrs *ifap, *ifa;
  char ipv6_str[INET6_ADDRSTRLEN];
  int assigned = 0;

  if (getifaddrs(&ifap) == -1) {
    perror("getifaddrs");
    return -1;
  }

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6 &&
        strcmp(ifa->ifa_name, interface) == 0) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6_str, sizeof(ipv6_str));
      if (strcmp(ipv6_str, prefix) == 0) {
        assigned = 1;
        break;
      }
    }
  }

  freeifaddrs(ifap);
  return assigned;
}

int assign_ipv6_address(const char *interface, const char *prefix) {
  if (is_ipv6_address_assigned(interface, prefix)) {
    printf("IPv6 address %s is already assigned to %s\n", prefix, interface);
    return 0;
  }

  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  struct in6_ifreq ifr6 = {0};
  if (inet_pton(AF_INET6, prefix, &ifr6.ifr6_addr) <= 0) {
    perror("inet_pton");
    close(sock);
    return -1;
  }

  ifr6.ifr6_ifindex = if_nametoindex(interface);
  ifr6.ifr6_prefixlen = IPV6_PREFIX_LEN;

  if (ioctl(sock, SIOCSIFADDR, &ifr6) < 0) {
    perror("ioctl(SIOCSIFADDR)");
    close(sock);
    return -1;
  }

  close(sock);
  printf("Assigned IPv6 address: %s\n", prefix);
  return 0;
}

int is_public_ipv6(const char *ipv6) {
  struct in6_addr addr;
  inet_pton(AF_INET6, ipv6, &addr);
  return (ntohl(addr.s6_addr32[0]) & 0xe0000000) == 0x20000000;
}

void process_ipv6_address(const char *interface, const char *ipv6_str) {
  if (is_public_ipv6(ipv6_str) &&
      (strcmp(ipv6_str + strlen(ipv6_str) - 3, "::1") != 0)) {
    printf("Invalid IPv6 address %s found. Deleting and assigning a new one.\n",
           ipv6_str);

    delete_ipv6_address(interface, ipv6_str);

    char new_prefix[INET6_ADDRSTRLEN];
    strncpy(new_prefix, ipv6_str, sizeof(new_prefix) - 1);
    new_prefix[sizeof(new_prefix) - 1] = '\0';
    char *fourth_colon = strchr(
        strchr(strchr(strchr(new_prefix, ':') + 1, ':') + 1, ':') + 1, ':');
    if (fourth_colon) {
      strcpy(fourth_colon + 1, ":1");
    }
    assign_ipv6_address(interface, new_prefix);
  }
}

int main(int argc, char *argv[]) {
  check_root();

  if (signal(SIGINT, sig_handler) == SIG_ERR) {
    perror("Unable to set up signal handler");
    exit(EXIT_FAILURE);
  }

  const char *interface = "enp4s0";

  struct ifaddrs *ifap, *ifa;
  char ipv6_str[INET6_ADDRSTRLEN];

  if (getifaddrs(&ifap) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6 &&
        strcmp(ifa->ifa_name, interface) == 0) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6_str, sizeof(ipv6_str));
      process_ipv6_address(interface, ipv6_str);
    }
  }

  freeifaddrs(ifap);

  int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_sock < 0) {
    perror("Failed to create netlink socket");
    exit(EXIT_FAILURE);
  }

  int flags = fcntl(nl_sock, F_GETFL, 0);
  fcntl(nl_sock, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_nl addr = {0};
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_IPV6_IFADDR;

  if (bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("Failed to bind to netlink socket");
    close(nl_sock);
    exit(EXIT_FAILURE);
  }

  printf("Monitoring IPv6 address changes. Press Ctrl+C to exit.\n");

  while (keep_running) {
    char buf[BUFLEN];
    int len = recv(nl_sock, buf, sizeof(buf), 0);
    if (len < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        usleep(100000);
        continue;
      }
      perror("Error receiving netlink message");
      continue;
    }

    struct nlmsghdr *nh;
    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
      if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
        struct ifaddrmsg *ifa = NLMSG_DATA(nh);
        struct rtattr *rth = IFA_RTA(ifa);
        int rtl = IFA_PAYLOAD(nh);

        char if_name[IF_NAMESIZE] = {0};
        if_indextoname(ifa->ifa_index, if_name);

        if (strcmp(if_name, interface) == 0) {
          for (; RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
            if (rth->rta_type == IFA_ADDRESS) {
              char ipv6_str[INET6_ADDRSTRLEN];
              inet_ntop(AF_INET6, RTA_DATA(rth), ipv6_str, sizeof(ipv6_str));
              process_ipv6_address(interface, ipv6_str);
            }
          }
        }
      }
    }
  }

  close(nl_sock);
  printf("Program terminated.\n");
  return 0;
}
