#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/ipv6.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFLEN 8192

// Helper function to check if running as root
void check_root() {
  if (geteuid() != 0) {
    fprintf(stderr, "This tool must be run as root.\n");
    exit(1);
  }
}

// Helper function to run netlink commands
int send_netlink_command(int sock, struct nlmsghdr *nlh,
                         struct sockaddr_nl *sa) {
  struct iovec iov = {nlh, nlh->nlmsg_len};
  struct msghdr msg = {sa, sizeof(*sa), &iov, 1, NULL, 0, 0};
  return sendmsg(sock, &msg, 0);
}

// Helper function to delete IPv6 address
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
  } req;

  memset(&req, 0, sizeof(req));

  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.nlh.nlmsg_flags = NLM_F_REQUEST;
  req.nlh.nlmsg_type = RTM_DELADDR;

  req.ifa.ifa_family = AF_INET6;
  req.ifa.ifa_prefixlen = 64; // Assuming /64 prefix
  req.ifa.ifa_index = if_nametoindex(interface);

  struct rtattr *rta =
      (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH(16); // IPv6 address length

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

// Helper function to assign new IPv6 address
int assign_ipv6_address(const char *interface, const char *prefix) {
  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  struct in6_ifreq ifr6;
  memset(&ifr6, 0, sizeof(ifr6));
  if (inet_pton(AF_INET6, prefix, &ifr6.ifr6_addr) <= 0) {
    perror("inet_pton");
    close(sock);
    return -1;
  }

  ifr6.ifr6_ifindex = if_nametoindex(interface);
  ifr6.ifr6_prefixlen = 64; // Set prefix length to 64

  if (ioctl(sock, SIOCSIFADDR, &ifr6) < 0) {
    perror("ioctl(SIOCSIFADDR)");
    close(sock);
    return -1;
  }

  close(sock);
  printf("Assigned IPv6 address: %s\n", prefix);
  return 0;
}

// Check if the address is public IPv6 (in 2000::/3 range)
int is_public_ipv6(const char *ipv6) {
  struct in6_addr addr;
  inet_pton(AF_INET6, ipv6, &addr);
  return (ntohl(addr.s6_addr32[0]) & 0xe0000000) == 0x20000000;
}

// Main function to retrieve, filter, and modify IPv6 addresses
int main(int argc, char *argv[]) {
  check_root();

  const char *interface = "enp4s0";
  struct ifaddrs *ifap, *ifa;
  char ipv6_str[INET6_ADDRSTRLEN];

  if (getifaddrs(&ifap) == -1) {
    perror("getifaddrs");
    exit(1);
  }

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6 &&
        strcmp(ifa->ifa_name, interface) == 0) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, ipv6_str, sizeof(ipv6_str));

      // Check if it's a public IPv6 and does not end with ::1 or has a wrong
      // prefix length
      if (is_public_ipv6(ipv6_str) &&
          (strcmp(ipv6_str + strlen(ipv6_str) - 3, "::1") != 0)) {
        printf("Invalid IPv6 address %s found. Deleting and assigning a new "
               "one.\n",
               ipv6_str);

        // Delete the incorrect IPv6 address
        delete_ipv6_address(interface, ipv6_str);

        // Assign a new address with ::1 ending and /64 prefix
        char new_prefix[INET6_ADDRSTRLEN];
        strncpy(new_prefix, ipv6_str,
                strlen(ipv6_str)); // Copy the entire address
        char *fourth_colon = strchr(
            strchr(strchr(strchr(new_prefix, ':') + 1, ':') + 1, ':') + 1, ':');
        if (fourth_colon) {
          strcpy(fourth_colon + 1,
                 ":1"); // Replace everything after the fourth colon with ":1"
        }
        assign_ipv6_address(interface, new_prefix);
      }
    }
  }

  freeifaddrs(ifap);
  return 0;
}
