/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"

#include "child.h"
#include "cleanup.h"
#include "sockfd.h"

// C++ standard
#include <cstdio>
#include <cstring>

// glibc
#include <linux/if_tun.h>

#include <net/if.h>
#include <net/route.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

static int open_tap(const char *tapname) {
  int fd;
  if (!tapname) {
    fprintf(stderr, "tapname is NULL\n");
    return -1;
  }
  if (fd = open("/dev/net/tun", O_RDWR); fd < 0) {
    perror("open(\"/dev/net/tun\")");
    return fd;
  }
  ifreq ifr{};
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, tapname, sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return -1;
  }
  return fd;
}

static int configure_network(const char *tapname,
                             struct slirp4netns_config *cfg) {
  struct rtentry route;
  struct ifreq ifr;
  auto *sai = (struct sockaddr_in *)&ifr.ifr_addr;
  int sockfd;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("cannot create socket");
    return -1;
  }

  // set loopback device to UP
  ifreq ifr_lo = {.ifr_name = "lo", .ifr_flags = IFF_UP | IFF_RUNNING};
  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr_lo) < 0) {
    perror("cannot set device up");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_UP | IFF_RUNNING;
  strncpy(ifr.ifr_name, tapname, sizeof(ifr.ifr_name) - 1);

  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
    perror("cannot set device up");
    return -1;
  }

  ifr.ifr_mtu = (int)cfg->mtu;
  if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
    perror("cannot set MTU");
    return -1;
  }

  if (cfg->vmacaddress_len > 0) {
    ifr.ifr_ifru.ifru_hwaddr = cfg->vmacaddress;
    if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
      perror("cannot set MAC address");
      return -1;
    }
  }

  sai->sin_family = AF_INET;
  sai->sin_port = 0;
  sai->sin_addr = cfg->recommended_vguest;

  if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
    perror("cannot set device address");
    return -1;
  }

  sai->sin_addr = cfg->vnetmask;
  if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
    perror("cannot set device netmask");
    return -1;
  }

  memset(&route, 0, sizeof(route));
  sai = (struct sockaddr_in *)&route.rt_gateway;
  sai->sin_family = AF_INET;
  sai->sin_addr = cfg->vhost;
  sai = (struct sockaddr_in *)&route.rt_dst;
  sai->sin_family = AF_INET;
  sai->sin_addr.s_addr = INADDR_ANY;
  sai = (struct sockaddr_in *)&route.rt_genmask;
  sai->sin_family = AF_INET;
  sai->sin_addr.s_addr = INADDR_ANY;

  route.rt_flags = RTF_UP | RTF_GATEWAY;
  route.rt_metric = 0;
  route.rt_dev = (char *)tapname;

  if (ioctl(sockfd, SIOCADDRT, &route) < 0) {
    perror("set route");
    return -1;
  }
  return 0;
}

int child(int _sock, int pidfd, const char *tapname,
          struct slirp4netns_config *cfg) {
  int tapfd [[gnu::cleanup(cleanup_fd)]] = FD_CLOSED;
  int sock [[gnu::cleanup(cleanup_fd)]] = _sock;
  setns(pidfd, CLONE_NEWUSER | CLONE_NEWNET);
  if (tapfd = open_tap(tapname); tapfd < 0) {
    return tapfd;
  }
  if (configure_network(tapname, cfg) < 0) {
    return -1;
  }
  if (int err = sendfd(sock, tapfd); err < 0) {
    return -1;
  }
  fprintf(stderr, "sent tapfd=%d for %s\n", tapfd, tapname);
  return 0;
}
