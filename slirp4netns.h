/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SLIRP4NETNS_H
#define SLIRP4NETNS_H
#include <arpa/inet.h>

// libslirp
#include <libslirp.h>

struct slirp4netns_config {
  unsigned int mtu;
  struct in_addr vnetwork;    // 10.0.2.0
  struct in_addr vnetmask;    // 255.255.255.0
  struct in_addr vhost;       // 10.0.2.2
  struct in_addr vdhcp_start; // 10.0.2.15
  struct in_addr vnameserver; // 10.0.2.3
  struct in_addr
      recommended_vguest; // 10.0.2.100 (slirp itself is unaware of vguest)
  bool enable_ipv6;
  bool disable_host_loopback;
  bool enable_outbound_addr;
  struct sockaddr_in outbound_addr;
  bool enable_outbound_addr6;
  struct sockaddr_in6 outbound_addr6;
  bool disable_dns;
  struct sockaddr vmacaddress; // MAC address of interface
  int vmacaddress_len;         // MAC address byte length
};
int do_slirp(int tapfd, struct slirp4netns_config *cfg);

#endif
