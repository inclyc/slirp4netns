/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"

#include "child.h"
#include "slirp4netns.h"
#include "sockfd.h"
#include "syscall.h"

// C++ standard
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// glibc
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/sched.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <regex.h>
#include <sched.h>
#include <unistd.h>

static int parent(int sock, struct slirp4netns_config *cfg) {
  char str[INET6_ADDRSTRLEN];
  int rc;
  int tapfd;
  struct in_addr vdhcp_end = {
#define NB_BOOTP_CLIENTS 16
      /* NB_BOOTP_CLIENTS is hard-coded to 16 in libslirp:
         https://gitlab.freedesktop.org/slirp/libslirp/-/issues/49 */
      .s_addr = htonl(ntohl(cfg->vdhcp_start.s_addr) + NB_BOOTP_CLIENTS - 1),
#undef NB_BOOTP_CLIENTS
  };
  if ((tapfd = recvfd(sock)) < 0) {
    return tapfd;
  }
  fprintf(stderr, "received tapfd=%d\n", tapfd);
  close(sock);
  printf("Starting slirp\n");
  printf("* MTU:             %d\n", cfg->mtu);
  printf("* Network:         %s\n",
         inet_ntop(AF_INET, &cfg->vnetwork, str, sizeof(str)));
  printf("* Netmask:         %s\n",
         inet_ntop(AF_INET, &cfg->vnetmask, str, sizeof(str)));
  printf("* Gateway:         %s\n",
         inet_ntop(AF_INET, &cfg->vhost, str, sizeof(str)));
  printf("* DNS:             %s\n",
         inet_ntop(AF_INET, &cfg->vnameserver, str, sizeof(str)));
  printf("* DHCP begin:      %s\n",
         inet_ntop(AF_INET, &cfg->vdhcp_start, str, sizeof(str)));
  printf("* DHCP end:        %s\n",
         inet_ntop(AF_INET, &vdhcp_end, str, sizeof(str)));
  printf("* Recommended IP:  %s\n",
         inet_ntop(AF_INET, &cfg->recommended_vguest, str, sizeof(str)));
#if SLIRP_CONFIG_VERSION_MAX >= 2
  if (cfg->enable_outbound_addr) {
    printf("* Outbound IPv4:    %s\n",
           inet_ntop(AF_INET, &cfg->outbound_addr.sin_addr, str, sizeof(str)));
  }
  if (cfg->enable_outbound_addr6) {
    if (inet_ntop(AF_INET6, &cfg->outbound_addr6.sin6_addr, str, sizeof(str))) {
      printf("* Outbound IPv6:    %s\n", str);
    }
  }
#endif
  if (cfg->vmacaddress_len > 0) {
    auto *mac = (unsigned char *)cfg->vmacaddress.sa_data;
    printf("* MAC address:     %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
  }
  if (!cfg->disable_host_loopback) {
    printf("WARNING: 127.0.0.1:* on the host is accessible as %s (set "
           "--disable-host-loopback to prohibit connecting to 127.0.0.1:*)\n",
           inet_ntop(AF_INET, &cfg->vhost, str, sizeof(str)));
  }
  for (auto &[from, to] : cfg->port_forwards) {
    printf("* Port forward:    %d -> %d\n", from, to);
  }
  if ((rc = do_slirp(tapfd, cfg)) < 0) {
    fprintf(stderr, "do_slirp failed\n");
    close(tapfd);
    return rc;
  }
  /* NOT REACHED */
  return 0;
}

static void check_child(int child_wstatus) {
  if (!WIFEXITED(child_wstatus)) [[unlikely]] {
    fprintf(stderr, "child failed(wstatus=%d, !WIFEXITED)\n", child_wstatus);
    std::exit(EXIT_FAILURE);
  }
  int child_status = WEXITSTATUS(child_wstatus);
  if (child_status != 0) [[unlikely]] {
    fprintf(stderr, "child failed(%d)\n", child_status);
    std::exit(EXIT_FAILURE);
  }
}

#define error_return(...)                                                      \
  {                                                                            \
    fprintf(stderr, __VA_ARGS__);                                              \
    return -1;                                                                 \
  }

int do_clone(int target_pid, int &pidfd, pid_t &child_pid) {
  if (target_pid == -1) {
    // Create a new network namespace, instead of using target_pid.
    clone_args cl_args{
        .flags = CLONE_NEWNET | CLONE_PIDFD,
        .pidfd = reinterpret_cast<uintptr_t>(&pidfd),
        .exit_signal = SIGCHLD,
    };
    child_pid = clone3(&cl_args);
  } else {
    child_pid = fork();
  }

  if (child_pid < 0) [[unlikely]]
    return child_pid;

  if (target_pid != -1) {
    if (pidfd = pidfd_open(target_pid, 0); pidfd < 0) [[unlikely]]
      return pidfd;
  }
  return 0;
}

int parse_args(int argc, char *argv[], int &target_pid, int &index,
               slirp4netns_config &config) {
  target_pid = -1;
  index = -1;
  for (int i = 0; i < argc; i++) {
    std::string arg(argv[i]);
    if (arg == "--target-pid") {
      if (++i == argc)
        error_return("missing argument\n");
      target_pid = std::stoi(argv[i]);
    } else if (arg == "--") {
      if (++i == argc)
        error_return("missing argument\n");
      index = i;
      break;
    } else if (arg == "-p") {
      int from;
      int to;
      if (++i == argc)
        error_return("missing argument\n");
      from = std::stoi(argv[i]);
      if (++i == argc)
        error_return("missing argument\n");
      to = std::stoi(argv[i]);
      config.port_forwards.emplace_back(from, to);
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  int target_pid;
  int index;
  slirp4netns_config slirp4netns_config{
      .mtu = 1500,
      .vnetwork = {htonl(0x0A000200)},
      .vnetmask = {htonl(0xFFFFFF00)},
      .vhost = {htonl(0x0A000202)},
      .vdhcp_start = {htonl(0x0A00020F)},
      .vnameserver = {htonl(0x0A000203)},
      .recommended_vguest = {htonl(0x0A000264)},
      .disable_host_loopback = true,
  };
  if (parse_args(argc, argv, target_pid, index, slirp4netns_config) < 0)
    return EXIT_FAILURE;

  int sv[2];
  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) [[unlikely]] {
    perror("socketpair");
    return EXIT_FAILURE;
  }

  pid_t child_pid;
  int pidfd;
  if (do_clone(target_pid, pidfd, child_pid) < 0) {
    perror("do_clone");
    return EXIT_FAILURE;
  }

  if (child_pid == 0) {
    // child
    int ret = child(sv[1], pidfd, "tap0", &slirp4netns_config);
    if (ret < 0)
      return EXIT_FAILURE;
    if (target_pid == -1) {
      pid_t pid = fork();
      if (pid < 0)
        return EXIT_FAILURE;
      if (pid == 0) {
        if (index < 0)
          execlp("bash", "bash");
        execvp(*(argv + index), argv + index);
      }
    }
    return 0;
  }

  // parent
  int ret;
  int child_wstatus;
  do
    ret = waitpid(child_pid, &child_wstatus, 0);
  while (ret < 0 && errno == EINTR);
  if (ret < 0) [[unlikely]] {
    perror("waitpid");
    return EXIT_FAILURE;
  }
  check_child(child_wstatus);
  if (parent(sv[0], &slirp4netns_config) < 0) {
    fprintf(stderr, "parent failed\n");
    return EXIT_FAILURE;
  }
  return 0;
}
