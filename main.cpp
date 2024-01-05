/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"

#include "child.h"
#include "slirp4netns.h"
#include "sockfd.h"
#include "syscall.h"

// C++ standard
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// glibc
#include <arpa/inet.h>
#include <linux/if_tun.h>
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

#define DEFAULT_MTU (1500)
#define DEFAULT_CIDR ("10.0.2.0/24")
#define DEFAULT_VHOST_OFFSET (2)                // 10.0.2.2
#define DEFAULT_VDHCPSTART_OFFSET (15)          // 10.0.2.15
#define DEFAULT_VNAMESERVER_OFFSET (3)          // 10.0.2.3
#define DEFAULT_RECOMMENDED_VGUEST_OFFSET (100) // 10.0.2.100
#define DEFAULT_NETNS_TYPE ("pid")
#define DEFAULT_TARGET_TYPE ("netns")
#define NETWORK_PREFIX_MIN (1)
// >=26 is not supported because the recommended guest IP is set to network addr
// + 100 .
#define NETWORK_PREFIX_MAX (25)

static int parent(int sock, int ready_fd, int exit_fd, const char *api_socket,
                  struct slirp4netns_config *cfg,
                  pid_t target_pid [[gnu::unused]]) {
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
  if (api_socket) {
    printf("* API Socket:      %s\n", api_socket);
  }
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
  if ((rc = do_slirp(tapfd, ready_fd, exit_fd, api_socket, cfg)) < 0) {
    fprintf(stderr, "do_slirp failed\n");
    close(tapfd);
    return rc;
  }
  /* NOT REACHED */
  return 0;
}

static void usage(const char *argv0) {
  printf("Usage: %s [OPTION]... PID|PATH [TAPNAME]\n", argv0);
  printf("User-mode networking for unprivileged network namespaces.\n\n");
  printf("-c, --configure          bring up the interface\n");
  printf("-e, --exit-fd=FD         specify the FD for terminating "
         "slirp4netns\n");
  printf("-r, --ready-fd=FD        specify the FD to write to when the "
         "network is configured\n");
  /* v0.2.0 */
  printf("-m, --mtu=MTU            specify MTU (default=%d, max=65521)\n",
         DEFAULT_MTU);
  printf("-6, --enable-ipv6        enable IPv6 (experimental)\n");
  /* v0.3.0 */
  printf("-a, --api-socket=PATH    specify API socket path\n");
  printf("--cidr=CIDR              specify network address CIDR (default=%s)\n",
         DEFAULT_CIDR);
  printf("--disable-host-loopback  prohibit connecting to 127.0.0.1:* on the "
         "host namespace\n");
  /* v0.4.0 */
  printf("--netns-type=TYPE 	 specify network namespace type ([path|pid], "
         "default=%s)\n",
         DEFAULT_NETNS_TYPE);
  printf("--userns-path=PATH	 specify user namespace path\n");
  /* v1.1.0 */
#if SLIRP_CONFIG_VERSION_MAX >= 2
  printf("--outbound-addr=IPv4     sets outbound ipv4 address to bound to "
         "(experimental)\n");
  printf("--outbound-addr6=IPv6    sets outbound ipv6 address to bound to "
         "(experimental)\n");
#endif
#if SLIRP_CONFIG_VERSION_MAX >= 3
  printf("--disable-dns            disables 10.0.2.3 (or configured internal "
         "ip) to host dns redirect (experimental)\n");
#endif
  /* v1.1.9 */
  printf("--macaddress=MAC         specify the MAC address of the TAP (only "
         "valid with -c)\n");
  /* v1.2.0 */
  printf("--target-type=TYPE       specify the target type ([netns|bess], "
         "default=%s)\n",
         DEFAULT_TARGET_TYPE);
  /* others */
  printf("-h, --help               show this help and exit\n");
  printf("-v, --version            show version and exit\n");
}

// version output is runc-compatible and machine-parsable
static void version() {
  printf("slirp4netns version %s\n", VERSION ? VERSION : PACKAGE_VERSION);
#ifdef COMMIT
  printf("commit: %s\n", COMMIT);
#endif
  printf("libslirp: %s\n", slirp_version_string());
  printf("SLIRP_CONFIG_VERSION_MAX: %d\n", SLIRP_CONFIG_VERSION_MAX);
}

struct options {
  char *tapname;              // argv[2]
  char *cidr;                 // --cidr
  char *api_socket;           // -a
  char *netns_type;           // argv[1]
  char *netns_path;           // --netns-path
  char *userns_path;          // --userns-path
  char *outbound_addr;        // --outbound-addr
  char *outbound_addr6;       // --outbound-addr6
  pid_t target_pid;           // argv[1]
  int exit_fd;                // -e
  int ready_fd;               // -r
  unsigned int mtu;           // -m
  bool do_config_network;     // -c
  bool disable_host_loopback; // --disable-host-loopback
  bool enable_ipv6;           // -6
  bool disable_dns;           // --disable-dns
  char *macaddress;           // --macaddress
  char *target_type;          // --target-type
};

static void options_init(struct options *options) {
  memset(options, 0, sizeof(*options));
  options->exit_fd = options->ready_fd = -1;
  options->mtu = DEFAULT_MTU;
}

static void options_destroy(struct options *options) {
  if (options->tapname) {
    free(options->tapname);
    options->tapname = nullptr;
  }
  if (options->cidr) {
    free(options->cidr);
    options->cidr = nullptr;
  }
  if (options->api_socket) {
    free(options->api_socket);
    options->api_socket = nullptr;
  }
  if (options->netns_type) {
    free(options->netns_type);
    options->netns_type = nullptr;
  }
  if (options->netns_path) {
    free(options->netns_path);
    options->netns_path = nullptr;
  }
  if (options->userns_path) {
    free(options->userns_path);
    options->userns_path = nullptr;
  }
  if (options->outbound_addr) {
    free(options->outbound_addr);
    options->outbound_addr = nullptr;
  }
  if (options->outbound_addr6) {
    free(options->outbound_addr6);
    options->outbound_addr6 = nullptr;
  }
  if (options->macaddress) {
    free(options->macaddress);
    options->macaddress = nullptr;
  }
  if (options->target_type) {
    free(options->target_type);
    options->target_type = nullptr;
  }
}

// * caller does not need to call options_init()
// * caller needs to call options_destroy() after calling this function.
// * this function calls exit() on an error.
static void parse_args(int argc, char *const argv[], struct options *options) {
  int opt;
  char *strtol_e = nullptr;
  char *optarg_cidr = nullptr;
  char *optarg_netns_type = nullptr;
  char *optarg_userns_path = nullptr;
  char *optarg_api_socket = nullptr;
  char *optarg_outbound_addr = nullptr;
  char *optarg_outbound_addr6 = nullptr;
  char *optarg_macaddress = nullptr;
  char *optarg_target_type = nullptr;
#define CIDR (-42)
#define DISABLE_HOST_LOOPBACK (-43)
#define NETNS_TYPE (-44)
#define USERNS_PATH (-45)
#define OUTBOUND_ADDR (-48)
#define OUTBOUND_ADDR6 (-49)
#define DISABLE_DNS (-50)
#define MACADDRESS (-51)
#define TARGET_TYPE (-52)
#define DEPRECATED_NO_HOST_LOOPBACK                                            \
  (-10043) // deprecated in favor of disable-host-loopback
#define DEPRECATED_CREATE_SANDBOX                                              \
  (-10044) // deprecated in favor of enable-sandbox
  const struct option longopts[] = {
      {"configure", no_argument, nullptr, 'c'},
      {"exit-fd", required_argument, nullptr, 'e'},
      {"ready-fd", required_argument, nullptr, 'r'},
      {"mtu", required_argument, nullptr, 'm'},
      {"cidr", required_argument, nullptr, CIDR},
      {"disable-host-loopback", no_argument, nullptr, DISABLE_HOST_LOOPBACK},
      {"no-host-loopback", no_argument, nullptr, DEPRECATED_NO_HOST_LOOPBACK},
      {"netns-type", required_argument, nullptr, NETNS_TYPE},
      {"userns-path", required_argument, nullptr, USERNS_PATH},
      {"api-socket", required_argument, nullptr, 'a'},
      {"enable-ipv6", no_argument, nullptr, '6'},
      {"help", no_argument, nullptr, 'h'},
      {"version", no_argument, nullptr, 'v'},
      {"outbound-addr", required_argument, nullptr, OUTBOUND_ADDR},
      {"outbound-addr6", required_argument, nullptr, OUTBOUND_ADDR6},
      {"disable-dns", no_argument, nullptr, DISABLE_DNS},
      {"macaddress", required_argument, nullptr, MACADDRESS},
      {"target-type", required_argument, nullptr, TARGET_TYPE},
      {nullptr, 0, nullptr, 0},
  };
  options_init(options);
  /* NOTE: clang-tidy hates strdup(optarg) in the while loop (#112) */
  while ((opt = getopt_long(argc, argv, "ce:r:m:a:6hv", longopts, nullptr)) !=
         -1) {
    switch (opt) {
    case 'c':
      options->do_config_network = true;
      break;
    case 'e':
      errno = 0;
      options->exit_fd = strtol(optarg, &strtol_e, 10);
      if (errno || *strtol_e != '\0' || options->exit_fd < 0) {
        fprintf(stderr, "exit-fd must be a non-negative integer\n");
        goto error;
      }
      break;
    case 'r':
      errno = 0;
      options->ready_fd = strtol(optarg, &strtol_e, 10);
      if (errno || *strtol_e != '\0' || options->ready_fd < 0) {
        fprintf(stderr, "ready-fd must be a non-negative integer\n");
        goto error;
      }
      break;
    case 'm':
      errno = 0;
      options->mtu = strtol(optarg, &strtol_e, 10);
      if (errno || *strtol_e != '\0' || options->mtu <= 0 ||
          options->mtu > 65521) {
        fprintf(stderr, "MTU must be a positive integer (< 65522)\n");
        goto error;
      }
      break;
    case CIDR:
      optarg_cidr = optarg;
      break;
    case DEPRECATED_NO_HOST_LOOPBACK:
      // There was no tagged release with support for --no-host-loopback.
      // So no one will be affected by removal of --no-host-loopback.
      printf("WARNING: --no-host-loopback is deprecated and will be "
             "removed in future releases, please use "
             "--disable-host-loopback instead.\n");
      /* FALLTHROUGH */
    case DISABLE_HOST_LOOPBACK:
      options->disable_host_loopback = true;
      break;
    case NETNS_TYPE:
      optarg_netns_type = optarg;
      break;
    case USERNS_PATH:
      optarg_userns_path = optarg;
      if (access(optarg_userns_path, F_OK) == -1) {
        fprintf(stderr, "userns path doesn't exist: %s\n", optarg_userns_path);
        goto error;
      }
      break;
    case 'a':
      optarg_api_socket = optarg;
      break;
    case '6':
      options->enable_ipv6 = true;
      printf("WARNING: Support for IPv6 is experimental\n");
      break;
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
      break;
    case 'v':
      version();
      exit(EXIT_SUCCESS);
      break;
    case OUTBOUND_ADDR:
      printf("WARNING: Support for --outbound-addr is experimental\n");
      optarg_outbound_addr = optarg;
      break;
    case OUTBOUND_ADDR6:
      printf("WARNING: Support for --outbound-addr6 is experimental\n");
      optarg_outbound_addr6 = optarg;
      break;
    case DISABLE_DNS:
      options->disable_dns = true;
      break;
    case MACADDRESS:
      optarg_macaddress = optarg;
      break;
    case TARGET_TYPE:
      optarg_target_type = optarg;
      break;
    default:
      goto error;
      break;
    }
  }
  if (optarg_cidr) {
    options->cidr = strdup(optarg_cidr);
  }
  if (optarg_netns_type) {
    options->netns_type = strdup(optarg_netns_type);
  }
  if (optarg_userns_path) {
    options->userns_path = strdup(optarg_userns_path);
  }
  if (optarg_api_socket) {
    options->api_socket = strdup(optarg_api_socket);
  }
  if (optarg_outbound_addr) {
    options->outbound_addr = strdup(optarg_outbound_addr);
  }
  if (optarg_outbound_addr6) {
    options->outbound_addr6 = strdup(optarg_outbound_addr6);
  }
  if (optarg_macaddress) {
    if (!options->do_config_network) {
      fprintf(stderr, "--macaddr cannot be specified when --configure or "
                      "-c is not specified\n");
      goto error;
    } else {
      options->macaddress = strdup(optarg_macaddress);
    }
  }
  if (optarg_target_type) {
    options->target_type = strdup(optarg_target_type);
  }
#undef CIDR
#undef DISABLE_HOST_LOOPBACK
#undef NETNS_TYPE
#undef USERNS_PATH
#undef _DEPRECATED_NO_HOST_LOOPBACK
#undef ENABLE_SANDBOX
#undef ENABLE_SECCOMP
#undef OUTBOUND_ADDR
#undef OUTBOUND_ADDR6
#undef DISABLE_DNS
#undef MACADDRESS
#undef TARGET_TYPE

  /* NetNS mode*/
  if (options->target_type && strcmp(options->target_type, "netns") != 0) {
    fprintf(stderr, "--target-type must be either \"netns\" or \"bess\"\n");
    goto error;
  }
  if (argc - optind < 2) {
    goto error;
  }
  if (argc - optind > 2) {
    // not an error, for preventing potential compatibility issue
    printf("WARNING: too many arguments\n");
  }
  if (!options->netns_type ||
      strcmp(options->netns_type, DEFAULT_NETNS_TYPE) == 0) {
    errno = 0;
    options->target_pid = strtol(argv[optind], &strtol_e, 10);
    if (errno || *strtol_e != '\0' || options->target_pid <= 0) {
      fprintf(stderr, "PID must be a positive integer\n");
      goto error;
    }
  } else {
    options->netns_path = strdup(argv[optind]);
    if (access(options->netns_path, F_OK) == -1) {
      perror("existing path expected when --netns-type=path");
      goto error;
    }
  }
  options->tapname = strdup(argv[optind + 1]);
  return;
error:
  usage(argv[0]);
  options_destroy(options);
  exit(EXIT_FAILURE);
}

static int from_regmatch(char *buf, size_t buf_len, regmatch_t match,
                         const char *orig) {
  size_t len = match.rm_eo - match.rm_so;
  if (len > buf_len - 1) {
    return -1;
  }
  memset(buf, 0, buf_len);
  strncpy(buf, &orig[match.rm_so], len);
  return 0;
}

static int parse_cidr(struct in_addr *network, struct in_addr *netmask,
                      const char *cidr) {
  int rc = 0;
  regex_t r;
  regmatch_t matches[4];
  size_t nmatch = sizeof(matches) / sizeof(matches[0]);
  const char *cidr_regex = "^(([0-9]{1,3}\\.){3}[0-9]{1,3})/([0-9]{1,2})$";
  char snetwork[16];
  char sprefix[16];
  int prefix;
  rc = regcomp(&r, cidr_regex, REG_EXTENDED);
  if (rc != 0) {
    fprintf(stderr, "internal regex error\n");
    rc = -1;
    goto finish;
  }
  rc = regexec(&r, cidr, nmatch, matches, 0);
  if (rc != 0) {
    fprintf(stderr, "invalid CIDR: %s\n", cidr);
    rc = -1;
    goto finish;
  }
  rc = from_regmatch(snetwork, sizeof(snetwork), matches[1], cidr);
  if (rc < 0) {
    fprintf(stderr, "invalid CIDR: %s\n", cidr);
    goto finish;
  }
  rc = from_regmatch(sprefix, sizeof(sprefix), matches[3], cidr);
  if (rc < 0) {
    fprintf(stderr, "invalid CIDR: %s\n", cidr);
    goto finish;
  }
  if (inet_pton(AF_INET, snetwork, network) != 1) {
    fprintf(stderr, "invalid network address: %s\n", snetwork);
    rc = -1;
    goto finish;
  }
  errno = 0;
  prefix = strtoul(sprefix, nullptr, 10);
  if (errno) {
    fprintf(stderr, "invalid prefix length: %s\n", sprefix);
    rc = -1;
    goto finish;
  }
  if (prefix < NETWORK_PREFIX_MIN || prefix > NETWORK_PREFIX_MAX) {
    fprintf(stderr, "prefix length needs to be %d-%d\n", NETWORK_PREFIX_MIN,
            NETWORK_PREFIX_MAX);
    rc = -1;
    goto finish;
  }
  netmask->s_addr = htonl(~((1 << (32 - prefix)) - 1));
  if ((network->s_addr & netmask->s_addr) != network->s_addr) {
    fprintf(stderr, "CIDR needs to be a network address like 10.0.2.0/24, "
                    "not like 10.0.2.100/24\n");
    rc = -1;
    goto finish;
  }
finish:
  regfree(&r);
  return rc;
}

static int slirp4netns_config_from_cidr(struct slirp4netns_config *cfg,
                                        const char *cidr) {
  int rc;
  rc = parse_cidr(&cfg->vnetwork, &cfg->vnetmask, cidr);
  if (rc < 0) {
    goto finish;
  }
  cfg->vhost.s_addr = htonl(ntohl(cfg->vnetwork.s_addr) + DEFAULT_VHOST_OFFSET);
  cfg->vdhcp_start.s_addr =
      htonl(ntohl(cfg->vnetwork.s_addr) + DEFAULT_VDHCPSTART_OFFSET);
  cfg->vnameserver.s_addr =
      htonl(ntohl(cfg->vnetwork.s_addr) + DEFAULT_VNAMESERVER_OFFSET);
  cfg->recommended_vguest.s_addr =
      htonl(ntohl(cfg->vnetwork.s_addr) + DEFAULT_RECOMMENDED_VGUEST_OFFSET);
finish:
  return rc;
}

static int get_interface_addr(const char *interface, int af, void *addr) {
  struct ifaddrs *ifaddr;
  struct ifaddrs *ifa;
  if (!interface)
    return -1;

  if (getifaddrs(&ifaddr) == -1) {
    fprintf(stderr, "getifaddrs failed to obtain interface addresses");
    return -1;
  }

  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || !ifa->ifa_name)
      continue;
    if (ifa->ifa_addr->sa_family == af) {
      if (strcmp(ifa->ifa_name, interface) == 0) {
        if (af == AF_INET) {
          *(struct in_addr *)addr =
              ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        } else {
          *(struct in6_addr *)addr =
              ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
        }
        return 0;
      }
    }
  }
  return -1;
}

/*
 * Convert a MAC string (macaddr) to bytes (data).
 * macaddr must be a null-terminated string in the format of
 * xx:xx:xx:xx:xx:xx.  The data buffer needs to be at least 6 bytes.
 * Typically the data is put into sockaddr sa_data, which is 14 bytes.
 */
static int slirp4netns_macaddr_hexstring_to_data(char *macaddr, char *data) {
  int temp;
  char *macaddr_ptr;
  char *data_ptr;
  for (macaddr_ptr = macaddr, data_ptr = data;
       macaddr_ptr && data_ptr < data + 6;
       macaddr_ptr = strchr(macaddr_ptr, ':'), data_ptr++) {
    if (macaddr_ptr != macaddr) {
      macaddr_ptr++; // advance over the :
    }
    if (sscanf(macaddr_ptr, "%x", &temp) != 1 || temp < 0 || temp > 255) {
      fprintf(stderr, "\"%s\" is an invalid MAC address.\n", macaddr);
      return -1;
    }
    *data_ptr = temp;
  }
  if (macaddr_ptr) {
    fprintf(stderr, "\"%s\" is an invalid MAC address.  Is it too long?\n",
            macaddr);
    return -1;
  }
  return (int)(data_ptr - data);
}

static int slirp4netns_config_from_options(struct slirp4netns_config *cfg,
                                           struct options *opt) {
  int rc = 0;
  cfg->mtu = opt->mtu;
  rc = slirp4netns_config_from_cidr(cfg, !opt->cidr ? DEFAULT_CIDR : opt->cidr);
  if (rc < 0) {
    return rc;
  }
  cfg->enable_ipv6 = opt->enable_ipv6;
  cfg->disable_host_loopback = opt->disable_host_loopback;
  cfg->enable_outbound_addr = false;
  cfg->enable_outbound_addr6 = false;

  if (opt->outbound_addr) {
    cfg->outbound_addr.sin_family = AF_INET;
    cfg->outbound_addr.sin_port = 0; // Any local port will do
    if (inet_pton(AF_INET, opt->outbound_addr, &cfg->outbound_addr.sin_addr) ==
        1) {
      cfg->enable_outbound_addr = true;
    } else {
      if (get_interface_addr(opt->outbound_addr, AF_INET,
                             &cfg->outbound_addr.sin_addr) != 0) {
        fprintf(stderr, "outbound-addr has to be valid ipv4 address or "
                        "interface name.");
        return -1;
      }
      cfg->enable_outbound_addr = true;
    }
    fprintf(stderr, "slirp4netns has to be compiled against libslrip 4.2.0 "
                    "or newer for --outbound-addr support.");
    return -1;
  }
  if (opt->outbound_addr6) {
#if SLIRP_CONFIG_VERSION_MAX >= 2
    cfg->outbound_addr6.sin6_family = AF_INET6;
    cfg->outbound_addr6.sin6_port = 0; // Any local port will do
    if (inet_pton(AF_INET6, opt->outbound_addr6,
                  &cfg->outbound_addr6.sin6_addr) == 1) {
      cfg->enable_outbound_addr6 = true;
    } else {
      if (get_interface_addr(opt->outbound_addr, AF_INET6,
                             &cfg->outbound_addr6.sin6_addr) != 0) {
        fprintf(stderr, "outbound-addr has to be valid ipv4 address or "
                        "iterface name.");
        rc = -1;
        goto finish;
      }
      cfg->enable_outbound_addr6 = true;
    }
#else
    fprintf(stderr, "slirp4netns has to be compiled against libslirp 4.2.0 "
                    "or newer for --outbound-addr6 support.");
    rc = -1;
    goto finish;
#endif
  }

#if SLIRP_CONFIG_VERSION_MAX >= 3
  cfg->disable_dns = opt->disable_dns;
#else
  if (opt->disable_dns) {
    fprintf(stderr, "slirp4netns has to be compiled against libslirp 4.3.0 "
                    "or newer for --disable-dns support.");
    rc = -1;
    goto finish;
  }
#endif

  cfg->vmacaddress_len = 0;
  memset(&cfg->vmacaddress, 0, sizeof(cfg->vmacaddress));
  if (opt->macaddress) {
    cfg->vmacaddress.sa_family = AF_LOCAL;
    int macaddr_len;
    if ((macaddr_len = slirp4netns_macaddr_hexstring_to_data(
             opt->macaddress, cfg->vmacaddress.sa_data)) < 0) {
      fprintf(stderr, "macaddress has to be a valid MAC address (hex "
                      "string, 6 bytes, each byte separated by a ':').");
      rc = -1;
      goto finish;
    }
    cfg->vmacaddress_len = macaddr_len;
  }
finish:
  return rc;
}

int main(int argc, char *const argv[]) {
  options options [[gnu::cleanup(options_destroy)]];
  slirp4netns_config slirp4netns_config;

  parse_args(argc, argv, &options);
  if (slirp4netns_config_from_options(&slirp4netns_config, &options) < 0) {
    return EXIT_FAILURE;
  }

  int sv[2];
  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) [[unlikely]] {
    perror("socketpair");
    return EXIT_FAILURE;
  }

  pid_t child_pid;
  if (child_pid = fork(); child_pid < 0) {
    perror("fork");
    return EXIT_FAILURE;
  }

  if (child_pid == 0) {
    if (int pidfd = pidfd_open(options.target_pid, 0); pidfd < 0) [[unlikely]] {
      fprintf(stderr, "no such process: pid %d\n", options.target_pid);
      return EXIT_FAILURE;
    } else {
      int ret = child(sv[1], pidfd, options.tapname, &slirp4netns_config);
      if (ret < 0)
        return EXIT_FAILURE;
    }
  } else {
    int ret;
    int child_wstatus;
    int child_status;
    do
      ret = waitpid(child_pid, &child_wstatus, 0);
    while (ret < 0 && errno == EINTR);
    if (ret < 0) [[unlikely]] {
      perror("waitpid");
      return EXIT_FAILURE;
    }
    if (!WIFEXITED(child_wstatus)) [[unlikely]] {
      fprintf(stderr, "child failed(wstatus=%d, !WIFEXITED)\n", child_wstatus);
      return EXIT_FAILURE;
    }
    child_status = WEXITSTATUS(child_wstatus);
    if (child_status != 0) [[unlikely]] {
      fprintf(stderr, "child failed(%d)\n", child_status);
      return child_status;
    }
    if (parent(sv[0], options.ready_fd, options.exit_fd, options.api_socket,
               &slirp4netns_config, options.target_pid) < 0) {
      fprintf(stderr, "parent failed\n");
      return EXIT_FAILURE;
    }
  }
  return 0;
}
