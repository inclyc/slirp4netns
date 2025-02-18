/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <glib.h>
#include <libslirp.h>

#include "slirp4netns.h"

/* opaque for SlirpCb */
struct libslirp_data {
    int tapfd;
    GSList *timers;
};

/* implements SlirpCb.send_packet */
static ssize_t libslirp_send_packet(const void *pkt, size_t pkt_len,
                                    void *opaque)
{
    auto *data = (struct libslirp_data *)opaque;
    return write(data->tapfd, pkt, pkt_len);
}

/* implements SlirpCb.guest_error */
static void libslirp_guest_error(const char *msg, void *opaque [[gnu::unused]])
{
    fprintf(stderr, "libslirp: %s\n", msg);
}

/* implements SlirpCb.clock_get_ns */
static int64_t libslirp_clock_get_ns(void *opaque [[gnu::unused]])
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* timer for SlirpCb */
struct timer {
    SlirpTimerCb cb;
    void *cb_opaque;
    int64_t expire_timer_msec;
};

/* implements SlirpCb.timer_new */
static void *libslirp_timer_new(SlirpTimerCb cb, void *cb_opaque, void *opaque)
{
    auto *data = (libslirp_data *)opaque;
    auto *t = static_cast<timer *>(g_malloc0(sizeof(timer)));
    t->cb = cb;
    t->cb_opaque = cb_opaque;
    t->expire_timer_msec = -1;
    data->timers = g_slist_append(data->timers, t);
    return t;
}

/* implements SlirpCb.timer_free */
static void libslirp_timer_free(void *timer, void *opaque)
{
    auto *data = (libslirp_data *)opaque;
    data->timers = g_slist_remove(data->timers, timer);
    g_free(timer);
}

/* implements SlirpCb.timer_mod */
static void libslirp_timer_mod(void *timer, int64_t expire_timer_msec,
                               void *opaque [[gnu::unused]])
{
    auto *t = (struct timer *)timer;
    t->expire_timer_msec = expire_timer_msec;
}

/* implements SlirpCb.register_poll_fd */
static void libslirp_register_poll_fd(int fd [[gnu::unused]],
                                      void *opaque [[gnu::unused]])
{
    /*
     * NOP
     *
     * This is NOP on QEMU@4c76137484878f42a2ce1ae1b888b6a7f66b4053 on Linux as
     * well, see:
     *  * qemu/net/slirp.c:          net_slirp_register_poll_fd (calls
     * qemu_fd_register)
     *  * qemu/stubs/fd-register.c:  qemu_fd_register (NOP on Linux)
     *
     *  See also:
     *  * qemu/util/main-loop.c:     qemu_fd_register (Win32 only)
     */
}

/* implements SlirpCb.unregister_poll_fd */
static void libslirp_unregister_poll_fd(int fd [[gnu::unused]],
                                        void *opaque [[gnu::unused]])
{
    /*
     * NOP
     *
     * This is NOP on QEMU@4c76137484878f42a2ce1ae1b888b6a7f66b4053 as well,
     * see:
     *  * qemu/net/slirp.c:          net_slirp_unregister_poll_fd (NOP)
     */
}

/* implements SlirpCb.notify */
static void libslirp_notify(void *opaque [[gnu::unused]])
{
    /*
     * NOP
     *
     * This can be NOP on QEMU@4c76137484878f42a2ce1ae1b888b6a7f66b4053 as well,
     * see:
     *  * qemu/net/slirp.c:          net_slirp_notify (calls qemu_notify_event)
     *  * qemu/stubs/notify-event.c: qemu_notify_event (NOP)
     *
     *  See also:
     *  * qemu/util/main-loop.c:     qemu_notify_event (NOP if
     * !qemu_aio_context)
     */
}

static int libslirp_poll_to_gio(int events)
{
    int ret = 0;
    if (events & SLIRP_POLL_IN) {
        ret |= G_IO_IN;
    }
    if (events & SLIRP_POLL_OUT) {
        ret |= G_IO_OUT;
    }
    if (events & SLIRP_POLL_PRI) {
        ret |= G_IO_PRI;
    }
    if (events & SLIRP_POLL_ERR) {
        ret |= G_IO_ERR;
    }
    if (events & SLIRP_POLL_HUP) {
        ret |= G_IO_HUP;
    }
    return ret;
}

/*
 * implements SlirpAddPollCb used in slirp_pollfds_fill.
 * originally from qemu/net/slirp.c:net_slirp_add_poll
 * (4c76137484878f42a2ce1ae1b888b6a7f66b4053)
 */
static int libslirp_add_poll(int fd, int events, void *opaque)
{
    auto *pollfds = (GArray *)(opaque);
    GPollFD pfd = {
        .fd = fd,
        .events = (ushort)libslirp_poll_to_gio(events),
    };
    int idx = pollfds->len;
    g_array_append_val(pollfds, pfd);
    return idx;
}

static int libslirp_gio_to_poll(int events)
{
    int ret = 0;
    if (events & G_IO_IN) {
        ret |= SLIRP_POLL_IN;
    }
    if (events & G_IO_OUT) {
        ret |= SLIRP_POLL_OUT;
    }
    if (events & G_IO_PRI) {
        ret |= SLIRP_POLL_PRI;
    }
    if (events & G_IO_ERR) {
        ret |= SLIRP_POLL_ERR;
    }
    if (events & G_IO_HUP) {
        ret |= SLIRP_POLL_HUP;
    }
    return ret;
}

/*
 * implements SlirpGetREventsCB used in slirp_pollfds_poll
 * originally from qemu/net/slirp.c:net_slirp_get_revents
 * (4c76137484878f42a2ce1ae1b888b6a7f66b4053)
 */
static int libslirp_get_revents(int idx, void *opaque)
{
    auto *pollfds = (GArray *)(opaque);
    return libslirp_gio_to_poll(g_array_index(pollfds, GPollFD, idx).revents);
}

/*
 * updates timeout_msec for data->timers
 * originally from
 * https://github.com/rd235/libslirp/blob/d2b7032e29f3ba98e17414b32c9effffc90f2bb0/src/qemu2libslirp.c#L66
 */
static void update_ra_timeout(uint32_t *timeout_msec,
                              struct libslirp_data *data)
{
    int64_t now_msec = libslirp_clock_get_ns(data) / 1000000;
    GSList *f;
    for (f = data->timers; f != nullptr; f = f->next) {
        auto *t = (timer *)f->data;
        if (t->expire_timer_msec != -1) {
            int64_t diff = t->expire_timer_msec - now_msec;
            if (diff < 0)
                diff = 0;
            if (diff < *timeout_msec)
                *timeout_msec = diff;
        }
    }
}

/*
 * calls SlirpTimerCb if timed out
 * originally from
 * https://github.com/rd235/libslirp/blob/d2b7032e29f3ba98e17414b32c9effffc90f2bb0/src/qemu2libslirp.c#L78
 */
static void check_ra_timeout(struct libslirp_data *data)
{
    int64_t now_msec = libslirp_clock_get_ns(data) / 1000000;
    GSList *f;
    for (f = data->timers; f; f = f->next) {
        auto *t = static_cast<struct timer *>(f->data);
        if (t->expire_timer_msec != -1) {
            int64_t diff = t->expire_timer_msec - now_msec;
            if (diff <= 0) {
                t->expire_timer_msec = -1;
                t->cb(t->cb_opaque);
            }
        }
    }
}

static const SlirpCb libslirp_cb = {
    .send_packet = libslirp_send_packet,
    .guest_error = libslirp_guest_error,
    .clock_get_ns = libslirp_clock_get_ns,
    .timer_new = libslirp_timer_new,
    .timer_free = libslirp_timer_free,
    .timer_mod = libslirp_timer_mod,
    .register_poll_fd = libslirp_register_poll_fd,
    .unregister_poll_fd = libslirp_unregister_poll_fd,
    .notify = libslirp_notify,
};

Slirp *create_slirp(void *opaque, struct slirp4netns_config *s4nn)
{
    Slirp *slirp = nullptr;
    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 1;
    cfg.restricted = 0;
    cfg.in_enabled = true;
    cfg.vnetwork = s4nn->vnetwork;
    cfg.vnetmask = s4nn->vnetmask;
    cfg.vhost = s4nn->vhost;
    cfg.in6_enabled = (int)(s4nn->enable_ipv6);
    inet_pton(AF_INET6, "fd00::", &cfg.vprefix_addr6);
    cfg.vprefix_len = 64;
    inet_pton(AF_INET6, "fd00::2", &cfg.vhost6);
    cfg.vhostname = nullptr;
    cfg.tftp_server_name = nullptr;
    cfg.tftp_path = nullptr;
    cfg.bootfile = nullptr;
    cfg.vdhcp_start = s4nn->vdhcp_start;
    cfg.vnameserver = s4nn->vnameserver;
    inet_pton(AF_INET6, "fd00::3", &cfg.vnameserver6);
    cfg.vdnssearch = nullptr;
    cfg.vdomainname = nullptr;
    cfg.if_mtu = s4nn->mtu;
    cfg.if_mru = s4nn->mtu;
    cfg.disable_host_loopback = s4nn->disable_host_loopback;
#if SLIRP_CONFIG_VERSION_MAX >= 2
    cfg.outbound_addr = nullptr;
    cfg.outbound_addr6 = nullptr;
    if (s4nn->enable_outbound_addr) {
        cfg.version = 2;
        cfg.outbound_addr = &s4nn->outbound_addr;
    }
    if (s4nn->enable_outbound_addr6) {
        cfg.version = 2;
        cfg.outbound_addr6 = &s4nn->outbound_addr6;
    }
#endif
#if SLIRP_CONFIG_VERSION_MAX >= 3
    if (s4nn->disable_dns) {
        cfg.version = 3;
        cfg.disable_dns = true;
    }
#endif
    slirp = slirp_new(&cfg, &libslirp_cb, opaque);
    if (!slirp) {
        fprintf(stderr, "slirp_new failed\n");
    }
    return slirp;
}

#define ETH_BUF_SIZE (65536)

int do_slirp(int tapfd, struct slirp4netns_config *cfg) {
    int ret = -1;
    Slirp *slirp = nullptr;
    uint8_t *buf = nullptr;
    struct libslirp_data opaque = { .tapfd = tapfd, .timers = nullptr };
    GArray *pollfds = g_array_new(FALSE, FALSE, sizeof(GPollFD));
    int pollfds_exitfd_idx = -1;
    size_t n_fds = 1;
    GPollFD tap_pollfd = {
        .fd = tapfd, .events = G_IO_IN | G_IO_HUP, .revents = 0};
    slirp = create_slirp((void *)&opaque, cfg);
    if (!slirp) {
        fprintf(stderr, "create_slirp failed\n");
        goto err;
    }
    buf = (unsigned char *)malloc(ETH_BUF_SIZE);
    if (!buf) {
        goto err;
    }
    g_array_append_val(pollfds, tap_pollfd);
    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int pollout;
        GPollFD *pollfds_data;
        uint32_t timeout = -1; /* msec */
        g_array_set_size(pollfds, n_fds);
        slirp_pollfds_fill(slirp, &timeout, libslirp_add_poll, pollfds);
        update_ra_timeout(&timeout, &opaque);
        pollfds_data = (GPollFD *)pollfds->data;
        do {
            pollout = g_poll(pollfds_data, pollfds->len, timeout);
        } while (pollout < 0 && errno == EINTR);
        if (pollout < 0) {
            goto err;
        }

        if (pollfds_data[0].revents) {
            ssize_t rc = read(tapfd, buf, ETH_BUF_SIZE);
            if (rc < 0) {
                perror("do_slirp: read");
                goto after_slirp_input;
            }
            slirp_input(slirp, buf, (int)rc);
        after_slirp_input:
            pollout = -1;
        }

        /* The exitfd is closed.  */
        if (pollfds_exitfd_idx >= 0 &&
            pollfds_data[pollfds_exitfd_idx].revents) {
            fprintf(stderr, "exitfd event\n");
            goto success;
        }

        slirp_pollfds_poll(slirp, (pollout <= 0), libslirp_get_revents,
                           pollfds);
        check_ra_timeout(&opaque);
    }
success:
    ret = 0;
err:
    fprintf(stderr, "do_slirp is exiting\n");
    if (!buf) {
        free(buf);
    }
    g_array_free(pollfds, TRUE);
    return ret;
}
