#include "stamonitord_history_internal.h"
#include "log.h"

/* ------------------------------------------------------------------------- */
/* Small local helpers                                                       */
/* ------------------------------------------------------------------------- */

static void copy_cstr_trunc(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0)
        return;

    if (!src)
        src = "";

    size_t n = strlen(src);

    if (n >= dst_sz)
        n = dst_sz - 1;

    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Interface discovery helpers                                               */
/* ------------------------------------------------------------------------- */

static bool path_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static bool looks_like_wifi_name(const char *ifname) {
    if (!ifname)
        return false;

    if (strncmp(ifname, "phy", 3) == 0 && strstr(ifname, "-ap"))
        return true;

    if (strncmp(ifname, "wlan", 4) == 0)
        return true;

    return false;
}

static bool is_wireless_if(const char *ifname) {
    if (!ifname || !ifname[0])
        return false;

    char path[512];

    int ret = snprintf(path,
                       sizeof(path),
                       "/sys/class/net/%s/wireless",
                       ifname);

    if (ret >= 0 && (size_t)ret < sizeof(path)) {
        if (path_exists(path))
            return true;
    }

    ret = snprintf(path,
                   sizeof(path),
                   "/sys/class/net/%s/phy80211",
                   ifname);

    if (ret >= 0 && (size_t)ret < sizeof(path)) {
        if (path_exists(path))
            return true;
    }

    return looks_like_wifi_name(ifname);
}

static bool is_excluded_if(const char *ifname) {
    if (!ifname)
        return true;

    if (!strcmp(ifname, "lo")) return true;
    if (!strcmp(ifname, "wan")) return true;
    if (!strcmp(ifname, "lan")) return true;
    if (!strncmp(ifname, "br-", 3)) return true;
    if (!strncmp(ifname, "eth", 3)) return true;

    return false;
}

static zone_t zone_from_bridge(const char *bridge) {
    if (!bridge)
        return ZONE_UNKNOWN;

    if (!strcmp(bridge, "br-lan")) return ZONE_BR_LAN;
    if (!strcmp(bridge, "br-nat")) return ZONE_BR_NAT;

    return ZONE_UNKNOWN;
}

/* ------------------------------------------------------------------------- */
/* Capture sockets                                                           */
/* ------------------------------------------------------------------------- */

int set_nonblock_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        return -1;

    return 0;
}

int open_packet_socket(const char *ifname) {
    if (!ifname || !ifname[0])
        return -1;

    int ifindex = if_nametoindex(ifname);

    if (ifindex <= 0)
        return -1;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;

    if (set_nonblock_cloexec(fd) < 0) {
        close(fd);
        return -1;
    }

    int rcvbuf = SOCKET_RCVBUF;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

cap_if_t *find_cap(app_t *app, const char *ifname) {
    if (!app || !ifname)
        return NULL;

    for (cap_if_t *c = app->caps; c; c = c->next) {
        if (!strcmp(c->ifname, ifname))
            return c;
    }

    return NULL;
}

void packet_read_cb(EV_P_ ev_io *w, int revents) {
    (void)loop;

    if (!(revents & EV_READ))
        return;

    cap_if_t *cap = container_of(w, cap_if_t, io);
    app_t *app = cap->app;

    if (!app)
        return;

    uint8_t buf[MAX_PACKET_SIZE];

    while (1) {
        struct sockaddr_ll addr;
        socklen_t addrlen = sizeof(addr);

        ssize_t n = recvfrom(cap->fd,
                             buf,
                             sizeof(buf),
                             MSG_DONTWAIT,
                             (struct sockaddr *)&addr,
                             &addrlen);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (errno == EINTR)
                continue;

            LOG(ERR, "recvfrom %s failed: %s",
                    cap->ifname, strerror(errno));
            break;
        }

        if (n == 0)
            break;

        app->packets_seen++;

        if (addr.sll_ifindex && addr.sll_ifindex != cap->ifindex)
            continue;

        parsed_pkt_t pp;

        if (parse_ether_ip(buf, (size_t)n, &pp) < 0) {
            app->packets_parse_failed++;
            continue;
        }

        app->packets_parsed++;
        pp.packet_type = addr.sll_pkttype;

        account_packet(app, cap, &pp);
    }
}

int ensure_capture(app_t *app, const char *ifname, const char *bridge) {
    if (!app || !ifname || !bridge)
        return -1;

    cap_if_t *c = find_cap(app, ifname);

    if (c) {
        c->seen = true;

        if (strcmp(c->bridge, bridge)) {
            copy_cstr_trunc(c->bridge, sizeof(c->bridge), bridge);
            c->zone = zone_from_bridge(bridge);
        }

        return 0;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0)
        return -1;

    int fd = open_packet_socket(ifname);
    if (fd < 0) {
        LOG(ERR, "failed to open capture socket on %s: %s",
                ifname, strerror(errno));
        return -1;
    }

    c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        return -1;
    }

    copy_cstr_trunc(c->ifname, sizeof(c->ifname), ifname);
    copy_cstr_trunc(c->bridge, sizeof(c->bridge), bridge);

    c->ifindex = ifindex;
    c->fd = fd;
    c->zone = zone_from_bridge(bridge);
    c->seen = true;
    c->app = app;

    ev_io_init(&c->io, packet_read_cb, fd, EV_READ);
    ev_io_start(app->loop, &c->io);

    c->next = app->caps;
    app->caps = c;

    LOG(INFO, "capturing ifname=%s bridge=%s zone=%s ifindex=%d",
            c->ifname, c->bridge, zone_str(c->zone), c->ifindex);

    return 0;
}

void remove_capture(app_t *app, cap_if_t *c, cap_if_t *prev) {
    if (!app || !c)
        return;

    LOG(INFO, "removing capture ifname=%s bridge=%s",
            c->ifname, c->bridge);

    ev_io_stop(app->loop, &c->io);

    if (c->fd >= 0)
        close(c->fd);

    if (prev)
        prev->next = c->next;
    else
        app->caps = c->next;

    free(c);
}

void mark_all_caps_unseen(app_t *app) {
    if (!app)
        return;

    for (cap_if_t *c = app->caps; c; c = c->next)
        c->seen = false;
}

void remove_unseen_caps(app_t *app) {
    if (!app)
        return;

    cap_if_t *prev = NULL;
    cap_if_t *c = app->caps;

    while (c) {
        cap_if_t *next = c->next;

        if (!c->seen) {
            remove_capture(app, c, prev);
        } else {
            prev = c;
        }

        c = next;
    }
}

void scan_bridge(app_t *app, const char *bridge) {
    if (!app || !bridge || !bridge[0])
        return;

    /*
     * Prefer capturing on the bridge itself. On some OpenWrt WiFi drivers,
     * per-AP netdev packet sockets only see station-originated frames, which
     * makes application traffic look upload-only. The bridge sees both
     * directions and also avoids double counting across multiple AP members.
     */
    if (ensure_capture(app, bridge, bridge) == 0)
        return;

    char path[512];

    int ret = snprintf(path,
                       sizeof(path),
                       "/sys/class/net/%s/brif",
                       bridge);

    if (ret < 0 || (size_t)ret >= sizeof(path))
        return;

    DIR *d = opendir(path);
    if (!d)
        return;

    struct dirent *de;

    while ((de = readdir(d))) {
        const char *ifname = de->d_name;

        if (!ifname || ifname[0] == '.')
            continue;

        if (is_excluded_if(ifname))
            continue;

        if (!is_wireless_if(ifname))
            continue;

        ensure_capture(app, ifname, bridge);
    }

    closedir(d);
}

void resync_interfaces(app_t *app) {
    if (!app)
        return;

    load_local_macs(app);

    mark_all_caps_unseen(app);

    scan_bridge(app, "br-lan");
    scan_bridge(app, "br-nat");

    remove_unseen_caps(app);
}

void resync_timer_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)revents;

    app_t *app = w ? w->data : NULL;

    if (app)
        resync_interfaces(app);
}

void resync_debounce_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)revents;

    app_t *app = w ? w->data : NULL;

    if (app)
        resync_interfaces(app);
}

/* ------------------------------------------------------------------------- */
/* rtnetlink                                                                 */
/* ------------------------------------------------------------------------- */

int open_rtnetlink_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        return -1;

    if (set_nonblock_cloexec(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));

    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

void rtnl_read_cb(EV_P_ ev_io *w, int revents) {
    (void)loop;

    if (!(revents & EV_READ))
        return;

    app_t *app = w ? w->data : NULL;

    if (!app)
        return;

    char buf[8192];

    while (1) {
        ssize_t n = recv(w->fd, buf, sizeof(buf), MSG_DONTWAIT);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (errno == EINTR)
                continue;

            break;
        }

        if (n == 0)
            break;

        ev_timer_stop(app->loop, &app->resync_debounce_timer);

        ev_timer_set(&app->resync_debounce_timer,
                     app->resync_debounce_sec,
                     0.0);

        ev_timer_start(app->loop, &app->resync_debounce_timer);
    }
}

/* ------------------------------------------------------------------------- */
/* Expiry                                                                    */
/* ------------------------------------------------------------------------- */

void expire_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)revents;

    app_t *app = w ? w->data : NULL;

    if (!app)
        return;

    uint64_t t = now_ms();

    for (size_t i = 0; i < DNS_BUCKETS; i++) {
        dns_entry_t **pp = &app->dns[i];

        while (*pp) {
            dns_entry_t *e = *pp;

            if (e->expires_ms <= t) {
                *pp = e->next;
                free(e);
                if (app->dns_count > 0)
                    app->dns_count--;
            } else {
                pp = &e->next;
            }
        }
    }

    for (size_t i = 0; i < FLOW_BUCKETS; i++) {
        flow_t **pp = &app->flows[i];

        while (*pp) {
            flow_t *f = *pp;

            if (t > f->last_seen_ms &&
                t - f->last_seen_ms > FLOW_IDLE_TIMEOUT_SEC * 1000ULL) {
                *pp = f->next;
                flow_free(f);
                if (app->flow_count > 0)
                    app->flow_count--;
            } else {
                pp = &f->next;
            }
        }
    }

    for (size_t i = 0; i < STATION_BUCKETS; i++) {
        for (station_t *s = app->stations[i]; s; s = s->next) {
            for (size_t j = 0; j < DOMAIN_BUCKETS; j++) {
                for (domain_stat_t *d = s->domains[j]; d; d = d->next) {
                    if (t > d->last_seen_ms &&
                        t - d->last_seen_ms >
                            DOMAIN_ACTIVE_TIMEOUT_SEC * 1000ULL) {
                        d->active = false;
                    }
                }
            }
        }
    }
}
