#include "stamonitord_history_internal.h"
#include <ev.h>
#include "log.h"


static stamonitord_history_t *g_hist = NULL;

static char *xstrdup_safe(const char *s) {
    if (!s)
        s = STAMONITORD_HISTORY_DEFAULT_OUTPUT;

    return strdup(s);
}

int stamonitord_history_start(struct ev_loop *loop) {
    if (!loop)
        return -1;

    /*
     * Already started.
     */
    if (g_hist)
        return 0;

    stamonitord_history_t *hist = calloc(1, sizeof(*hist));
    if (!hist)
        return -1;

    app_t *app = &hist->app;

    app->loop = loop;
    app->rtnl_fd = -1;

    app->output_path = xstrdup_safe(STAMONITORD_HISTORY_DEFAULT_OUTPUT);
    if (!app->output_path) {
        free(hist);
        return -1;
    }

    /*
     * Since your main program already owns ev_run() and probably owns
     * signal handling, do not install SIGINT/SIGTERM handlers here.
     */
    app->install_signal_handlers = false;

    app->flush_interval_sec = 120.0;
    app->expire_interval_sec = 30.0;
    app->resync_interval_sec = 10.0;
    app->resync_debounce_sec = 0.5;
    app->report_seq = 0;

    LOG(INFO, "STAMONITORD history starting, output=%s", app->output_path);

    load_local_macs(app);

    if (init_ndpi(app) < 0) {
        free(app->output_path);
        free(hist);
        return -1;
    }

    app->rtnl_fd = open_rtnetlink_socket();

    if (app->rtnl_fd >= 0) {
        ev_io_init(&app->rtnl_io, rtnl_read_cb, app->rtnl_fd, EV_READ);
        app->rtnl_io.data = app;
        ev_io_start(app->loop, &app->rtnl_io);

        LOG(INFO, "STAMONITORD history rtnetlink watcher enabled");
    } else {
        LOG(WARN, "STAMONITORD history rtnetlink watcher disabled: %s",
                strerror(errno));
    }

    ev_timer_init(&app->flush_timer,
                  flush_cb,
                  app->flush_interval_sec,
                  app->flush_interval_sec);
    app->flush_timer.data = app;
    ev_timer_start(app->loop, &app->flush_timer);

    ev_timer_init(&app->expire_timer,
                  expire_cb,
                  app->expire_interval_sec,
                  app->expire_interval_sec);
    app->expire_timer.data = app;
    ev_timer_start(app->loop, &app->expire_timer);

    ev_timer_init(&app->resync_timer,
                  resync_timer_cb,
                  0.0,
                  app->resync_interval_sec);
    app->resync_timer.data = app;
    ev_timer_start(app->loop, &app->resync_timer);

    ev_timer_init(&app->resync_debounce_timer,
                  resync_debounce_cb,
                  app->resync_debounce_sec,
                  0.0);
    app->resync_debounce_timer.data = app;

    /*
     * Initial scan of br-lan/br-nat wireless interfaces.
     */
    resync_interfaces(app);

    g_hist = hist;

    return 0;
}

void stamonitord_history_flush(void) {
    if (!g_hist)
        return;

    flush_json(&g_hist->app);
}

void stamonitord_history_resync(void) {
    if (!g_hist)
        return;

    resync_interfaces(&g_hist->app);
}

void stamonitord_history_notify_station_connect(const uint8_t *mac, const char *ifname) {
    if (!g_hist || !mac)
        return;

    mac_addr_t station_mac;
    memcpy(station_mac.b, mac, sizeof(station_mac.b));

    station_t *s = station_get_or_create(&g_hist->app, station_mac, 0, ZONE_UNKNOWN, 0);
    if (!s)
        return;

    s->last_seen_ms = now_ms();
    LOG(DEBUG, "STAMONITORD history station connect: %02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
        station_mac.b[0], station_mac.b[1], station_mac.b[2],
        station_mac.b[3], station_mac.b[4], station_mac.b[5],
        ifname ? ifname : "unknown");
}

void stamonitord_history_notify_station_disconnect(const uint8_t *mac, const char *ifname) {
    if (!g_hist || !mac)
        return;

    mac_addr_t station_mac;
    memcpy(station_mac.b, mac, sizeof(station_mac.b));

    station_t *s = station_get_or_create(&g_hist->app, station_mac, 0, ZONE_UNKNOWN, 0);
    if (!s)
        return;

    s->last_seen_ms = now_ms();
    LOG(DEBUG, "STAMONITORD history station disconnect: %02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
        station_mac.b[0], station_mac.b[1], station_mac.b[2],
        station_mac.b[3], station_mac.b[4], station_mac.b[5],
        ifname ? ifname : "unknown");
}

bool stamonitord_history_lookup_station_ip(const uint8_t *mac, char *ipaddr, size_t ipaddr_len) {
    if (!g_hist || !mac || !ipaddr || ipaddr_len == 0)
        return false;

    mac_addr_t station_mac;
    memcpy(station_mac.b, mac, sizeof(station_mac.b));

    uint32_t h = hash_bytes(station_mac.b, sizeof(station_mac.b)) % STATION_BUCKETS;

    for (station_t *s = g_hist->app.stations[h]; s; s = s->next) {
        if (!mac_equal(s->mac, station_mac))
            continue;

        if (s->ip == 0)
            return false;

        char tmp[INET_ADDRSTRLEN];
        if (!ip4_to_str(s->ip, tmp))
            return false;

        snprintf(ipaddr, ipaddr_len, "%s", tmp);
        return true;
    }

    return false;
}

bool stamonitord_history_lookup_client_identity(const uint8_t *mac,
                                                char *ipaddr,
                                                size_t ipaddr_len,
                                                char *hostname,
                                                size_t hostname_len,
                                                char *dhcp_options,
                                                size_t dhcp_options_len,
                                                char *dhcp_vendor,
                                                size_t dhcp_vendor_len) {
    if (!g_hist || !mac)
        return false;

    mac_addr_t station_mac;
    memcpy(station_mac.b, mac, sizeof(station_mac.b));

    uint32_t h = hash_bytes(station_mac.b, sizeof(station_mac.b)) % STATION_BUCKETS;

    for (station_t *s = g_hist->app.stations[h]; s; s = s->next) {
        if (!mac_equal(s->mac, station_mac))
            continue;

        bool found = false;

        if (ipaddr && ipaddr_len > 0 && s->ip != 0) {
            char tmp[INET_ADDRSTRLEN];

            if (ip4_to_str(s->ip, tmp)) {
                snprintf(ipaddr, ipaddr_len, "%s", tmp);
                found = true;
            }
        }

        if (hostname && hostname_len > 0 && s->hostname[0]) {
            snprintf(hostname, hostname_len, "%s", s->hostname);
            found = true;
        }

        if (dhcp_options && dhcp_options_len > 0 && s->dhcp_options[0]) {
            snprintf(dhcp_options, dhcp_options_len, "%s", s->dhcp_options);
            found = true;
        }

        if (dhcp_vendor && dhcp_vendor_len > 0 && s->dhcp_vendor[0]) {
            snprintf(dhcp_vendor, dhcp_vendor_len, "%s", s->dhcp_vendor);
            found = true;
        }

        return found;
    }

    return false;
}

void stamonitord_history_stop(void) {
    if (!g_hist)
        return;

    stamonitord_history_t *hist = g_hist;
    g_hist = NULL;

    app_t *app = &hist->app;

    LOG(INFO, "STAMONITORD history stopping");

    flush_json(app);

    cleanup_app(app);

    free(app->output_path);
    app->output_path = NULL;

    free(hist);
}

/*
 * You can keep this even if you do not install signal handlers.
 * It is useful if later you enable them.
 */
void signal_cb(EV_P_ ev_signal *w, int revents) {
    (void)revents;

    app_t *app = w->data;
    if (!app)
        return;

    if (app->shutting_down)
        return;

    app->shutting_down = true;

    LOG(INFO, "STAMONITORD history shutdown requested");

    flush_json(app);

    ev_break(EV_A_ EVBREAK_ALL);
}

void cleanup_app(app_t *app) {
    if (!app)
        return;

    if (app->loop) {
        ev_timer_stop(app->loop, &app->flush_timer);
        ev_timer_stop(app->loop, &app->expire_timer);
        ev_timer_stop(app->loop, &app->resync_timer);
        ev_timer_stop(app->loop, &app->resync_debounce_timer);

        if (app->install_signal_handlers) {
            ev_signal_stop(app->loop, &app->sigint_watcher);
            ev_signal_stop(app->loop, &app->sigterm_watcher);
        }
    }

    cap_if_t *c = app->caps;

    while (c) {
        cap_if_t *next = c->next;

        if (app->loop)
            ev_io_stop(app->loop, &c->io);

        if (c->fd >= 0)
            close(c->fd);

        free(c);
        c = next;
    }

    app->caps = NULL;

    if (app->rtnl_fd >= 0) {
        if (app->loop)
            ev_io_stop(app->loop, &app->rtnl_io);

        close(app->rtnl_fd);
        app->rtnl_fd = -1;
    }

    for (size_t i = 0; i < FLOW_BUCKETS; i++) {
        flow_t *f = app->flows[i];

        while (f) {
            flow_t *next = f->next;
            flow_free(f);
            f = next;
        }

        app->flows[i] = NULL;
    }

    app->flow_count = 0;

    for (size_t i = 0; i < DNS_BUCKETS; i++) {
        dns_entry_t *e = app->dns[i];

        while (e) {
            dns_entry_t *next = e->next;
            free(e);
            e = next;
        }

        app->dns[i] = NULL;
    }

    app->dns_count = 0;

    for (size_t i = 0; i < STATION_BUCKETS; i++) {
        station_t *s = app->stations[i];

        while (s) {
            station_t *s_next = s->next;

            for (size_t j = 0; j < DOMAIN_BUCKETS; j++) {
                domain_stat_t *d = s->domains[j];

                while (d) {
                    domain_stat_t *d_next = d->next;
                    free(d);
                    d = d_next;
                }
            }

            free(s);
            s = s_next;
        }

        app->stations[i] = NULL;
    }

    if (app->ndpi) {
        //ndpi_exit_detection_module(app->ndpi);
        app->ndpi = NULL;
    }
}
