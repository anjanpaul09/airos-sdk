#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <wpa_ctrl.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "report.h"
#include "log.h"
#include "stamonitord.h"
#include "stamonitord_vif_info.h"
#include "stamonitord_client_events.h"

#include <ev.h>

/* ============================================================
 * Globals
 * ============================================================
 */

static struct ubus_context *g_ubus_ctx;

static struct ubus_event_handler g_listener;

static struct ev_loop *g_loop;

static ev_io g_ubus_watcher;

static bool g_shutdown = false;

static ev_timer g_refresh_timer;
static bool g_refresh_pending;

static struct wpa_ctrl *g_hostapd_ctrl;

static ev_io g_hostapd_watcher;

/* ============================================================
 * Your Wireless Refresh Hook
 * ============================================================
 */

static void refresh_wireless_topology(void)
{
    LOG(INFO, "WIRELESS_TOPOLOGY_REFRESH: Wi-Fi config change detected, refreshing VIFs and radios");
    stamonitord_send_vif_info();
}

/* ============================================================
 * Wireless Event Detection
 * ============================================================
 */

static bool is_wireless_event(const char *type,
                              struct blob_attr *msg)
{
    if (!type)
        return false;

    /*
     * OpenWrt wireless subsystems
     */

    if (strstr(type, "hostapd"))
        return true;

    if (strstr(type, "wireless"))
        return true;

    if (strstr(type, "network.interface"))
        return true;

    if (strstr(type, "network.device"))
        return true;

    if (!msg)
        return false;

    char *json =
        blobmsg_format_json(msg, true);

    if (!json)
        return false;

    bool wireless = false;

    /*
     * Runtime AP events
     */

    if (strstr(json, "csa") ||
        strstr(json, "channel_switch") ||
        strstr(json, "dfs") ||
        strstr(json, "acs") ||
        strstr(json, "radar") ||
        strstr(json, "channel"))
    {
        wireless = true;
    }

    /*
     * Interface/radio topology
     */

    if (strstr(json, "wlan") ||
        strstr(json, "radio") ||
        strstr(json, "phy") ||
        strstr(json, "ssid"))
    {
        wireless = true;
    }

    free(json);

    return wireless;
}

static bool is_rf_runtime_event(const char *buf)
{
    if (!buf)
        return false;

    if (strstr(buf, "AP-CSA-FINISHED"))
        return true;

    if (strstr(buf, "CTRL-EVENT-CHANNEL-SWITCH"))
        return true;

    if (strstr(buf, "DFS-CAC-START"))
        return true;

    if (strstr(buf, "DFS-CAC-COMPLETED"))
        return true;

    if (strstr(buf, "DFS-NOP-FINISHED"))
        return true;

    if (strstr(buf, "ACS-COMPLETED"))
        return true;

    return false;
}

/* ============================================================
 * UBUS Event Callback
 * ============================================================
 */

static void refresh_timer_cb(EV_P_
                             ev_timer *w,
                             int revents)
{
    (void)w;
    (void)revents;

    if (!g_refresh_pending)
        return;

    g_refresh_pending = false;

    LOG(INFO, "Processing debounced wireless refresh");

    refresh_wireless_topology();
}

static void ubus_event_cb(struct ubus_context *ctx,
                          struct ubus_event_handler *ev,
                          const char *type,
                          struct blob_attr *msg)
{
    (void)ctx;
    (void)ev;

    if (!type)
        return;

    char *json =
        blobmsg_format_json(msg, true);

    LOG(INFO,"EVENT TYPE: %s",
        type);

    if (json) {

        LOG(INFO,"EVENT DATA: %s",
            json);
    }

    if (is_wireless_event(type, msg)) {

        LOG(INFO,"Wireless config change detected");

        g_refresh_pending = true;

        ev_timer_stop(g_loop,
                  &g_refresh_timer);

        ev_timer_set(&g_refresh_timer,
                 0.5,
                 0.0);

        ev_timer_start(g_loop,
               &g_refresh_timer);
    }

    free(json);
}

static void hostapd_fd_cb(EV_P_
                          ev_io *w,
                          int revents)
{
    (void)w;
    (void)revents;

    while (1) {

        char buf[4096];

        size_t len =
            sizeof(buf) - 1;

        int ret =
            wpa_ctrl_recv(g_hostapd_ctrl,
                          buf,
                          &len);

        if (ret != 0) {

            if (errno != EAGAIN &&
                errno != EWOULDBLOCK)
            {
                printf("hostapd recv failed");
            }

            break;
        }

        buf[len] = '\0';


        if (is_rf_runtime_event(buf)) {

            LOG(INFO,"RF runtime event detected");

            /*
             * Debounced refresh
             */

            g_refresh_pending = true;

            ev_timer_stop(g_loop,
                          &g_refresh_timer);

            ev_timer_set(&g_refresh_timer,
                         0.5,
                         0.0);

            ev_timer_start(g_loop,
                           &g_refresh_timer);
        }
    }
}

/* ============================================================
 * libev -> ubus bridge
 * ============================================================
 */

static void ubus_fd_cb(EV_P_
                       ev_io *w,
                       int revents)
{
    (void)revents;

    if (!g_ubus_ctx)
        return;

    /*
     * Process pending ubus events
     */

    ubus_handle_event(g_ubus_ctx);
}

/* ============================================================
 * Signal Handling
 * ============================================================
 */

static void signal_handler(int sig)
{
    LOG(INFO,"Signal received: %d",
        sig);

    g_shutdown = true;

    ev_break(g_loop,
             EVBREAK_ALL);
}

/* ============================================================
 * UBUS Initialization
 * ============================================================
 */

static int init_ubus(void)
{
    g_ubus_ctx =
        ubus_connect(NULL);

    if (!g_ubus_ctx) {

        LOG(INFO,"ubus connect failed");

        return -1;
    }

    LOG(INFO,"Connected to ubus");

    /*
     * Register wildcard listener
     */

    memset(&g_listener,
           0,
           sizeof(g_listener));

    g_listener.cb =
        ubus_event_cb;

    int ret =
        ubus_register_event_handler(
            g_ubus_ctx,
            &g_listener,
            "*");

    if (ret != 0) {

        LOG(INFO,"ubus listener registration failed");

        ubus_free(g_ubus_ctx);

        g_ubus_ctx = NULL;

        return -1;
    }

    /*
     * Monitor ubus socket fd with libev
     */

    int fd = g_ubus_ctx->sock.fd;

    ev_io_init(&g_ubus_watcher,
               ubus_fd_cb,
               fd,
               EV_READ);

    ev_io_start(g_loop,
                &g_ubus_watcher);

    LOG(INFO,"libev ubus watcher started");

    return 0;
}

static int init_hostapd_global_socket(void)
{
    g_hostapd_ctrl =
        wpa_ctrl_open("/var/run/hostapd/global");

    if (!g_hostapd_ctrl) {

        LOG(INFO,"Failed to open hostapd global socket");

        return -1;
    }

    if (wpa_ctrl_attach(g_hostapd_ctrl) != 0) {

        LOG(INFO,"Failed to attach hostapd global socket");

        wpa_ctrl_close(g_hostapd_ctrl);

        g_hostapd_ctrl = NULL;

        return -1;
    }

    int fd =
        wpa_ctrl_get_fd(g_hostapd_ctrl);

    ev_io_init(&g_hostapd_watcher,
               hostapd_fd_cb,
               fd,
               EV_READ);

    ev_io_start(g_loop,
                &g_hostapd_watcher);

    LOG(INFO,"hostapd global watcher started");

    return 0;
}

/* ============================================================
 * Public APIs
 * ============================================================
 */

int wireless_monitor_init()
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_loop = EV_DEFAULT;

    ev_timer_init(&g_refresh_timer,
              refresh_timer_cb,
              0.0,
              0.0);

    if (init_ubus() != 0) {

        return -1;
    }

    if (init_hostapd_global_socket() != 0) {

        LOG(INFO,"hostapd global socket init failed");
    }

    LOG(INFO,"Wireless monitor initialized");

    return 0;
}

void wireless_monitor_stop()
{
    if (g_ubus_ctx) {

        ev_io_stop(g_loop,
                   &g_ubus_watcher);

        ubus_free(g_ubus_ctx);

        g_ubus_ctx = NULL;
    }

    if (g_hostapd_ctrl) {

    ev_io_stop(g_loop,
               &g_hostapd_watcher);

    wpa_ctrl_detach(g_hostapd_ctrl);

    wpa_ctrl_close(g_hostapd_ctrl);

    g_hostapd_ctrl = NULL;
    }

    LOG(INFO,"Wireless monitor stopped");
}

/* ============================================================
 * Example Main
 * ============================================================
 */

#ifdef BUILD_STANDALONE

int main(void)
{
    if (wireless_monitor_init() != 0) {

        return -1;
    }

    wireless_monitor_start();

    wireless_monitor_stop();

    return 0;
}

#endif
