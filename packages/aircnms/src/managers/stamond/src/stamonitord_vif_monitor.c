#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <ev.h>

#include "log.h"
#include "stamonitord.h"
#include "stamonitord_vif_info.h"
#include "stamonitord_vif_monitor.h"

/* ============================================================
 * Configuration Constants
 * ============================================================
 */

#define VIF_MON_DEBOUNCE_SEC       5.0   /* 5-second settle window for events (allows MT7915 5G radio bringup) */
#define VIF_MON_PERIODIC_SEC       30.0  /* 30-second backup failsafe poll */
#define VIF_MON_MAX_IFACES         16
#define VIF_MON_IFNAME_LEN         32

/* ============================================================
 * Runtime Channel Store (Thread-safe)
 * ============================================================
 */

typedef struct {
    char ifname[VIF_MON_IFNAME_LEN];
    uint8_t channel;
    uint64_t last_updated_ms;
} channel_entry_t;

static channel_entry_t g_channel_table[VIF_MON_MAX_IFACES];
static pthread_mutex_t g_channel_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================
 * State & Watchers
 * ============================================================
 */

static struct ev_loop *g_mon_loop = NULL;
static struct ubus_context *g_mon_ubus_ctx = NULL;
static struct ubus_event_handler g_mon_ubus_listener;
static ev_io g_mon_ubus_watcher;

static ev_timer g_mon_debounce_timer;
static ev_timer g_mon_periodic_timer;
static ev_async g_mon_async_trigger;

static pthread_mutex_t g_trigger_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_trigger_pending = false;
static char g_last_trigger_reason[128] = "init";
static bool g_mon_running = false;

/* ============================================================
 * Helper: Frequency to Channel Converter
 * ============================================================
 */

uint8_t stamonitord_freq_to_channel(uint32_t freq)
{
    if (freq == 2484) {
        return 14;
    }
    if (freq >= 2412 && freq <= 2472) {
        return (uint8_t)((freq - 2407) / 5);
    }
    if (freq >= 5000 && freq <= 5900) {
        return (uint8_t)((freq - 5000) / 5);
    }
    if (freq >= 5950 && freq <= 7115) {
        return (uint8_t)((freq - 5950) / 5 + 1);
    }
    return 0;
}

/* ============================================================
 * Runtime Channel Table Accessors
 * ============================================================
 */

void stamonitord_vif_monitor_update_channel(const char *ifname, uint8_t channel)
{
    if (!ifname || !*ifname || channel == 0) {
        return;
    }

    pthread_mutex_lock(&g_channel_mutex);

    int free_slot = -1;
    for (int i = 0; i < VIF_MON_MAX_IFACES; i++) {
        if (strcmp(g_channel_table[i].ifname, ifname) == 0) {
            g_channel_table[i].channel = channel;
            pthread_mutex_unlock(&g_channel_mutex);
            LOG(INFO, "VIF_MON: Updated runtime channel for %s -> %u", ifname, channel);
            return;
        }
        if (free_slot < 0 && g_channel_table[i].ifname[0] == '\0') {
            free_slot = i;
        }
    }

    if (free_slot >= 0) {
        strncpy(g_channel_table[free_slot].ifname, ifname, VIF_MON_IFNAME_LEN - 1);
        g_channel_table[free_slot].ifname[VIF_MON_IFNAME_LEN - 1] = '\0';
        g_channel_table[free_slot].channel = channel;
        LOG(INFO, "VIF_MON: Registered runtime channel for %s -> %u", ifname, channel);
    }

    pthread_mutex_unlock(&g_channel_mutex);
}

uint8_t stamonitord_vif_monitor_get_channel(const char *ifname)
{
    if (!ifname || !*ifname) {
        return 0;
    }

    uint8_t ch = 0;
    pthread_mutex_lock(&g_channel_mutex);
    for (int i = 0; i < VIF_MON_MAX_IFACES; i++) {
        if (strcmp(g_channel_table[i].ifname, ifname) == 0) {
            ch = g_channel_table[i].channel;
            break;
        }
    }
    pthread_mutex_unlock(&g_channel_mutex);
    return ch;
}

/* ============================================================
 * Debounce & Evaluation Engine
 * ============================================================
 */

static void mon_debounce_timer_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    char reason[128] = {0};
    pthread_mutex_lock(&g_trigger_mutex);
    g_trigger_pending = false;
    strncpy(reason, g_last_trigger_reason, sizeof(reason) - 1);
    pthread_mutex_unlock(&g_trigger_mutex);

    LOG(INFO, "VIF_MON: Settle window expired (trigger: '%s'), evaluating VIF topology changes", reason);
    stamonitord_send_vif_info();
}

static void mon_async_cb(EV_P_ ev_async *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    if (!g_mon_loop) {
        return;
    }

    /* Coalesce / debounce: restart timer with VIF_MON_DEBOUNCE_SEC */
    ev_timer_stop(g_mon_loop, &g_mon_debounce_timer);
    ev_timer_set(&g_mon_debounce_timer, VIF_MON_DEBOUNCE_SEC, 0.0);
    ev_timer_start(g_mon_loop, &g_mon_debounce_timer);
}

static void mon_periodic_timer_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    /* Failsafe backup check */
    stamonitord_vif_monitor_trigger("periodic_failsafe");
}

/* Thread-safe external trigger entry point */
void stamonitord_vif_monitor_trigger(const char *reason)
{
    if (!g_mon_running || !g_mon_loop) {
        return;
    }

    pthread_mutex_lock(&g_trigger_mutex);
    g_trigger_pending = true;
    if (reason) {
        strncpy(g_last_trigger_reason, reason, sizeof(g_last_trigger_reason) - 1);
        g_last_trigger_reason[sizeof(g_last_trigger_reason) - 1] = '\0';
    }
    pthread_mutex_unlock(&g_trigger_mutex);

    LOG(DEBUG, "VIF_MON: Trigger event recorded ('%s'), resetting %0.1fs settle timer",
        reason ? reason : "unknown", VIF_MON_DEBOUNCE_SEC);

    ev_async_send(g_mon_loop, &g_mon_async_trigger);
}

void stamonitord_vif_monitor_resync_now(const char *reason)
{
    LOG(INFO, "VIF_MON: Immediate resync requested: %s", reason ? reason : "unknown");
    stamonitord_send_vif_info();
}

/* ============================================================
 * UBUS Event Monitor
 * ============================================================
 */

static bool is_relevant_ubus_event(const char *type, struct blob_attr *msg)
{
    if (!type) {
        return false;
    }

    /* Subsystem matches */
    if (strstr(type, "wireless") != NULL ||
        strstr(type, "hostapd") != NULL ||
        strstr(type, "network.interface") != NULL ||
        strstr(type, "network.device") != NULL ||
        strstr(type, "air.netconfd") != NULL ||
        strstr(type, "netconf") != NULL) {
        return true;
    }

    /* If payload has RF keywords, trigger */
    if (msg) {
        char *json = blobmsg_format_json(msg, true);
        if (json) {
            bool matched = (strstr(json, "csa") != NULL ||
                            strstr(json, "channel") != NULL ||
                            strstr(json, "switch") != NULL ||
                            strstr(json, "dfs") != NULL ||
                            strstr(json, "radar") != NULL ||
                            strstr(json, "wlan") != NULL ||
                            strstr(json, "radio") != NULL);
            free(json);
            if (matched) {
                return true;
            }
        }
    }

    return false;
}

static void mon_ubus_event_cb(struct ubus_context *ctx,
                              struct ubus_event_handler *ev,
                              const char *type,
                              struct blob_attr *msg)
{
    (void)ctx;
    (void)ev;

    if (!type) {
        return;
    }

    if (is_relevant_ubus_event(type, msg)) {
        LOG(INFO, "VIF_MON: UBUS event detected: '%s'", type);
        char reason[64];
        snprintf(reason, sizeof(reason), "ubus: %s", type);
        stamonitord_vif_monitor_trigger(reason);
    }
}

static void mon_ubus_fd_cb(EV_P_ ev_io *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    if (g_mon_ubus_ctx) {
        ubus_handle_event(g_mon_ubus_ctx);
    }
}

/* ============================================================
 * Lifecycle (Start / Stop)
 * ============================================================
 */

bool stamonitord_vif_monitor_start(struct ev_loop *loop)
{
    if (g_mon_running) {
        return true;
    }

    if (!loop) {
        LOG(ERR, "VIF_MON: Null event loop provided");
        return false;
    }

    g_mon_loop = loop;

    /* Initialize runtime channel cache */
    pthread_mutex_lock(&g_channel_mutex);
    memset(g_channel_table, 0, sizeof(g_channel_table));
    pthread_mutex_unlock(&g_channel_mutex);

    /* Initialize async watcher for cross-thread triggers */
    ev_async_init(&g_mon_async_trigger, mon_async_cb);
    ev_async_start(g_mon_loop, &g_mon_async_trigger);

    /* Initialize debounce timer (one-shot, armed dynamically) */
    ev_timer_init(&g_mon_debounce_timer, mon_debounce_timer_cb, 0.0, 0.0);

    /* Initialize periodic failsafe timer */
    ev_timer_init(&g_mon_periodic_timer, mon_periodic_timer_cb,
                  VIF_MON_PERIODIC_SEC, VIF_MON_PERIODIC_SEC);
    ev_timer_start(g_mon_loop, &g_mon_periodic_timer);

    /* Connect dedicated UBUS context for monitoring */
    g_mon_ubus_ctx = ubus_connect(NULL);
    if (!g_mon_ubus_ctx) {
        LOG(WARN, "VIF_MON: Failed to connect dedicated ubus context; continuing with netlink only");
    } else {
        memset(&g_mon_ubus_listener, 0, sizeof(g_mon_ubus_listener));
        g_mon_ubus_listener.cb = mon_ubus_event_cb;

        int ret = ubus_register_event_handler(g_mon_ubus_ctx, &g_mon_ubus_listener, "*");
        if (ret != 0) {
            LOG(WARN, "VIF_MON: ubus_register_event_handler failed: %d", ret);
            ubus_free(g_mon_ubus_ctx);
            g_mon_ubus_ctx = NULL;
        } else {
            ev_io_init(&g_mon_ubus_watcher, mon_ubus_fd_cb,
                       g_mon_ubus_ctx->sock.fd, EV_READ);
            ev_io_start(g_mon_loop, &g_mon_ubus_watcher);
            LOG(INFO, "VIF_MON: UBUS event listener initialized");
        }
    }

    g_mon_running = true;
    LOG(INFO, "VIF_MON: Production VIF monitor started (debounce=%0.1fs, periodic=%0.1fs)",
        VIF_MON_DEBOUNCE_SEC, VIF_MON_PERIODIC_SEC);

    return true;
}

void stamonitord_vif_monitor_stop(void)
{
    if (!g_mon_running) {
        return;
    }

    g_mon_running = false;

    if (g_mon_loop) {
        ev_timer_stop(g_mon_loop, &g_mon_debounce_timer);
        ev_timer_stop(g_mon_loop, &g_mon_periodic_timer);
        ev_async_stop(g_mon_loop, &g_mon_async_trigger);

        if (g_mon_ubus_ctx) {
            ev_io_stop(g_mon_loop, &g_mon_ubus_watcher);
            ubus_unregister_event_handler(g_mon_ubus_ctx, &g_mon_ubus_listener);
            ubus_free(g_mon_ubus_ctx);
            g_mon_ubus_ctx = NULL;
        }
    }

    g_mon_loop = NULL;
    LOG(INFO, "VIF_MON: VIF monitor stopped");
}
