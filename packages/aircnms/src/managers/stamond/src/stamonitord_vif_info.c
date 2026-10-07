#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ev.h>

#include "log.h"
#include "os.h"
#include "info_events.h"
#include "stamonitord.h"
#include "stamonitord_info_events.h"
#include "stamonitord_vif_info.h"

// Forward declaration - target_info_vif_get is defined in platform/mtk/target/target_stats.c
bool target_info_vif_get(vif_info_event_t *vif_info);

static bool is_radio_band_configured(const char *band)
{
    char buf[32] = {0};
    char dev[16] = {0};

    if (cmd_buf("uci -q get wireless.wifi0.band", buf, sizeof(buf)) == 0) {
        buf[strcspn(buf, "\r\n \t")] = '\0';
        if (strcasecmp(buf, band) == 0) {
            strcpy(dev, "wifi0");
        } else {
            strcpy(dev, "wifi1");
        }
    } else {
        strcpy(dev, strcmp(band, "2g") == 0 ? "wifi1" : "wifi0");
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.disabled", dev);
    if (cmd_buf(cmd, buf, sizeof(buf)) == 0) {
        buf[strcspn(buf, "\r\n \t")] = '\0';
        if (strcmp(buf, "1") == 0) {
            return false;
        }
    }
    return true;
}

#define VIF_INFO_RETRY_INTERVAL_SEC 5.0

/* Static cache and libev retry state */
static vif_info_event_t g_vif_info_cache = {0};
static bool g_vif_info_cache_valid = false;

static struct ev_loop *g_vif_loop = NULL;
static ev_timer g_vif_retry_timer;
static bool g_vif_retry_timer_active = false;

/* Comparison functions for qsort */
static int radio_compare(const void *a, const void *b)
{
    const radio_info_t *ra = (const radio_info_t *)a;
    const radio_info_t *rb = (const radio_info_t *)b;
    int cmp = strcmp(ra->band, rb->band);
    if (cmp != 0) return cmp;
    if (ra->channel != rb->channel) return (int)ra->channel - (int)rb->channel;
    return (int)ra->txpower - (int)rb->txpower;
}

static int vif_compare(const void *a, const void *b)
{
    const vif_info_t *va = (const vif_info_t *)a;
    const vif_info_t *vb = (const vif_info_t *)b;
    int cmp = strcmp(va->radio, vb->radio);
    if (cmp != 0) return cmp;
    return strcmp(va->ssid, vb->ssid);
}

static int ethernet_compare(const void *a, const void *b)
{
    const ethernet_info_t *ea = (const ethernet_info_t *)a;
    const ethernet_info_t *eb = (const ethernet_info_t *)b;
    int cmp = strcmp(ea->interface, eb->interface);
    if (cmp != 0) return cmp;
    cmp = strcmp(ea->name, eb->name);
    if (cmp != 0) return cmp;
    return strcmp(ea->type, eb->type);
}

/* Helper function to normalize VIF info (sort arrays for consistent comparison) */
static void normalize_vif_info(vif_info_event_t *info)
{
    if (info->n_radio > 0) {
        qsort(info->radio, info->n_radio, sizeof(radio_info_t), radio_compare);
    }
    if (info->n_vif > 0) {
        qsort(info->vif, info->n_vif, sizeof(vif_info_t), vif_compare);
    }
    if (info->n_ethernet > 0) {
        qsort(info->ethernet, info->n_ethernet, sizeof(ethernet_info_t), ethernet_compare);
    }
}

/* Helper function to compare VIF info structures */
static bool vif_info_equal(const vif_info_event_t *a, const vif_info_event_t *b)
{
    // Compare basic fields
    if (strcmp(a->serialNum, b->serialNum) != 0 ||
        strcmp(a->macAddr, b->macAddr) != 0 ||
        a->n_radio != b->n_radio ||
        a->n_vif != b->n_vif ||
        a->n_ethernet != b->n_ethernet) {
        return false;
    }

    // Compare radio info arrays (already sorted)
    if (memcmp(a->radio, b->radio, sizeof(radio_info_t) * a->n_radio) != 0) {
        return false;
    }

    // Compare VIF info arrays (already sorted)
    if (memcmp(a->vif, b->vif, sizeof(vif_info_t) * a->n_vif) != 0) {
        return false;
    }

    // Compare ethernet info arrays (already sorted)
    if (memcmp(a->ethernet, b->ethernet, sizeof(ethernet_info_t) * a->n_ethernet) != 0) {
        return false;
    }

    return true;
}

/* Retry callback executed on libev event loop */
static void vif_retry_timer_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    LOG(DEBUG, "VIF_INFO: Retry timer triggered");
    stamonitord_send_vif_info();
}

/* Invalidate VIF info cache */
void stamonitord_invalidate_vif_cache(void)
{
    g_vif_info_cache_valid = false;
    memset(&g_vif_info_cache, 0, sizeof(vif_info_event_t));
    LOG(DEBUG, "VIF info cache invalidated");
}

/* Initialize VIF info subsystem with libev loop */
bool stamonitord_vif_info_init(struct ev_loop *loop)
{
    g_vif_loop = loop ? loop : EV_DEFAULT;

    ev_timer_init(&g_vif_retry_timer, vif_retry_timer_cb,
                  VIF_INFO_RETRY_INTERVAL_SEC, VIF_INFO_RETRY_INTERVAL_SEC);
    g_vif_retry_timer_active = false;

    LOG(INFO, "VIF_INFO: Initialized with libev loop");

    // Perform initial sync attempt
    if (stamonitord_is_cloud_enrolled()) {
        stamonitord_send_vif_info();
    }

    return true;
}

/* Cleanup function */
void stamonitord_vif_info_cleanup(void)
{
    if (g_vif_retry_timer_active && g_vif_loop) {
        ev_timer_stop(g_vif_loop, &g_vif_retry_timer);
        g_vif_retry_timer_active = false;
    }
    g_vif_loop = NULL;
}

/* Send VIF info event: compares against cache and publishes if changed */
bool stamonitord_send_vif_info(void)
{
    if (!stamonitord_is_cloud_enrolled()) {
        LOG(DEBUG, "VIF_INFO: Not cloud enrolled, skipping");
        return false;
    }

    vif_info_event_t vif_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();

    // Call target function to fill VIF info
    if (!target_info_vif_get(&vif_info)) {
        LOG(ERR, "VIF_INFO: Failed to get VIF info from target");
        return false;
    }

    // Normalize the VIF info (sort arrays for consistent comparison)
    normalize_vif_info(&vif_info);

    // If 5GHz radio is enabled in UCI but active VIFs have not appeared yet, wait for MT7915 settle
    static int settle_retries = 0;
    bool need_5g = is_radio_band_configured("5g");
    bool has_5g = false;
    for (int i = 0; i < vif_info.n_vif; i++) {
        if (strcmp(vif_info.vif[i].radio, "BAND5G") == 0) {
            has_5g = true;
            break;
        }
    }

    if (need_5g && !has_5g && settle_retries < 3) {
        settle_retries++;
        LOG(INFO, "VIF_INFO: 5GHz radio interfaces still initializing (retry %d/3), waiting 2.0s", settle_retries);
        if (g_vif_loop) {
            ev_timer_stop(g_vif_loop, &g_vif_retry_timer);
            ev_timer_set(&g_vif_retry_timer, 2.0, 0.0);
            ev_timer_start(g_vif_loop, &g_vif_retry_timer);
            g_vif_retry_timer_active = true;
        }
        return false;
    }
    settle_retries = 0;

    // Check if VIF info has changed from last sent version
    bool info_changed = !g_vif_info_cache_valid || !vif_info_equal(&vif_info, &g_vif_info_cache);

    if (!info_changed) {
        LOG(DEBUG, "VIF_INFO: Info unchanged from last sent, skipping");

        // If retry timer was running, stop it since cache is valid and unchanged
        if (g_vif_retry_timer_active && g_vif_loop) {
            ev_timer_stop(g_vif_loop, &g_vif_retry_timer);
            g_vif_retry_timer_active = false;
        }
        return true;
    }

    // Attempt to publish
    bool sent = stamonitord_send_vif_info_event(&vif_info, timestamp_ms);
    if (sent) {
        // Update cache only after successful send
        memcpy(&g_vif_info_cache, &vif_info, sizeof(vif_info_event_t));
        g_vif_info_cache_valid = true;

        if (g_vif_retry_timer_active && g_vif_loop) {
            ev_timer_stop(g_vif_loop, &g_vif_retry_timer);
            g_vif_retry_timer_active = false;
        }

        LOG(INFO, "Sent VIF info event: n_radio=%d n_vif=%d n_ethernet=%d",
            vif_info.n_radio, vif_info.n_vif, vif_info.n_ethernet);
        return true;
    }

    // Send failed (likely offline on startup or ubus/cgwd busy)
    LOG(INFO, "VIF_INFO: Publish failed (device may be offline), will retry in %0.0fs",
        VIF_INFO_RETRY_INTERVAL_SEC);

    if (!g_vif_retry_timer_active && g_vif_loop) {
        ev_timer_set(&g_vif_retry_timer, VIF_INFO_RETRY_INTERVAL_SEC, VIF_INFO_RETRY_INTERVAL_SEC);
        ev_timer_start(g_vif_loop, &g_vif_retry_timer);
        g_vif_retry_timer_active = true;
    }

    return false;
}
