#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include "log.h"
#include "info_events.h"
#include "netev_info_events.h"

// Forward declaration - target_info_vif_get is defined in platform/mtk/target/target_stats.c
bool target_info_vif_get(vif_info_event_t *vif_info);
#define SETTLE_TIME_MS 6000  // Wait 5 seconds for changes to settle

/* Static cache and delayed send state */
static vif_info_event_t g_vif_info_cache = {0};
static bool g_vif_info_cache_valid = false;
static vif_info_event_t g_vif_info_pending = {0};
static bool g_vif_info_pending_valid = false;
static uint64_t g_pending_timer_expiry = 0;
static pthread_mutex_t g_vif_info_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_timer_thread = 0;
static bool g_timer_thread_running = false;

/* Comparison functions for qsort */
static int radio_compare(const void *a, const void *b)
{
    const radio_info_t *ra = (const radio_info_t *)a;
    const radio_info_t *rb = (const radio_info_t *)b;
    int cmp = strcmp(ra->band, rb->band);
    if (cmp != 0) return cmp;
    if (ra->channel != rb->channel) return ra->channel - rb->channel;
    return ra->txpower - rb->txpower;
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

/* Timer thread that sends pending VIF info after settle time */
static void *vif_info_timer_thread(void *arg)
{
    (void)arg;

    while (g_timer_thread_running) {
        usleep(100000); // Check every 100ms

        pthread_mutex_lock(&g_vif_info_mutex);

        if (g_vif_info_pending_valid && g_pending_timer_expiry > 0) {
            uint64_t now = get_timestamp_ms();

            if (now >= g_pending_timer_expiry) {
                // Timer expired, send the pending info
                vif_info_event_t info_to_send;
                memcpy(&info_to_send, &g_vif_info_pending, sizeof(vif_info_event_t));

                // Clear pending state before sending
                g_vif_info_pending_valid = false;
                g_pending_timer_expiry = 0;

                pthread_mutex_unlock(&g_vif_info_mutex);

                // Send event (outside mutex to avoid blocking)
                if (netev_send_vif_info_event(&info_to_send, now)) {
                    // Update cache after successful send
                    pthread_mutex_lock(&g_vif_info_mutex);
                    memcpy(&g_vif_info_cache, &info_to_send, sizeof(vif_info_event_t));
                    g_vif_info_cache_valid = true;
                    pthread_mutex_unlock(&g_vif_info_mutex);

                    LOG(INFO, "Sent VIF info event: n_radio=%d n_vif=%d n_ethernet=%d",
                        info_to_send.n_radio, info_to_send.n_vif, info_to_send.n_ethernet);
                } else {
                    LOG(ERR, "Failed to send delayed VIF info event");
                }

                pthread_mutex_lock(&g_vif_info_mutex);
            }
        }

        pthread_mutex_unlock(&g_vif_info_mutex);
    }

    return NULL;
}

/* Initialize the timer thread */
static bool init_vif_info_timer(void)
{
    if (g_timer_thread_running) {
        return true; // Already running
    }

    g_timer_thread_running = true;

    if (pthread_create(&g_timer_thread, NULL, vif_info_timer_thread, NULL) != 0) {
        LOG(ERR, "Failed to create VIF info timer thread");
        g_timer_thread_running = false;
        return false;
    }

    pthread_detach(g_timer_thread);
    LOG(INFO, "VIF info timer thread started");
    return true;
}

/* Invalidate VIF info cache (optional utility function) */
void netev_invalidate_vif_cache(void)
{
    pthread_mutex_lock(&g_vif_info_mutex);
    g_vif_info_cache_valid = false;
    g_vif_info_pending_valid = false;
    g_pending_timer_expiry = 0;
    memset(&g_vif_info_cache, 0, sizeof(vif_info_event_t));
    memset(&g_vif_info_pending, 0, sizeof(vif_info_event_t));
    pthread_mutex_unlock(&g_vif_info_mutex);
    LOG(DEBUG, "VIF info cache invalidated");
}

/* Cleanup function to stop timer thread */
void netev_cleanup_vif_timer(void)
{
    g_timer_thread_running = false;
    // Give thread time to exit
    usleep(200000);
}

/* Send VIF info event by calling target_info_vif_get */
bool netev_send_vif_info(void)
{
    vif_info_event_t vif_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();

    // Ensure timer thread is running
    if (!g_timer_thread_running) {
        if (!init_vif_info_timer()) {
            LOG(ERR, "Failed to initialize VIF info timer");
            return false;
        }
    }

    // Call target function to fill VIF info
    if (!target_info_vif_get(&vif_info)) {
        LOG(ERR, "Failed to get VIF info from target");
        return false;
    }

    // Normalize the VIF info (sort arrays for consistent comparison)
    normalize_vif_info(&vif_info);

    pthread_mutex_lock(&g_vif_info_mutex);

    // Check if VIF info has changed from last sent version
    bool info_changed = !g_vif_info_cache_valid || !vif_info_equal(&vif_info, &g_vif_info_cache);

    if (!info_changed) {
        pthread_mutex_unlock(&g_vif_info_mutex);
        LOG(DEBUG, "VIF info unchanged from last sent, skipping");
        return true;
    }

    // Info has changed - update pending and reset timer
    memcpy(&g_vif_info_pending, &vif_info, sizeof(vif_info_event_t));
    g_vif_info_pending_valid = true;
    g_pending_timer_expiry = timestamp_ms + SETTLE_TIME_MS;

    pthread_mutex_unlock(&g_vif_info_mutex);

    LOG(DEBUG, "VIF info changed, timer reset. Will send after %d ms settle time", SETTLE_TIME_MS);

    return true;
}

#if 0
/* Send VIF info event by calling target_info_vif_get */
bool netev_send_vif_info(void)
{
    vif_info_event_t vif_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    
    // Call target function to fill VIF info
    if (!target_info_vif_get(&vif_info)) {
        LOG(ERR, "Failed to get VIF info from target");
        return false;
    }
    
    // Send VIF info event
    if (!netev_send_vif_info_event(&vif_info, timestamp_ms)) {
        LOG(ERR, "Failed to send VIF info event");
        return false;
    }
    
    LOG(INFO, "Sent VIF info event: n_radio=%d n_vif=%d n_ethernet=%d", 
        vif_info.n_radio, vif_info.n_vif, vif_info.n_ethernet);
    
    return true;
}
#endif
