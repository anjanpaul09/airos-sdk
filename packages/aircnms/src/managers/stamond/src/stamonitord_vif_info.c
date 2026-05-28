#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "ds_tree.h"
#include "log.h"
#include "info_events.h"
#include "stamonitord_vif_info.h"
#include "stamonitord_info_events.h"

bool target_info_vif_get(vif_info_event_t *vif_info);
#define SETTLE_TIME_MS 10000

#ifndef STRSCPY
#define STRSCPY(dst, src)                         \
    do {                                          \
        strncpy((dst), (src), sizeof(dst) - 1);  \
        (dst)[sizeof(dst) - 1] = '\0';           \
    } while (0)
#endif



static int
ifname_cmp(const void *a, const void *b)
{
    return strcmp(
        (const char *)a,
        (const char *)b);
}

static ds_tree_t g_radio_tree =
    DS_TREE_INIT(
        ifname_cmp,
        struct radio_state,
        node);

static ds_tree_t g_vif_tree =
    DS_TREE_INIT(
        ifname_cmp,
        struct vif_state,
        node);

static ds_tree_t g_eth_tree =
    DS_TREE_INIT(
        ifname_cmp,
        struct ethernet_state,
        node);

/*****************************************************************************/
/* GLOBAL SNAPSHOT CACHE */
/*****************************************************************************/

static vif_info_event_t g_vif_info_cache = {0};

static bool g_vif_info_cache_valid = false;

static vif_info_event_t g_vif_info_pending = {0};

static bool g_vif_info_pending_valid = false;

static uint64_t g_pending_timer_expiry = 0;

pthread_mutex_t g_vif_info_mutex =
    PTHREAD_MUTEX_INITIALIZER;

static pthread_t g_timer_thread = 0;

static bool g_timer_thread_running = false;

/*****************************************************************************/
/* LOOKUP HELPERS */
/*****************************************************************************/

/*
 * Caller must hold:
 * g_vif_info_mutex
 */

struct radio_state *
radio_cache_lookup_by_ifname(
    const char *ifname)
{
    if (!ifname)
        return NULL;

    return ds_tree_find(
        &g_radio_tree,
        ifname);
}

bool
radio_cache_lookup_by_band(
    const char *band,
    radio_info_t *radio_out)
{
    struct radio_state *r;

    if (!band || !radio_out)
        return false;

    ds_tree_foreach(
        &g_radio_tree,
        r)
    {
        if (!r->valid)
            continue;

        if (strcmp(
                r->current.band,
                band) == 0)
        {
            memcpy(
                radio_out,
                &r->current,
                sizeof(*radio_out));

            pthread_mutex_unlock(
                &g_vif_info_mutex);

            return true;
        }
    }

    return false;
}

struct vif_state *
vif_cache_lookup_by_ifname(
    const char *ifname)
{
    if (!ifname)
        return NULL;

    return ds_tree_find(
        &g_vif_tree,
        ifname);
}

struct ethernet_state *
eth_cache_lookup_by_ifname(
    const char *ifname)
{
    if (!ifname)
        return NULL;

    return ds_tree_find(
        &g_eth_tree,
        ifname);
}

/*****************************************************************************/
/* CACHE UPDATE */
/*****************************************************************************/

static void
radio_cache_update(
    const radio_info_t *radio)
{
    struct radio_state *state;

    if (!radio)
        return;

    state = radio_cache_lookup_by_ifname(
        radio->ifname);

    if (!state) {

        state = calloc(1, sizeof(*state));

        if (!state)
            return;

        STRSCPY(
            state->ifname,
            radio->ifname);

        ds_tree_insert(
            &g_radio_tree,
            state,
            state->ifname);
    }

    if (memcmp(&state->current,
               radio,
               sizeof(*radio)) == 0)
    {
        return;
    }

    memcpy(
        &state->current,
        radio,
        sizeof(*radio));

    state->valid = true;
}

static void
vif_cache_update(
    const vif_info_t *vif)
{
    struct vif_state *state;

    if (!vif)
        return;

    state = vif_cache_lookup_by_ifname(
        vif->ifname);

    if (!state) {

        state = calloc(1, sizeof(*state));

        if (!state)
            return;

        STRSCPY(
            state->ifname,
            vif->ifname);

        ds_tree_insert(
            &g_vif_tree,
            state,
            state->ifname);
    }

    if (memcmp(&state->current,
               vif,
               sizeof(*vif)) == 0)
    {
        return;
    }

    memcpy(
        &state->current,
        vif,
        sizeof(*vif));

    state->valid = true;
}

static void
eth_cache_update(
    const ethernet_info_t *eth)
{
    struct ethernet_state *state;

    if (!eth)
        return;

    state = eth_cache_lookup_by_ifname(
        eth->interface);

    if (!state) {

        state = calloc(1, sizeof(*state));

        if (!state)
            return;

        STRSCPY(
            state->ifname,
            eth->interface);

        ds_tree_insert(
            &g_eth_tree,
            state,
            state->ifname);
    }

    if (memcmp(&state->current,
               eth,
               sizeof(*eth)) == 0)
    {
        return;
    }

    memcpy(
        &state->current,
        eth,
        sizeof(*eth));

    state->valid = true;
}

static void
stamonitord_vif_cache_update(
    const vif_info_event_t *info)
{
    int i;

    if (!info)
        return;

    for (i = 0; i < info->n_radio; i++) {

        radio_cache_update(
            &info->radio[i]);
    }

    for (i = 0; i < info->n_vif; i++) {

        vif_cache_update(
            &info->vif[i]);
    }

    for (i = 0; i < info->n_ethernet; i++) {

        eth_cache_update(
            &info->ethernet[i]);
    }
}

/*****************************************************************************/
/* SORT */
/*****************************************************************************/

static int
radio_compare(const void *a,
              const void *b)
{
    const radio_info_t *ra = a;
    const radio_info_t *rb = b;

    return strcmp(
        ra->ifname,
        rb->ifname);
}

static int
vif_compare(const void *a,
            const void *b)
{
    const vif_info_t *va = a;
    const vif_info_t *vb = b;

    return strcmp(
        va->ifname,
        vb->ifname);
}

static int
ethernet_compare(const void *a,
                 const void *b)
{
    const ethernet_info_t *ea = a;
    const ethernet_info_t *eb = b;

    return strcmp(
        ea->interface,
        eb->interface);
}

static void
normalize_vif_info(
    vif_info_event_t *info)
{
    if (!info)
        return;

    if (info->n_radio > 0) {

        qsort(
            info->radio,
            info->n_radio,
            sizeof(radio_info_t),
            radio_compare);
    }

    if (info->n_vif > 0) {

        qsort(
            info->vif,
            info->n_vif,
            sizeof(vif_info_t),
            vif_compare);
    }

    if (info->n_ethernet > 0) {

        qsort(
            info->ethernet,
            info->n_ethernet,
            sizeof(ethernet_info_t),
            ethernet_compare);
    }
}

/*****************************************************************************/
/* SNAPSHOT COMPARE */
/*****************************************************************************/

static bool
vif_info_equal(
    const vif_info_event_t *a,
    const vif_info_event_t *b)
{
    if (!a || !b)
        return false;

    if (strcmp(a->serialNum,
               b->serialNum) != 0 ||

        strcmp(a->macAddr,
               b->macAddr) != 0 ||

        a->n_radio != b->n_radio ||

        a->n_vif != b->n_vif ||

        a->n_ethernet != b->n_ethernet)
    {
        return false;
    }

    if (memcmp(a->radio,
               b->radio,
               sizeof(radio_info_t) *
               a->n_radio) != 0)
    {
        return false;
    }

    if (memcmp(a->vif,
               b->vif,
               sizeof(vif_info_t) *
               a->n_vif) != 0)
    {
        return false;
    }

    if (memcmp(a->ethernet,
               b->ethernet,
               sizeof(ethernet_info_t) *
               a->n_ethernet) != 0)
    {
        return false;
    }

    return true;
}

/*****************************************************************************/
/* TIMER THREAD */
/*****************************************************************************/

static void *
vif_info_timer_thread(
    void *arg)
{
    (void)arg;

    while (g_timer_thread_running) {

        usleep(100000);

        pthread_mutex_lock(
            &g_vif_info_mutex);

        if (g_vif_info_pending_valid &&
            g_pending_timer_expiry > 0)
        {
            uint64_t now =
                get_timestamp_ms();

            if (now >=
                g_pending_timer_expiry)
            {
                vif_info_event_t info_to_send;

                memcpy(
                    &info_to_send,
                    &g_vif_info_pending,
                    sizeof(vif_info_event_t));

                g_vif_info_pending_valid =
                    false;

                g_pending_timer_expiry = 0;

                pthread_mutex_unlock(
                    &g_vif_info_mutex);

                /*
                 * Send outside mutex
                 */
                if (stamonitord_send_vif_info_event(
                        &info_to_send,
                        now))
                {
                    pthread_mutex_lock(
                        &g_vif_info_mutex);

                    memcpy(
                        &g_vif_info_cache,
                        &info_to_send,
                        sizeof(vif_info_event_t));

                    g_vif_info_cache_valid =
                        true;

                    pthread_mutex_unlock(
                        &g_vif_info_mutex);

                    LOG(INFO,
                        "Sent VIF info event");
                }
                else {

                    LOG(ERR,
                        "Failed to send "
                        "VIF info event");
                }

                pthread_mutex_lock(
                    &g_vif_info_mutex);
            }
        }

        pthread_mutex_unlock(
            &g_vif_info_mutex);
    }

    return NULL;
}

/*****************************************************************************/
/* INIT TIMER */
/*****************************************************************************/

static bool
init_vif_info_timer(void)
{
    if (g_timer_thread_running)
        return true;

    g_timer_thread_running = true;

    if (pthread_create(
            &g_timer_thread,
            NULL,
            vif_info_timer_thread,
            NULL) != 0)
    {
        LOG(ERR,
            "Failed to create "
            "VIF timer thread");

        g_timer_thread_running =
            false;

        return false;
    }

    pthread_detach(
        g_timer_thread);

    return true;
}

/*****************************************************************************/
/* INVALIDATE */
/*****************************************************************************/

void
stamonitord_invalidate_vif_cache(void)
{
    pthread_mutex_lock(
        &g_vif_info_mutex);

    g_vif_info_cache_valid = false;

    g_vif_info_pending_valid = false;

    g_pending_timer_expiry = 0;

    memset(
        &g_vif_info_cache,
        0,
        sizeof(vif_info_event_t));

    memset(
        &g_vif_info_pending,
        0,
        sizeof(vif_info_event_t));

    pthread_mutex_unlock(
        &g_vif_info_mutex);
}

/*****************************************************************************/
/* CLEANUP */
/*****************************************************************************/

void
stamonitord_cleanup_vif_timer(void)
{
    g_timer_thread_running = false;

    usleep(200000);
}

/*****************************************************************************/
/* MAIN ENTRY */
/*****************************************************************************/

bool
stamonitord_send_vif_info(void)
{
    vif_info_event_t vif_info = {0};

    uint64_t timestamp_ms =
        get_timestamp_ms();

    /*
     * Ensure timer thread running
     */
    if (!g_timer_thread_running) {

        if (!init_vif_info_timer()) {

            LOG(ERR,
                "Failed to init "
                "VIF timer");

            return false;
        }
    }

    /*
     * Fetch latest snapshot
     */
    if (!target_info_vif_get(
            &vif_info))
    {
        LOG(ERR,
            "Failed to get "
            "VIF info");

        return false;
    }

    /*
     * Normalize
     */
    normalize_vif_info(
        &vif_info);

    pthread_mutex_lock(
        &g_vif_info_mutex);

    /*
     * Update runtime trees
     */
    stamonitord_vif_cache_update(
        &vif_info);

    /*
     * Compare against last sent snapshot
     */
    bool info_changed =
        !g_vif_info_cache_valid ||

        !vif_info_equal(
            &vif_info,
            &g_vif_info_cache);

    if (!info_changed) {

        pthread_mutex_unlock(
            &g_vif_info_mutex);

        LOG(DEBUG,
            "VIF info unchanged");

        return true;
    }

    /*
     * Debounce
     */
    memcpy(
        &g_vif_info_pending,
        &vif_info,
        sizeof(vif_info_event_t));

    g_vif_info_pending_valid =
        true;

    g_pending_timer_expiry =
        timestamp_ms +
        SETTLE_TIME_MS;

    pthread_mutex_unlock(
        &g_vif_info_mutex);

    LOG(DEBUG,
        "VIF info changed, "
        "timer reset");

    return true;
}
