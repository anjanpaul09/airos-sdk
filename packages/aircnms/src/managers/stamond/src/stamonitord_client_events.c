/*****************************************************************************/
/* stamonitord_client_events.c */
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <net/if.h>

#include <ev.h>

#include "ds_tree.h"

#include "log.h"

#include "stats_report.h"

#include "dhcp_fp.h"

#include "stamonitord_history.h"

#include "stamonitord_client_cap.h"

#include "stamonitord_vif_info.h"

#include "stamonitord_info_events.h"

#include "stamonitord_client_events.h"

/*****************************************************************************/
/* CONFIG */
/*****************************************************************************/

#define METADATA_RETRY_INTERVAL   5.0
#define METADATA_MAX_RETRIES      3

/*****************************************************************************/
/* LOCAL STRSCPY */
/*****************************************************************************/

#ifndef STRSCPY
#define STRSCPY(dst, src)                         \
    do {                                          \
        strncpy((dst), (src), sizeof(dst) - 1);  \
        (dst)[sizeof(dst) - 1] = '\0';           \
    } while (0)
#endif

/*****************************************************************************/
/* CLIENT EVENT TYPES */
/*****************************************************************************/


/*****************************************************************************/
/* TREE */
/*****************************************************************************/

static int
mac_cmp(const void *a,
        const void *b)
{
    return memcmp(a, b, 6);
}

ds_tree_t g_client_tree =
    DS_TREE_INIT(
        mac_cmp,
        client_state_t,
        node);

/*****************************************************************************/
/* EXTERNAL */
/*****************************************************************************/

extern bool target_info_clients_get(
    const uint8_t *macaddr,
    const char *ifname,
    client_info_event_t *client_info,
    uint64_t timestamp_ms,
    bool is_connected);

extern int get_client_capability(
    const char *ifname,
    client_info_event_t *client_info);

client_state_t *
stamonitord_client_lookup(
    const uint8_t *macaddr)
{
    if (!macaddr)
        return NULL;

    return ds_tree_find(
        &g_client_tree,
        macaddr);
}

void
stamonitord_client_history_free(
    client_state_t *client)
{
    history_domain_t *d;

    if (!client)
        return;

    while ((d = ds_tree_head(&client->history.domains))) {
        ds_tree_remove(&client->history.domains, d);
        free(d);
    }

    client->history.domain_count = 0;
}

/*****************************************************************************/
/* METADATA COMPLETE */
/*****************************************************************************/

static bool
client_metadata_complete(
    const client_info_event_t *info)
{
    if (!info)
        return false;

    /*
     * DHCP/IP not ready
     */
    if (strcmp(info->ipaddr,
               "0.0.0.0") == 0)
    {
        return false;
    }

    /*
     * Unknown hostname
     */
    if (strcmp(info->hostname,
               "unknown") == 0)
    {
        return false;
    }

    return true;
}

/*****************************************************************************/
/* OS RESOLUTION */
/*****************************************************************************/

static void
resolve_client_osinfo(
    client_info_event_t *client)
{
    char fp[256];

    char *os_info_result;

    if (!client)
        return;

    /*
     * Original DHCP fingerprint
     */
    if (client->osinfo[0] == '\0')
        return;

    memset(fp, 0, sizeof(fp));

    strncpy(
        fp,
        client->osinfo,
        sizeof(fp) - 1);

    os_info_result =
        get_os_info(fp, NULL);

    if (!os_info_result ||
        os_info_result[0] == '\0')
    {
        return;
    }

    strncpy(
        client->osinfo,
        os_info_result,
        sizeof(client->osinfo) - 1);

    client->osinfo[
        sizeof(client->osinfo) - 1] =
            '\0';
}

/*****************************************************************************/
/* CAPABILITY */
/*****************************************************************************/

static void
client_fill_capability(
    client_info_event_t *client_info,
    const char *ifname)
{
    if (!client_info || !ifname)
        return;

    if (get_client_capability(
            ifname,
            client_info) == 0)
    {
        LOG(INFO,
            "Collected client capability");
    }
}

/*****************************************************************************/
/* RUNTIME CACHE LOOKUP */
/*****************************************************************************/

static void
client_fill_runtime_info(
    client_info_event_t *client_info,
    const char *ifname)
{
    struct vif_state *vif;

    if (!client_info || !ifname)
        return;

    pthread_mutex_lock(
        &g_vif_info_mutex);

    /*
     * VIF lookup
     */
    vif = vif_cache_lookup_by_ifname(
        ifname);

    if (vif && vif->valid) {

        STRSCPY(
            client_info->ssid,
            vif->current.ssid);

        STRSCPY(
            client_info->band,
            vif->current.band);
    }

    if (vif && vif->valid) {

        radio_info_t radio_info;

        memset(
            &radio_info,
            0,
            sizeof(radio_info));

        if (radio_cache_lookup_by_band(
            vif->current.band,
            &radio_info))
        {
            client_info->channel =
                radio_info.channel;

            LOG(INFO,
                "CLIENT CHANNEL=%d",
                radio_info.channel);
        }
    }


    pthread_mutex_unlock(
        &g_vif_info_mutex);
}

/*****************************************************************************/
/* COMPLETE ENRICHMENT */
/*****************************************************************************/

static void
client_enrich_metadata(
    client_info_event_t *client_info,
    const char *ifname)
{
    if (!client_info || !ifname)
        return;

    /*
     * Resolve DHCP fingerprint
     */
    resolve_client_osinfo(
        client_info);

    /*
     * Client capability
     */
    client_fill_capability(
        client_info,
        ifname);

    LOG(INFO,
    "CLIENT LOOKUP ifname=%s",
    ifname);
    /*
     * Runtime wireless cache
     */
    client_fill_runtime_info(
        client_info,
        ifname);
}

/*****************************************************************************/
/* TIMER CALLBACK */
/*****************************************************************************/

static void
client_metadata_retry_cb(
    EV_P_ ev_timer *w,
    int revents)
{
    client_state_t *client;

    client_info_event_t new_info = {0};

    bool changed = false;

    uint64_t ts;

    (void)revents;

    client = w->data;

    if (!client)
        return;

    if (!client->connected)
        goto done;

    if (client->metadata_complete)
        goto done;

    if (client->metadata_retry_count >=
        METADATA_MAX_RETRIES)
    {
        LOG(DEBUG,
            "Metadata retries exhausted");

        goto done;
    }

    ts = get_timestamp_ms();

    /*
     * Refresh metadata
     */
    if (!target_info_clients_get(
            client->mac,
            client->ifname,
            &new_info,
            ts,
            true))
    {
        goto retry;
    }

    /*
     * Full metadata enrichment
     */
    client_enrich_metadata(
        &new_info,
        client->ifname);

    /*
     * hostname
     */
    if (new_info.hostname[0] &&
        strcmp(client->info.hostname,
               new_info.hostname) != 0)
    {
        STRSCPY(
            client->info.hostname,
            new_info.hostname);

        changed = true;
    }

    /*
     * ip
     */
    if (new_info.ipaddr[0] &&
        strcmp(client->info.ipaddr,
               new_info.ipaddr) != 0)
    {
        STRSCPY(
            client->info.ipaddr,
            new_info.ipaddr);

        changed = true;
    }

    /*
     * osinfo
     */
    if (new_info.osinfo[0] &&
        strcmp(client->info.osinfo,
               new_info.osinfo) != 0)
    {
        STRSCPY(
            client->info.osinfo,
            new_info.osinfo);

        changed = true;
    }

    /*
     * capability
     */
    if (memcmp(
            &client->info.capability,
            &new_info.capability,
            sizeof(client_capability_t)) != 0)
    {
        memcpy(
            &client->info.capability,
            &new_info.capability,
            sizeof(client_capability_t));

        changed = true;
    }

    if (changed) {

        client->info.event_type =
            CLIENT_EVENT_UPDATE;

        stamonitord_send_client_info_event(
            &client->info,
            ts);
    }

    if (client_metadata_complete(
            &client->info))
    {
        client->metadata_complete =
            true;

        goto done;
    }

retry:

    client->metadata_retry_count++;

    return;

done:

    ev_timer_stop(
        EV_A_ &client->metadata_timer);
}

/*****************************************************************************/
/* CONNECT */
/*****************************************************************************/

void
stamonitord_handle_client_connect(
    const uint8_t *macaddr,
    const char *ifname)
{
    client_state_t *client;

    client_info_event_t info = {0};

    uint64_t ts;

    ts = get_timestamp_ms();

    client = ds_tree_find(
        &g_client_tree,
        macaddr);

    /*
     * ROAM
     */
    if (client) {

        /*
         * Same interface reconnect
         */
        if (strcmp(client->ifname,
                   ifname) == 0)
        {
            return;
        }

        LOG(INFO,
                "Client roam %02x:%02x:%02x:%02x:%02x:%02x %s -> %s",
                macaddr[0],
                macaddr[1],
                macaddr[2],
                macaddr[3],
                macaddr[4],
                macaddr[5],
                client->ifname,
                ifname);

        STRSCPY(
            client->ifname,
            ifname);

        /*
         * Refresh wireless runtime info
         */
        client_fill_runtime_info(
            &client->info,
            ifname);

        client->info.event_type =
            CLIENT_EVENT_UPDATE;

        stamonitord_send_client_info_event(
            &client->info,
            ts);

        return;
    }

    /*
     * NEW CLIENT
     */
    client = calloc(1, sizeof(*client));

    LOG(INFO,
    "CLIENT CONNECT %02x:%02x:%02x:%02x:%02x:%02x if=%s",
    macaddr[0],
    macaddr[1],
    macaddr[2],
    macaddr[3],
    macaddr[4],
    macaddr[5],
    ifname);

    if (!client)
        return;

    if (!target_info_clients_get(
            macaddr,
            ifname,
            &info,
            ts,
            true))
    {
        free(client);

        return;
    }

    /*
     * Full metadata enrichment
     */
    client_enrich_metadata(
        &info,
        ifname);

    info.event_type =
        CLIENT_EVENT_CONNECT;

    info.is_connected = true;

    memcpy(
        client->mac,
        macaddr,
        6);

    STRSCPY(
        client->ifname,
        ifname);

    memcpy(
        &client->info,
        &info,
        sizeof(info));

    client->connected = true;
    client->disconnected_ms = 0;

    ds_tree_init(
        &client->history.domains,
        history_domain_cmp,
        history_domain_t,
        node);

    client->history.first_seen_ms = ts;
    client->history.last_seen_ms = ts;

    client->metadata_complete =
        client_metadata_complete(
            &info);

    ds_tree_insert(
        &g_client_tree,
        client,
        client->mac);

    LOG(INFO,
    "CLIENT INSERTED");

    /*
     * Initial connect
     */
    stamonitord_send_client_info_event(
        &info,
        ts);
    
    stamonitord_history_notify_station_connect(macaddr, ifname);

    /*
     * Metadata retry
     */
    if (!client->metadata_complete) {

        ev_timer_init(
            &client->metadata_timer,
            client_metadata_retry_cb,
            METADATA_RETRY_INTERVAL,
            METADATA_RETRY_INTERVAL);

        client->metadata_timer.data =
            client;

        ev_timer_start(
            EV_DEFAULT,
            &client->metadata_timer);
        LOG(INFO,
            "Starting metadata retry timer");
    }
}

/*****************************************************************************/
/* DISCONNECT */
/*****************************************************************************/

void
stamonitord_handle_client_disconnect(
    const uint8_t *macaddr,
    const char *ifname)
{
    client_state_t *client;

    uint64_t ts;

    client = ds_tree_find(
        &g_client_tree,
        macaddr);


    if (!client) {

        LOG(ERR,
            "CLIENT NOT FOUND IN TREE");

        return;
    }


    LOG(INFO,
    "CLIENT DISCONNECT %02x:%02x:%02x:%02x:%02x:%02x if=%s",
    macaddr[0],
    macaddr[1],
    macaddr[2],
    macaddr[3],
    macaddr[4],
    macaddr[5],
    ifname);
    /*
     * Ignore stale disconnect
     * after roam
     */
    if (strcmp(client->ifname,
               ifname) != 0)
    {
        return;
    }

    ts = get_timestamp_ms();

    client->info.event_type =
        CLIENT_EVENT_DISCONNECT;

    client->info.is_connected =
        false;

    client->info.end_time =
        ts;

    client->connected = false;
    client->disconnected_ms = ts;

    stamonitord_send_client_info_event(
        &client->info,
        ts);

    ev_timer_stop(
        EV_DEFAULT,
        &client->metadata_timer);

    ds_tree_remove(
        &g_client_tree,
        client);

    stamonitord_client_history_free(client);

    free(client);
}
