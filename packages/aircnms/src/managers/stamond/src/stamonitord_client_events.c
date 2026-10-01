#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <ev.h>
#include "dhcp_fp.h"
#include "log.h"
#include "info_events.h"
#include "stamonitord_info_events.h"
#include "stats_report.h"
#include "stamonitord_client_cap.h"
#include "stamonitord_history.h"
#include "stamonitord_client_events.h"

// Forward declaration - target_info_clients_get is defined in platform/mtk/target/target_stats.c
bool target_info_clients_get(const uint8_t *macaddr, const char *ifname, 
                             client_info_event_t *client_info, uint64_t timestamp_ms, bool is_connect);

void resolve_client_osinfo(client_info_event_t *client)
{
    if (!client) {
        return;
    }

    if (client->osinfo[0] == '\0' || strcmp(client->osinfo, "unknown") == 0) {
        snprintf(client->osinfo, sizeof(client->osinfo), "unknown");
        return;
    }

    /* osinfo contains DHCP option fingerprint string initially */
    char fp[256];
    strncpy(fp, client->osinfo, sizeof(fp) - 1);
    fp[sizeof(fp) - 1] = '\0';

    // Get OS info and copy to static buffer
    char *os_info_result = get_os_info(fp, NULL);
    strncpy(client->osinfo, os_info_result, sizeof(client->osinfo) - 1);
    client->osinfo[sizeof(client->osinfo) - 1] = '\0';
    
    return;
}

static void fill_client_ip_from_history(client_info_event_t *client)
{
    if (!client)
        return;

    if (client->ipaddr[0] && strcmp(client->ipaddr, "0.0.0.0") != 0)
        return;

    char ipaddr[IPADDR_MAX_LEN] = {0};
    if (stamonitord_history_lookup_station_ip(client->macaddr,
                                              ipaddr,
                                              sizeof(ipaddr))) {
        snprintf(client->ipaddr, sizeof(client->ipaddr), "%s", ipaddr);
    }
}

static void fill_client_identity_from_leases_and_arp(client_info_event_t *client)
{
    if (!client)
        return;

    stamonitord_history_fill_identity_from_leases_and_arp(client->macaddr,
                                                          client->ipaddr, sizeof(client->ipaddr),
                                                          client->hostname, sizeof(client->hostname));
}

static void enrich_client_identity(client_info_event_t *client)
{
    if (!client)
        return;

    char ipaddr[IPADDR_MAX_LEN] = {0};
    char hostname[HOSTNAME_MAX_LEN] = {0};
    char dhcp_options[128] = {0};
    char dhcp_vendor[64] = {0};

    if (stamonitord_history_lookup_client_identity(client->macaddr,
                                                   ipaddr,
                                                   sizeof(ipaddr),
                                                   hostname,
                                                   sizeof(hostname),
                                                   dhcp_options,
                                                   sizeof(dhcp_options),
                                                   dhcp_vendor,
                                                   sizeof(dhcp_vendor))) {
        if (ipaddr[0])
            snprintf(client->ipaddr, sizeof(client->ipaddr), "%s", ipaddr);

        if (hostname[0])
            snprintf(client->hostname, sizeof(client->hostname), "%s", hostname);

        if (dhcp_options[0]) {
            char *os_info = get_os_info(dhcp_options,
                                        dhcp_vendor[0] ? dhcp_vendor : NULL);

            if (os_info)
                snprintf(client->osinfo, sizeof(client->osinfo), "%s", os_info);
        }
    }

    fill_client_ip_from_history(client);
    fill_client_identity_from_leases_and_arp(client);
}

#define CLIENT_CONNECT_TIMEOUT_SEC 5.0

typedef struct pending_connect {
    uint8_t macaddr[6];
    char ifname[32];
    uint64_t timestamp_ms;
    ev_timer timer;
    struct pending_connect *next;
} pending_connect_t;

static pending_connect_t *g_pending_connects = NULL;

static pending_connect_t *find_pending_connect(const uint8_t *macaddr)
{
    if (!macaddr)
        return NULL;

    for (pending_connect_t *p = g_pending_connects; p; p = p->next) {
        if (memcmp(p->macaddr, macaddr, 6) == 0)
            return p;
    }
    return NULL;
}

static void remove_pending_connect(pending_connect_t *target)
{
    if (!target)
        return;

    ev_timer_stop(EV_DEFAULT, &target->timer);

    pending_connect_t **curr = &g_pending_connects;
    while (*curr) {
        if (*curr == target) {
            *curr = target->next;
            free(target);
            return;
        }
        curr = &(*curr)->next;
    }
}

static void cancel_pending_connect(const uint8_t *macaddr)
{
    pending_connect_t *p = find_pending_connect(macaddr);
    if (p) {
        remove_pending_connect(p);
    }
}

static void dispatch_client_connect(const uint8_t *macaddr, const char *ifname, uint64_t timestamp_ms)
{
    if (!macaddr)
        return;

    client_info_event_t client_info = {0};

    // Call target function to fill client info
    if (!target_info_clients_get(macaddr, ifname, &client_info, timestamp_ms, true)) {
        LOG(ERR, "Failed to get client info from target");
        return;
    }

    enrich_client_identity(&client_info);
    if (get_client_capability(ifname, &client_info) == 0) {
        LOG(INFO, "Collected Client Capabilities\n");
    }

    client_info.is_connected = true;

    // Send client info event
    LOG(INFO, "STA_CONNECTED: mac=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s ssid='%s' band=%s ch=%u ip=%s host='%s' os='%s' phy=%s bw=%s roaming=%s",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5],
        ifname ? ifname : "unknown",
        client_info.ssid[0] ? client_info.ssid : "none",
        client_info.band[0] ? client_info.band : "unknown",
        client_info.channel,
        client_info.ipaddr[0] ? client_info.ipaddr : "0.0.0.0",
        client_info.hostname[0] ? client_info.hostname : "unknown",
        client_info.osinfo[0] ? client_info.osinfo : "unknown",
        client_info.capability.phy[0] ? client_info.capability.phy : "legacy",
        client_info.capability.bw[0] ? client_info.capability.bw : "20",
        client_info.capability.roaming[0] ? client_info.capability.roaming : "none");

    if (!stamonitord_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client connect info event");
    }
}

static void pending_connect_timer_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop;
    (void)revents;

    pending_connect_t *p = (pending_connect_t *)w->data;
    if (!p)
        return;

    uint8_t mac[6];
    char ifname[32];
    uint64_t timestamp_ms = p->timestamp_ms;

    memcpy(mac, p->macaddr, 6);
    strncpy(ifname, p->ifname, sizeof(ifname) - 1);
    ifname[sizeof(ifname) - 1] = '\0';

    remove_pending_connect(p);

    dispatch_client_connect(mac, ifname, timestamp_ms);
}

/* Notification when DHCP IP/identity is resolved for a station */
void stamonitord_client_events_on_dhcp_resolved(const uint8_t *macaddr)
{
    if (!macaddr)
        return;

    pending_connect_t *p = find_pending_connect(macaddr);
    if (!p)
        return;

    uint8_t mac[6];
    char ifname[32];
    uint64_t timestamp_ms = p->timestamp_ms;

    memcpy(mac, p->macaddr, 6);
    strncpy(ifname, p->ifname, sizeof(ifname) - 1);
    ifname[sizeof(ifname) - 1] = '\0';

    remove_pending_connect(p);

    dispatch_client_connect(mac, ifname, timestamp_ms);
}

/* Clean up pending connect timers on daemon exit */
void stamonitord_client_events_cleanup(void)
{
    while (g_pending_connects) {
        remove_pending_connect(g_pending_connects);
    }
}

/* Handle client connect event */
void stamonitord_handle_client_connect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "stamonitord_handle_client_connect: NULL macaddr");
        return;
    }

    uint64_t timestamp_ms = get_timestamp_ms();

    pending_connect_t *p = find_pending_connect(macaddr);
    if (!p) {
        p = calloc(1, sizeof(*p));
        if (!p) {
            LOG(ERR, "Failed to allocate pending connect");
            dispatch_client_connect(macaddr, ifname, timestamp_ms);
            return;
        }
        memcpy(p->macaddr, macaddr, 6);
        p->next = g_pending_connects;
        g_pending_connects = p;
    } else {
        ev_timer_stop(EV_DEFAULT, &p->timer);
    }

    strncpy(p->ifname, ifname ? ifname : "unknown", sizeof(p->ifname) - 1);
    p->ifname[sizeof(p->ifname) - 1] = '\0';
    p->timestamp_ms = timestamp_ms;
    p->timer.data = p;

    ev_timer_init(&p->timer, pending_connect_timer_cb, CLIENT_CONNECT_TIMEOUT_SEC, 0.);
    ev_timer_start(EV_DEFAULT, &p->timer);
}

/* Handle client disconnect event */
void stamonitord_handle_client_disconnect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "stamonitord_handle_client_disconnect: NULL macaddr");
        return;
    }

    // Cancel pending connect timer if station disconnected before DHCP/timeout
    cancel_pending_connect(macaddr);

    client_info_event_t client_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();

    // No nanosleep! Zero freeze on disconnect.
    if (!target_info_clients_get(macaddr, ifname, &client_info, timestamp_ms, false)) {
        LOG(ERR, "Failed to get client info from target");
        return;
    }

    enrich_client_identity(&client_info);
    client_info.is_connected = false;

    // Send client info event
    LOG(INFO, "STA_DISCONNECTED: mac=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s ssid='%s' band=%s ch=%u ip=%s host='%s'",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5],
        ifname ? ifname : "unknown",
        client_info.ssid[0] ? client_info.ssid : "none",
        client_info.band[0] ? client_info.band : "unknown",
        client_info.channel,
        client_info.ipaddr[0] ? client_info.ipaddr : "0.0.0.0",
        client_info.hostname[0] ? client_info.hostname : "unknown");

    if (!stamonitord_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client disconnect info event");
    }
}
