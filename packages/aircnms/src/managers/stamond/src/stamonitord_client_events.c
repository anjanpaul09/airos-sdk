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
#include "dhcp_fp.h"
#include "log.h"
#include "info_events.h"
#include "stamonitord_info_events.h"
#include "stats_report.h"
#include "stamonitord_client_cap.h"
#include "stamonitord_history.h"

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
}

/* Handle client connect event */
void stamonitord_handle_client_connect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "stamonitord_handle_client_connect: NULL macaddr");
        return;
    }
    
    client_info_event_t client_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    //usleep(3000*1000); 
    struct timespec ts = {
        .tv_sec = 5,
        .tv_nsec = 0
    };
    nanosleep(&ts, NULL);
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
    LOG(INFO, "Client connected: MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s ip=%s",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], 
        ifname ? ifname : "unknown", client_info.ipaddr);
    
    if (!stamonitord_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client connect info event");
    }
}

/* Handle client disconnect event */
void stamonitord_handle_client_disconnect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "stamonitord_handle_client_disconnect: NULL macaddr");
        return;
    }
    
    client_info_event_t client_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    
    struct timespec ts = {
        .tv_sec = 5,
        .tv_nsec = 0
    };
    nanosleep(&ts, NULL);
    
    // Call target function to fill client info
    if (!target_info_clients_get(macaddr, ifname, &client_info, timestamp_ms, false)) {
        LOG(ERR, "Failed to get client info from target");
        return;
    }
    
    client_info.is_connected = false;
    
    // Send client info event
    LOG(INFO, "Client disconnected: MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], 
        ifname ? ifname : "unknown");
    
    if (!stamonitord_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client disconnect info event");
    }
}
