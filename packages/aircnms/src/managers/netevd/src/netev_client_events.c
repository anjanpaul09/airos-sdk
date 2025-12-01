#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include "dhcp_fp.h"
#include "log.h"
#include "info_events.h"
#include "netev_info_events.h"
#include "stats_report.h"
#include "netev_client_cap.h"

// Forward declaration - target_info_clients_get is defined in platform/mtk/target/target_stats.c
bool target_info_clients_get(const uint8_t *macaddr, const char *ifname, 
                             client_info_event_t *client_info, uint64_t timestamp_ms, bool is_connect);

void resolve_client_osinfo(client_info_event_t *client)
{
    if (!client) {
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

/* Handle client connect event */
void netev_handle_client_connect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "netev_handle_client_connect: NULL macaddr");
        return;
    }
    
    client_info_event_t client_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    sleep(2); 
    // Call target function to fill client info
    if (!target_info_clients_get(macaddr, ifname, &client_info, timestamp_ms, true)) {
        LOG(ERR, "Failed to get client info from target");
        return;
    }
 
    resolve_client_osinfo(&client_info);
    if (get_client_capability(ifname, &client_info) == 0) {
        printf("Client Capabilities:\n");
        printf("  PHY: %s\n", client_info.capability.phy);
        printf("  Roaming: %s\n", client_info.capability.roaming);
        printf("  MCS: %s\n", client_info.capability.mcs);
        printf("  NSS: %s\n", client_info.capability.nss);
        printf("  WMM: %s\n", client_info.capability.wmm);
        printf("  MU-MIMO: %s\n", client_info.capability.mu_mimo);
        printf("  OFDMA: %s\n", client_info.capability.ofdma);
        printf("  Bandwidth: %s MHz\n", client_info.capability.bw);
    } else {
        printf("Failed to get client capabilities\n");
    }

    client_info.is_connected = true;
    // Send client info event
    LOG(INFO, "Client connected: MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5], 
        ifname ? ifname : "unknown");
    
    if (!netev_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client connect info event");
    }
}

/* Handle client disconnect event */
void netev_handle_client_disconnect(const uint8_t *macaddr, const char *ifname)
{
    if (!macaddr) {
        LOG(ERR, "netev_handle_client_disconnect: NULL macaddr");
        return;
    }
    
    client_info_event_t client_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    
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
    
    if (!netev_send_client_info_event(&client_info, timestamp_ms)) {
        LOG(ERR, "Failed to send client disconnect info event");
    }
}

