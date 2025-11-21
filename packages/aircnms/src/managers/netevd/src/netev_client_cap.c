#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "log.h"
#include "netev_client_cap.h"
#include "info_events.h"
#include "netev_info_events.h"
#include "stats_report.h"

/**
 * Parse MCS and NSS from VHT MCS map
 * VHT MCS map format: 2 bits per stream (00=MCS 0-7, 01=MCS 0-8, 10=MCS 0-9, 11=not supported)
 */
static void parse_vht_mcs_nss(const char *vht_mcs_map, char *mcs, char *nss) {
    if (!vht_mcs_map || strlen(vht_mcs_map) < 4) {
        strcpy(mcs, "N/A");
        strcpy(nss, "N/A");
        return;
    }

    unsigned long map = strtoul(vht_mcs_map, NULL, 16);
    int max_nss = 0;
    int max_mcs = 0;

    // Check each 2-bit pair for NSS 1-8
    for (int i = 0; i < 8; i++) {
        int mcs_support = (map >> (i * 2)) & 0x3;
        if (mcs_support != 3) { // 3 means not supported
            max_nss = i + 1;
            if (mcs_support == 0) max_mcs = 7;
            else if (mcs_support == 1) max_mcs = 8;
            else if (mcs_support == 2) max_mcs = 9;
        }
    }

    snprintf(mcs, 8, "%d", max_mcs);
    snprintf(nss, 8, "%d", max_nss);
}

/**
 * Get client capability from hostapd_cli sta command
 *
 * @param ifname Interface name (e.g., "phy1-ap0")
 * @param client_info Pointer to client_info_event_t structure to fill
 * @return 0 on success, -1 on failure
 */
int get_client_capability(const char *ifname, client_info_event_t *client_info) {
    if (!ifname || !client_info) {
        return -1;
    }

    char cmd[256];
    char macaddr_str[18];
    FILE *fp;
    char line[512];

    // Convert MAC address from uint8_t array to string
    snprintf(macaddr_str, sizeof(macaddr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             client_info->macaddr[0], client_info->macaddr[1],
             client_info->macaddr[2], client_info->macaddr[3],
             client_info->macaddr[4], client_info->macaddr[5]);

    // Build hostapd_cli command
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s sta %s", ifname, macaddr_str);

    // Execute command
    fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Failed to execute command: %s\n", cmd);
        return -1;
    }

    // Initialize capability fields
    memset(&client_info->capability, 0, sizeof(client_capability_t));
    strcpy(client_info->capability.phy, "N/A");
    strcpy(client_info->capability.roaming, "N/A");
    strcpy(client_info->capability.mcs, "N/A");
    strcpy(client_info->capability.nss, "N/A");
    strcpy(client_info->capability.ps, "N/A");
    strcpy(client_info->capability.wmm, "No");
    strcpy(client_info->capability.mu_mimo, "No");
    strcpy(client_info->capability.ofdma, "No");
    strcpy(client_info->capability.bw, "N/A");

    char vht_mcs_map[16] = {0};
    int has_ht = 0, has_vht = 0, has_he = 0;

    // Parse output
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Parse flags line for PHY and capabilities
        if (strncmp(line, "flags=", 6) == 0) {
            if (strstr(line, "[HE]")) {
                strcpy(client_info->capability.phy, "HE");
                has_he = 1;
            } else if (strstr(line, "[VHT]")) {
                strcpy(client_info->capability.phy, "VHT");
                has_vht = 1;
            } else if (strstr(line, "[HT]")) {
                strcpy(client_info->capability.phy, "HT");
                has_ht = 1;
            }

            if (strstr(line, "[WMM]")) {
                strcpy(client_info->capability.wmm, "Yes");
            }
        }

        // Parse VHT MCS map
        if (strncmp(line, "tx_vht_mcs_map=", 15) == 0) {
            sscanf(line, "tx_vht_mcs_map=%s", vht_mcs_map);
        }

        // Parse VHT capabilities for bandwidth and MU-MIMO
        if (strncmp(line, "vht_capab=", 10) == 0) {
            char vht_capab[32];
            sscanf(line, "vht_capab=%s", vht_capab);

            unsigned long caps = strtoul(vht_capab, NULL, 16);

            // Bandwidth - bits 2-3
            int bw_support = (caps >> 2) & 0x3;
            if (bw_support == 0) strcpy(client_info->capability.bw, "80");
            else if (bw_support == 1) strcpy(client_info->capability.bw, "160");
            else if (bw_support == 2) strcpy(client_info->capability.bw, "80+80");

            // MU-MIMO - bit 19 for MU beamformee
            if (caps & (1 << 19)) {
                strcpy(client_info->capability.mu_mimo, "Yes");
            }
        }

        // Parse HE capabilities for OFDMA
        if (strncmp(line, "he_capab=", 9) == 0 && has_he) {
            strcpy(client_info->capability.ofdma, "Yes");
        }

        // Parse extended capabilities for roaming (11k, 11r, 11v)
        if (strncmp(line, "ext_capab=", 10) == 0) {
            char ext_capab[64];
            sscanf(line, "ext_capab=%s", ext_capab);

            // Basic roaming support detection (simplified)
            if (strlen(ext_capab) > 0) {
                strcpy(client_info->capability.roaming, "11k");
            }
        }
    }

    pclose(fp);

    // Parse MCS and NSS from VHT MCS map if available
    if (strlen(vht_mcs_map) > 0 && (has_vht || has_he)) {
        parse_vht_mcs_nss(vht_mcs_map, client_info->capability.mcs,
                          client_info->capability.nss);
    }

    // Set bandwidth based on PHY if not already set
    if (strcmp(client_info->capability.bw, "N/A") == 0) {
        if (has_he || has_vht) {
            strcpy(client_info->capability.bw, "80");
        } else if (has_ht) {
            strcpy(client_info->capability.bw, "40");
        } else {
            strcpy(client_info->capability.bw, "20");
        }
    }

    return 0;
}

