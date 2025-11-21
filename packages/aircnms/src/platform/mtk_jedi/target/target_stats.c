#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "ioctl80211_jedi.h"
#include "report.h"
//Anjan
#include "MT7621.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool target_stats_clients_get(client_report_data_t *client_list);
bool target_info_clients_get(client_report_data_t *client_list);
bool target_info_vif_get(vif_record_t *record);
bool target_stats_vif_get(vif_record_t *record);
bool target_stats_neighbor_get(neighbor_report_data_t *report);
/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/
bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(if_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/

bool target_info_clients_get(client_report_data_t *client_list)
{
    // Fill client info with dummy data for now
    if (!client_list || !client_list->record) {
        return false;
    }

    for (int i = 0; i < client_list->n_client; i++) {
        client_record_t *rec = &client_list->record[i];
        
        // Fill info with dummy data
        strncpy(rec->info.hostname, "realme-13-Pro-5G", HOSTNAME_MAX_LEN - 1);
        strncpy(rec->info.ipaddr, "192.168.16.143", IPADDR_MAX_LEN - 1);
        strncpy(rec->info.ssid, "Diff-NAT", SSID_MAX_LEN - 1);
        strncpy(rec->info.band, "BAND2G", sizeof(rec->info.band) - 1);
        rec->info.channel = 6;
        rec->info.is_connected = 1;
        strncpy(rec->info.client_type, "wireless", sizeof(rec->info.client_type) - 1);
        strncpy(rec->info.osinfo, "android", sizeof(rec->info.osinfo) - 1);
        rec->info.start_time = 1762968000000;
        rec->info.end_time = 1762969105455;
        
        // Fill capability
        strncpy(rec->info.capability.phy, "HE", sizeof(rec->info.capability.phy) - 1);
        strncpy(rec->info.capability.roaming, "11kr", sizeof(rec->info.capability.roaming) - 1);
        strncpy(rec->info.capability.mcs, "11", sizeof(rec->info.capability.mcs) - 1);
        strncpy(rec->info.capability.nss, "2", sizeof(rec->info.capability.nss) - 1);
        strncpy(rec->info.capability.ps, "1", sizeof(rec->info.capability.ps) - 1);
        strncpy(rec->info.capability.wmm, "1", sizeof(rec->info.capability.wmm) - 1);
        strncpy(rec->info.capability.mu_mimo, "0", sizeof(rec->info.capability.mu_mimo) - 1);
        strncpy(rec->info.capability.ofdma, "1", sizeof(rec->info.capability.ofdma) - 1);
        strncpy(rec->info.capability.bw, "80", sizeof(rec->info.capability.bw) - 1);
    }

    return true;
}

bool target_stats_clients_get(client_report_data_t *client_list)
{
    ioctl_status_t rc;
    rc = ioctl80211_jedi_client_list_get(client_list);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    // Now fill only stats with dummy data
    if (!client_list || !client_list->record) {
        return false;
    }

    for (int i = 0; i < client_list->n_client; i++) {
        client_record_t *rec = &client_list->record[i];
        
        // Fill stats with dummy data
        rec->stats.duration_ms = 20896000;
        rec->stats.rssi = -78;
        rec->stats.snr = 28;
        rec->stats.tx_rate_mbps = 173;
        rec->stats.rx_rate_mbps = 72;
        rec->stats.tx_bytes = 4119379993;
        rec->stats.rx_bytes = 454820901;
        rec->stats.tx_packets = 928133;
        rec->stats.rx_packets = 421023;
        rec->stats.tx_retries = 12011;
        rec->stats.tx_failures = 42;
        rec->stats.tx_phy_rate = 433;
        rec->stats.rx_phy_rate = 200;
        rec->stats.signal_avg = -70;
    }

    return true;
}

/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
#define MAX_LINE_LENGTH 100

bool target_info_vif_get(vif_record_t *record)
{
    if (!record) {
        return false;
    }
    
    // Fill info with dummy data for now
    strncpy(record->info.serialNum, "AIR587BE924EF9A", sizeof(record->info.serialNum) - 1);
    strncpy(record->info.macAddr, "587BE924EF9A", sizeof(record->info.macAddr) - 1);
    
    // Fill radio info
    record->info.n_radio = 2;
    strncpy(record->info.radio[0].band, "BAND2G", sizeof(record->info.radio[0].band) - 1);
    record->info.radio[0].channel = 6;
    record->info.radio[0].txpower = 25;
    
    strncpy(record->info.radio[1].band, "BAND5G", sizeof(record->info.radio[1].band) - 1);
    record->info.radio[1].channel = 36;
    record->info.radio[1].txpower = 30;
    
    // Fill VIF info
    record->info.n_vif = 2;
    strncpy(record->info.vif[0].radio, "BAND5G", sizeof(record->info.vif[0].radio) - 1);
    strncpy(record->info.vif[0].ssid, "Anjan-Test", sizeof(record->info.vif[0].ssid) - 1);
    
    strncpy(record->info.vif[1].radio, "BAND2G", sizeof(record->info.vif[1].radio) - 1);
    strncpy(record->info.vif[1].ssid, "Anjan-Test", sizeof(record->info.vif[1].ssid) - 1);
    
    // Fill ethernet info with dummy data
    record->info.n_ethernet = 3;
    strncpy(record->info.ethernet[0].interface, "eth0", sizeof(record->info.ethernet[0].interface) - 1);
    strncpy(record->info.ethernet[0].name, "WAN", sizeof(record->info.ethernet[0].name) - 1);
    strncpy(record->info.ethernet[0].type, "wan", sizeof(record->info.ethernet[0].type) - 1);
    
    strncpy(record->info.ethernet[1].interface, "eth1", sizeof(record->info.ethernet[1].interface) - 1);
    strncpy(record->info.ethernet[1].name, "LAN1", sizeof(record->info.ethernet[1].name) - 1);
    strncpy(record->info.ethernet[1].type, "lan", sizeof(record->info.ethernet[1].type) - 1);
    
    strncpy(record->info.ethernet[2].interface, "eth2", sizeof(record->info.ethernet[2].interface) - 1);
    strncpy(record->info.ethernet[2].name, "LAN2", sizeof(record->info.ethernet[2].name) - 1);
    strncpy(record->info.ethernet[2].type, "lan", sizeof(record->info.ethernet[2].type) - 1);
    
    return true;
}

bool target_stats_vif_get(vif_record_t *record)
{
    // Get stats from ioctl (this will need to be updated to work with new structure)
    // For now, fill stats with dummy data
    if (!record) {
        return false;
    }
    
    // Fill radio stats
    record->stats.n_radio = 2;
    strncpy(record->stats.radio[0].band, "BAND2G", sizeof(record->stats.radio[0].band) - 1);
    record->stats.radio[0].channel_utilization = 30;
    
    strncpy(record->stats.radio[1].band, "BAND5G", sizeof(record->stats.radio[1].band) - 1);
    record->stats.radio[1].channel_utilization = 2;
    
    // Fill VIF stats
    record->stats.n_vif = 2;
    strncpy(record->stats.vif[0].radio, "BAND5G", sizeof(record->stats.vif[0].radio) - 1);
    strncpy(record->stats.vif[0].ssid, "Anjan-Test", sizeof(record->stats.vif[0].ssid) - 1);
    record->stats.vif[0].statNumSta = 0;
    record->stats.vif[0].statUplinkMb = 301;
    record->stats.vif[0].statDownlinkMb = 71;
    
    strncpy(record->stats.vif[1].radio, "BAND2G", sizeof(record->stats.vif[1].radio) - 1);
    strncpy(record->stats.vif[1].ssid, "Anjan-Test", sizeof(record->stats.vif[1].ssid) - 1);
    record->stats.vif[1].statNumSta = 1;
    record->stats.vif[1].statUplinkMb = 15;
    record->stats.vif[1].statDownlinkMb = 0;
    
    // Fill ethernet stats with dummy data
    record->stats.n_ethernet = 3;
    strncpy(record->stats.ethernet[0].interface, "eth0", sizeof(record->stats.ethernet[0].interface) - 1);
    record->stats.ethernet[0].rxBytes = 1234567890;
    record->stats.ethernet[0].txBytes = 987654321;
    record->stats.ethernet[0].rxPackets = 1234567;
    record->stats.ethernet[0].txPackets = 987654;
    record->stats.ethernet[0].rxErrors = 0;
    record->stats.ethernet[0].txErrors = 0;
    record->stats.ethernet[0].rxDropped = 0;
    record->stats.ethernet[0].txDropped = 0;
    record->stats.ethernet[0].speed = 1000;
    strncpy(record->stats.ethernet[0].duplex, "full", sizeof(record->stats.ethernet[0].duplex) - 1);
    record->stats.ethernet[0].link = 1;
    
    strncpy(record->stats.ethernet[1].interface, "eth1", sizeof(record->stats.ethernet[1].interface) - 1);
    record->stats.ethernet[1].rxBytes = 2345678901;
    record->stats.ethernet[1].txBytes = 876543210;
    record->stats.ethernet[1].rxPackets = 2345678;
    record->stats.ethernet[1].txPackets = 876543;
    record->stats.ethernet[1].rxErrors = 0;
    record->stats.ethernet[1].txErrors = 0;
    record->stats.ethernet[1].rxDropped = 0;
    record->stats.ethernet[1].txDropped = 0;
    record->stats.ethernet[1].speed = 1000;
    strncpy(record->stats.ethernet[1].duplex, "full", sizeof(record->stats.ethernet[1].duplex) - 1);
    record->stats.ethernet[1].link = 1;
    
    strncpy(record->stats.ethernet[2].interface, "eth2", sizeof(record->stats.ethernet[2].interface) - 1);
    record->stats.ethernet[2].rxBytes = 3456789012;
    record->stats.ethernet[2].txBytes = 765432109;
    record->stats.ethernet[2].rxPackets = 3456789;
    record->stats.ethernet[2].txPackets = 765432;
    record->stats.ethernet[2].rxErrors = 0;
    record->stats.ethernet[2].txErrors = 0;
    record->stats.ethernet[2].rxDropped = 0;
    record->stats.ethernet[2].txDropped = 0;
    record->stats.ethernet[2].speed = 100;
    strncpy(record->stats.ethernet[2].duplex, "half", sizeof(record->stats.ethernet[2].duplex) - 1);
    record->stats.ethernet[2].link = 0;
    
    return true;
}

/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_neighbor_get(neighbor_report_data_t *report)
{
    ioctl_status_t rc;

    rc = ioctl80211_jedi_scan_results_get(report);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

