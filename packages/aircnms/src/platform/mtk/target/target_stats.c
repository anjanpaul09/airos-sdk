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
#include <linux/wireless.h>
#include <sys/ioctl.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "nl80211.h"
#include "target_nl80211.h"

#include "nl80211_stats.h"
#include "nl80211_client.h"
#include "nl80211_survey.h"
#include "nl80211_scan.h"
#include "nl80211_device.h"
#include "target_util.h"

// Forward declarations
bool nl80211_stats_scan_get(neighbor_report_data_t *report);
bool nl80211_stats_vif_get(vif_record_t *record);
bool nl80211_stats_vap_get(vif_record_t *record);
bool nl80211_stats_radio_get(vif_record_t *record);

#include "stats_report.h"
#include "info_events.h"
#include "airdpi/air_ioctl.h"
//Anjan
#include "MT7621.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

//bool nl80211_stats_vif_get(dpp_vif_record_t *record);
/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/

static bool
check_interface_exists(char *if_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, if_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


static bool
check_radio_exists(char *phy_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir(CONFIG_MAC80211_WIPHY_PATH))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, phy_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = check_radio_exists(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = check_interface_exists(if_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/

bool target_info_clients_get(const uint8_t *macaddr, const char *ifname, 
                             client_info_event_t *client_info, uint64_t timestamp_ms, bool is_connect)
{
    if (!macaddr || !client_info) {
        return false;
    }
    
    memset(client_info, 0, sizeof(client_info_event_t));
    
    // Copy MAC address
    memcpy(client_info->macaddr, macaddr, 6);
    
    // Determine interface name to use (will be set from ioctl if available)
    const char *use_ifname = ifname ? ifname : "unknown";
    char ioctl_ifname[12] = {0};
    
    // Get client info from airdpi ioctl
    struct adpi_sta_data sta;
    memset(&sta, 0, sizeof(sta));
    memcpy(sta.macaddr, macaddr, 6);
    sta.result_valid = 0;
    
    int fd = open("/dev/air", O_RDWR);
    if (fd < 0) {
        LOG(ERR, "Failed to open /dev/air: %s", strerror(errno));
        // Fallback to defaults
        snprintf(client_info->hostname, HOSTNAME_MAX_LEN, "unknown");
        snprintf(client_info->ipaddr, IPADDR_MAX_LEN, "0.0.0.0");
        snprintf(client_info->osinfo, sizeof(client_info->osinfo), "unknown");
        snprintf(client_info->client_type, sizeof(client_info->client_type), "wireless");
        
    } else {
        printf("Ankit: call IOCTL \n");
        if (ioctl(fd, IOCTL_ADPI_GET_STA_DATA, &sta) < 0) {
            LOG(ERR, "IOCTL_ADPI_GET_STA_DATA failed: %s", strerror(errno));
        printf("Ankit: call IOCTL failed: %s\n", strerror(errno));
            close(fd);
            // Fallback to defaults
            snprintf(client_info->hostname, HOSTNAME_MAX_LEN, "unknown");
            snprintf(client_info->ipaddr, IPADDR_MAX_LEN, "0.0.0.0");
            snprintf(client_info->osinfo, sizeof(client_info->osinfo), "unknown");
            snprintf(client_info->client_type, sizeof(client_info->client_type), "wireless");
            
        } else {
            close(fd);
            
        printf("Ankit: call IOCTL valid\n");
            if (sta.result_valid) {
                struct sta_info *info = &sta.info;
                
                // Copy hostname
                strncpy(client_info->hostname, info->hostname, HOSTNAME_MAX_LEN - 1);
                client_info->hostname[HOSTNAME_MAX_LEN - 1] = '\0';
                
                // Convert IP from uint32_t to string
                struct in_addr addr;
                addr.s_addr = info->ip;
                const char *ip_str = inet_ntoa(addr);
                if (ip_str) {
                    strncpy(client_info->ipaddr, ip_str, IPADDR_MAX_LEN - 1);
                    client_info->ipaddr[IPADDR_MAX_LEN - 1] = '\0';
                } else {
                    snprintf(client_info->ipaddr, IPADDR_MAX_LEN, "0.0.0.0");
                }
                
                // Copy OS info
                strncpy(client_info->osinfo, info->os_name, sizeof(client_info->osinfo) - 1);
                client_info->osinfo[sizeof(client_info->osinfo) - 1] = '\0';
                
                // Set client type based on is_wireless
                if (info->is_wireless) {
                    snprintf(client_info->client_type, sizeof(client_info->client_type), "wireless");
                } else {
                    snprintf(client_info->client_type, sizeof(client_info->client_type), "wired");
                }
                
                // Use ifname from ioctl if available, otherwise use passed parameter
                if (info->ifname[0] != '\0') {
                    strncpy(ioctl_ifname, info->ifname, sizeof(ioctl_ifname) - 1);
                    ioctl_ifname[sizeof(ioctl_ifname) - 1] = '\0';
                    use_ifname = ioctl_ifname;
                }
            } else {
        printf("Ankit: call IOCTL sta not found\n");
                // Client not found in airdpi
                snprintf(client_info->hostname, HOSTNAME_MAX_LEN, "unknown");
                snprintf(client_info->ipaddr, IPADDR_MAX_LEN, "0.0.0.0");
                snprintf(client_info->osinfo, sizeof(client_info->osinfo), "unknown");
                snprintf(client_info->client_type, sizeof(client_info->client_type), "wireless");
                
                // Fill default capability
                memset(&client_info->capability, 0, sizeof(client_capability_t));
                snprintf(client_info->capability.phy, sizeof(client_info->capability.phy), "unknown");
                snprintf(client_info->capability.roaming, sizeof(client_info->capability.roaming), "unknown");
                snprintf(client_info->capability.mcs, sizeof(client_info->capability.mcs), "0");
                snprintf(client_info->capability.nss, sizeof(client_info->capability.nss), "1");
                snprintf(client_info->capability.ps, sizeof(client_info->capability.ps), "0");
                snprintf(client_info->capability.wmm, sizeof(client_info->capability.wmm), "0");
                snprintf(client_info->capability.mu_mimo, sizeof(client_info->capability.mu_mimo), "0");
                snprintf(client_info->capability.ofdma, sizeof(client_info->capability.ofdma), "0");
                snprintf(client_info->capability.bw, sizeof(client_info->capability.bw), "20");
            }
        }
    }
    
    // Get SSID, band, and channel from interface using iw commands
    FILE *fp_cmd;
    char cmd[256];
    char line[256];
    
    // Get SSID
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | grep ssid | cut -d ' ' -f 2-", use_ifname);
    fp_cmd = popen(cmd, "r");
    if (fp_cmd) {
        if (fgets(line, sizeof(line), fp_cmd) != NULL) {
            char *newline = strchr(line, '\n');
            if (newline) *newline = '\0';
            // Trim whitespace
            char *start = line;
            while (*start == ' ' || *start == '\t') start++;
            char *end = start + strlen(start) - 1;
            while (end > start && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
            *(end + 1) = '\0';
            // Limit SSID length to fit in destination buffer
            size_t ssid_len = strlen(start);
            if (ssid_len >= sizeof(client_info->ssid)) {
                ssid_len = sizeof(client_info->ssid) - 1;
            }
            strncpy(client_info->ssid, start, ssid_len);
            client_info->ssid[ssid_len] = '\0';
        } else {
            snprintf(client_info->ssid, sizeof(client_info->ssid), "unknown");
        }
        pclose(fp_cmd);
    } else {
        snprintf(client_info->ssid, sizeof(client_info->ssid), "unknown");
    }
    
    // Get band from frequency
    snprintf(cmd, sizeof(cmd), "iw dev %s info | awk -F'[()]' '/channel/ {print $2}' | awk '{print $1}'", use_ifname);
    fp_cmd = popen(cmd, "r");
    if (fp_cmd) {
        if (fgets(line, sizeof(line), fp_cmd) != NULL) {
            int freq = atoi(line);
            if (freq >= 2400 && freq <= 2500) {
                snprintf(client_info->band, sizeof(client_info->band), "BAND2G");
            } else if (freq >= 5000 && freq <= 6000) {
                snprintf(client_info->band, sizeof(client_info->band), "BAND5G");
            } else {
                snprintf(client_info->band, sizeof(client_info->band), "UNKNOWN");
            }
        } else {
            snprintf(client_info->band, sizeof(client_info->band), "UNKNOWN");
        }
        pclose(fp_cmd);
    } else {
        snprintf(client_info->band, sizeof(client_info->band), "UNKNOWN");
    }
    
    // Get channel
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | grep 'channel' | awk '{print $2}'", use_ifname);
    fp_cmd = popen(cmd, "r");
    if (fp_cmd) {
        if (fgets(line, sizeof(line), fp_cmd) != NULL) {
            client_info->channel = (uint32_t)atoi(line);
        } else {
            client_info->channel = 0;
        }
        pclose(fp_cmd);
    } else {
        client_info->channel = 0;
    }
    
    // Set timestamps
    if (is_connect) {
        client_info->start_time = timestamp_ms;
        client_info->end_time = 0;
    } else {
        client_info->start_time = 0; // Unknown on disconnect
        client_info->end_time = timestamp_ms;
    }
    
    return true;
}

bool target_stats_clients_get(client_report_data_t *client_list)
{
    bool ret;

    ret = nl80211_stats_clients_get(client_list);
#if 0
    // Now fill only stats with dummy data (overwrite what nl80211 got)
    if (!client_list || !client_list->record) {
        return ret;
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
#endif
    return ret;
}

/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_neighbor_get(neighbor_report_data_t *scan_results)
{
    return nl80211_stats_scan_get(scan_results);
}

/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
#define MAX_LINE_LENGTH 100

bool target_info_vif_get(vif_info_event_t *vif_info)
{
    if (!vif_info) {
        return false;
    }
    
    memset(vif_info, 0, sizeof(vif_info_event_t));
    
    // Get device serial number and MAC (these should come from device config)
    // For now, use placeholder - should be filled from device_config.h or similar
    snprintf(vif_info->serialNum, sizeof(vif_info->serialNum), "AIR587BE924EF9A");
    snprintf(vif_info->macAddr, sizeof(vif_info->macAddr), "587BE924EF9A");
    
    // Fill radio info from UCI
    vif_info->n_radio = 2;
    
    // 2G Radio
    char buf[256];
    char param[4];
    size_t len;
    
    snprintf(vif_info->radio[0].band, sizeof(vif_info->radio[0].band), "BAND2G");
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    (void)cmd_buf("uci get wireless.wifi1.channel", buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[0].channel = atoi(param);
    } else {
        vif_info->radio[0].channel = 6; // default
    }
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    (void)cmd_buf("uci get wireless.wifi1.txpower", buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[0].txpower = atoi(param);
    } else {
        vif_info->radio[0].txpower = 25; // default
    }
    
    // 5G Radio
    snprintf(vif_info->radio[1].band, sizeof(vif_info->radio[1].band), "BAND5G");
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    (void)cmd_buf("uci get wireless.wifi0.channel", buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[1].channel = atoi(param);
    } else {
        vif_info->radio[1].channel = 36; // default
    }
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    (void)cmd_buf("uci get wireless.wifi0.txpower", buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[1].txpower = atoi(param);
    } else {
        vif_info->radio[1].txpower = 30; // default
    }
    
    // Fill VIF info from interfaces by scanning /sys/class/net
    // This avoids dependency on nl_sm_init which may not be available in netevd
    vif_info->n_vif = 0;
    DIR *net_dir = opendir("/sys/class/net");
    if (net_dir) {
        struct dirent *entry;
        char phy_buf[16];
        
        while ((entry = readdir(net_dir)) != NULL && vif_info->n_vif < MAX_VIF) {
            // Skip . and .. and non-wireless interfaces
            if (entry->d_name[0] == '.' || 
                strncmp(entry->d_name, "eth", 3) == 0 ||
                strncmp(entry->d_name, "lo", 2) == 0) {
                continue;
            }
            
            // Check if it's a wireless interface by trying to get phy
            if (util_get_vif_radio(entry->d_name, phy_buf, sizeof(phy_buf)) == 0) {
                // Determine radio band from phy
                if (strcmp(phy_buf, "phy0") == 0) {
                    snprintf(vif_info->vif[vif_info->n_vif].radio, 
                            sizeof(vif_info->vif[vif_info->n_vif].radio), "BAND2G");
                } else if (strcmp(phy_buf, "phy1") == 0) {
                    snprintf(vif_info->vif[vif_info->n_vif].radio, 
                            sizeof(vif_info->vif[vif_info->n_vif].radio), "BAND5G");
                } else {
                    continue; // Skip if phy is not phy0 or phy1
                }
                
                // Get SSID using iw command
                FILE *fp;
                char cmd[512];
                char line[256];
                int cmd_len = snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | grep 'ssid' | cut -d ' ' -f 2-", entry->d_name);
                if (cmd_len >= (int)sizeof(cmd)) {
                    // Command truncated, skip this interface
                    continue;
                }
                fp = popen(cmd, "r");
                if (fp) {
                    if (fgets(line, sizeof(line), fp) != NULL) {
                        char *newline = strchr(line, '\n');
                        if (newline) *newline = '\0';
                        // Trim whitespace
                        char *start = line;
                        while (*start == ' ' || *start == '\t') start++;
                        char *end = start + strlen(start) - 1;
                        while (end > start && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
                        *(end + 1) = '\0';
                        // Limit SSID length to fit in destination buffer
                        size_t ssid_len = strlen(start);
                        if (ssid_len >= sizeof(vif_info->vif[vif_info->n_vif].ssid)) {
                            ssid_len = sizeof(vif_info->vif[vif_info->n_vif].ssid) - 1;
                        }
                        strncpy(vif_info->vif[vif_info->n_vif].ssid, start, ssid_len);
                        vif_info->vif[vif_info->n_vif].ssid[ssid_len] = '\0';
                    }
                    pclose(fp);
                }
                
                vif_info->n_vif++;
            }
        }
        closedir(net_dir);
    }
    
    // Fill ethernet info (placeholder for now - should be read from system)
    vif_info->n_ethernet = 3;
    snprintf(vif_info->ethernet[0].interface, sizeof(vif_info->ethernet[0].interface), "eth0");
    snprintf(vif_info->ethernet[0].name, sizeof(vif_info->ethernet[0].name), "WAN");
    snprintf(vif_info->ethernet[0].type, sizeof(vif_info->ethernet[0].type), "wan");
    
    snprintf(vif_info->ethernet[1].interface, sizeof(vif_info->ethernet[1].interface), "eth1");
    snprintf(vif_info->ethernet[1].name, sizeof(vif_info->ethernet[1].name), "LAN1");
    snprintf(vif_info->ethernet[1].type, sizeof(vif_info->ethernet[1].type), "lan");
    
    snprintf(vif_info->ethernet[2].interface, sizeof(vif_info->ethernet[2].interface), "eth2");
    snprintf(vif_info->ethernet[2].name, sizeof(vif_info->ethernet[2].name), "LAN2");
    snprintf(vif_info->ethernet[2].type, sizeof(vif_info->ethernet[2].type), "lan");
    
    return true;
}

bool target_stats_vif_get(vif_record_t *record)
{
    // Get stats from nl80211 (this will need to be updated to work with new structure)
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
