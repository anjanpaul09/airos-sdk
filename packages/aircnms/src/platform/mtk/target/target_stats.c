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

#include "stats_report.h"
#include "info_events.h"
//Anjan
#include "MT7621.h"

// Forward declarations
bool nl80211_stats_scan_get(neighbor_report_data_t *report);
bool nl80211_stats_vif_get(vif_record_t *record);
bool nl80211_stats_vap_get(vif_record_t *record);
bool nl80211_stats_radio_get(vif_record_t *record);
bool get_all_ethernet_stats(vif_record_t *record);
bool get_all_ethernet_info(vif_info_event_t *vif_info);
int get_channel_from_cmd(const char *iface);


#define MODULE_ID LOG_MODULE_ID_TARGET

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
    
    // Set timestamps
    if (is_connect) {
        client_info->start_time = timestamp_ms;
        client_info->end_time = 0;
    } else {
        client_info->start_time = 0; // Unknown on disconnect
        client_info->end_time = timestamp_ms;
        return true; //return on disconnect
    }
    
    
    snprintf(client_info->hostname, HOSTNAME_MAX_LEN, "unknown");
    snprintf(client_info->ipaddr, IPADDR_MAX_LEN, "0.0.0.0");
    snprintf(client_info->osinfo, sizeof(client_info->osinfo), "unknown");
    snprintf(client_info->client_type, sizeof(client_info->client_type), "wireless");

    // Determine interface name to use.
    const char *use_ifname = ifname ? ifname : "unknown";
    
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
    
    
    return true;
}

bool target_stats_clients_get(client_report_data_t *client_list)
{
    bool ret;

    ret = nl80211_stats_clients_get(client_list);
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
    
    uint8_t ch = get_channel_from_cmd("phy0-ap0");
    if (!ch) {
        ch = 6;
    } 
    vif_info->radio[0].channel = ch;
    
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
    ch = get_channel_from_cmd("phy1-ap0");
    if (!ch) {
        ch = 36;
    } 
    vif_info->radio[1].channel = ch;
    
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
    
    get_all_ethernet_info(vif_info);
    
    return true;
}

bool target_stats_vif_get(vif_record_t *record)
{
    bool ret;
    // Get stats from nl80211 (this will need to be updated to work with new structure)
    // For now, fill stats with dummy data
    if (!record) {
        return false;
    }
   
    ret = nl80211_stats_vif_get(record);
    ret = get_all_ethernet_stats(record);
    return ret;
}
