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

__attribute__((weak)) uint8_t stamonitord_vif_monitor_get_channel(const char *ifname)
{
    (void)ifname;
    return 0;
}


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

static uint8_t query_radio_channel(const char *phy_prefix, const char *uci_dev, uint8_t fallback_ch)
{
    char ifname[32];
    int ch = 0;

    // 1. Check runtime monitor cache for primary AP interface (e.g. phy0-ap0, phy1-ap0)
    snprintf(ifname, sizeof(ifname), "%s-ap0", phy_prefix);
    ch = stamonitord_vif_monitor_get_channel(ifname);
    if (ch >= 1 && ch <= 196) {
        return (uint8_t)ch;
    }

    // 2. Check runtime monitor cache for secondary AP interface (e.g. phy0-ap1, phy1-ap1)
    snprintf(ifname, sizeof(ifname), "%s-ap1", phy_prefix);
    ch = stamonitord_vif_monitor_get_channel(ifname);
    if (ch >= 1 && ch <= 196) {
        return (uint8_t)ch;
    }

    // 3. Query primary AP interface via cmd
    snprintf(ifname, sizeof(ifname), "%s-ap0", phy_prefix);
    ch = get_channel_from_cmd(ifname);
    if (ch >= 1 && ch <= 196) {
        return (uint8_t)ch;
    }

    // 4. Query secondary AP interface via cmd
    snprintf(ifname, sizeof(ifname), "%s-ap1", phy_prefix);
    ch = get_channel_from_cmd(ifname);
    if (ch >= 1 && ch <= 196) {
        return (uint8_t)ch;
    }

    // 5. Fallback to UCI wireless configuration
    if (uci_dev && uci_dev[0] != '\0') {
        char ch_buf[16] = {0};
        char uci_cmd[64];
        snprintf(uci_cmd, sizeof(uci_cmd), "uci -q get wireless.%s.channel", uci_dev);
        if (cmd_buf(uci_cmd, ch_buf, sizeof(ch_buf)) == 0) {
            ch = atoi(ch_buf);
            if (ch >= 1 && ch <= 196) {
                return (uint8_t)ch;
            }
        }
    }

    // 6. Hard fallback default
    return fallback_ch;
}

bool target_info_vif_get(vif_info_event_t *vif_info)
{
    if (!vif_info) {
        return false;
    }
    
    memset(vif_info, 0, sizeof(vif_info_event_t));
    
    char buf[256] = {0};
    char param[16] = {0};
    size_t len;

    // Get device serial number and MAC from UCI (with eth0 fallback)
    if (cmd_buf("uci -q get aircnms.@aircnms[0].serial_num", vif_info->serialNum, sizeof(vif_info->serialNum)) != 0 ||
        vif_info->serialNum[0] == '\0') {
        char mac_clean[16] = {0};
        if (cmd_buf("cat /sys/class/net/eth0/address 2>/dev/null | tr -d ':'", mac_clean, sizeof(mac_clean)) == 0) {
            mac_clean[strcspn(mac_clean, "\r\n \t")] = '\0';
            snprintf(vif_info->serialNum, sizeof(vif_info->serialNum), "AIR%.20s", mac_clean);
        } else {
            snprintf(vif_info->serialNum, sizeof(vif_info->serialNum), "AIR000000000000");
        }
    } else {
        vif_info->serialNum[strcspn(vif_info->serialNum, "\r\n \t")] = '\0';
    }

    if (cmd_buf("uci -q get aircnms.@aircnms[0].macaddr", vif_info->macAddr, sizeof(vif_info->macAddr)) != 0 ||
        vif_info->macAddr[0] == '\0') {
        char mac_clean[16] = {0};
        if (cmd_buf("cat /sys/class/net/eth0/address 2>/dev/null | tr -d ':'", mac_clean, sizeof(mac_clean)) == 0) {
            mac_clean[strcspn(mac_clean, "\r\n \t")] = '\0';
            snprintf(vif_info->macAddr, sizeof(vif_info->macAddr), "%.17s", mac_clean);
        } else {
            snprintf(vif_info->macAddr, sizeof(vif_info->macAddr), "000000000000");
        }
    } else {
        vif_info->macAddr[strcspn(vif_info->macAddr, "\r\n \t")] = '\0';
    }
    
    // Fill radio info
    vif_info->n_radio = 2;
    
    // Determine 2G and 5G wifi device names from UCI
    char dev_2g[16] = "wifi1";
    char dev_5g[16] = "wifi0";
    char band_buf[32] = {0};
    if (cmd_buf("uci -q get wireless.wifi0.band", band_buf, sizeof(band_buf)) == 0) {
        band_buf[strcspn(band_buf, "\r\n \t")] = '\0';
        if (strcmp(band_buf, "2g") == 0) {
            strcpy(dev_2g, "wifi0");
            strcpy(dev_5g, "wifi1");
        }
    }

    // 2G Radio
    snprintf(vif_info->radio[0].band, sizeof(vif_info->radio[0].band), "BAND2G");
    vif_info->radio[0].channel = query_radio_channel("phy0", dev_2g, 1);
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    char uci_tx_cmd[64];
    snprintf(uci_tx_cmd, sizeof(uci_tx_cmd), "uci -q get wireless.%s.txpower", dev_2g);
    (void)cmd_buf(uci_tx_cmd, buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[0].txpower = atoi(param);
    } else {
        vif_info->radio[0].txpower = 22;
    }
    
    // 5G Radio
    snprintf(vif_info->radio[1].band, sizeof(vif_info->radio[1].band), "BAND5G");
    vif_info->radio[1].channel = query_radio_channel("phy1", dev_5g, 36);
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    snprintf(uci_tx_cmd, sizeof(uci_tx_cmd), "uci -q get wireless.%s.txpower", dev_5g);
    (void)cmd_buf(uci_tx_cmd, buf, sizeof(buf));
    len = strlen(buf);
    if (len > 0) {
        sscanf(buf, "%s", param);
        vif_info->radio[1].txpower = atoi(param);
    } else {
        vif_info->radio[1].txpower = 20;
    }
    
    // Fill VIF info from active interfaces by scanning /sys/class/net
    vif_info->n_vif = 0;
    DIR *net_dir = opendir("/sys/class/net");
    if (net_dir) {
        struct dirent *entry;
        char phy_buf[16];
        
        while ((entry = readdir(net_dir)) != NULL && vif_info->n_vif < MAX_VIF) {
            // Skip . and .. and non-wireless interfaces
            if (entry->d_name[0] == '.' || 
                strncmp(entry->d_name, "eth", 3) == 0 ||
                strncmp(entry->d_name, "br", 2) == 0 ||
                strncmp(entry->d_name, "lan", 3) == 0 ||
                strncmp(entry->d_name, "wan", 3) == 0 ||
                strncmp(entry->d_name, "lo", 2) == 0) {
                continue;
            }
            
            // Check if it's a wireless interface by trying to get phy
            if (util_get_vif_radio(entry->d_name, phy_buf, sizeof(phy_buf)) == 0) {
                // Check if interface is administratively UP (flags & IFF_UP)
                char sys_flags[512];
                char flags_buf[32] = {0};
                snprintf(sys_flags, sizeof(sys_flags), "/sys/class/net/%.64s/flags", entry->d_name);
                FILE *f_flags = fopen(sys_flags, "r");
                if (f_flags) {
                    if (fgets(flags_buf, sizeof(flags_buf), f_flags) != NULL) {
                        unsigned int flags = (unsigned int)strtoul(flags_buf, NULL, 0);
                        if (!(flags & IFF_UP)) {
                            fclose(f_flags);
                            continue;
                        }
                    }
                    fclose(f_flags);
                }

                // Check operstate (skip interfaces that are down)
                char sys_oper[512];
                char oper_buf[32] = {0};
                snprintf(sys_oper, sizeof(sys_oper), "/sys/class/net/%.64s/operstate", entry->d_name);
                FILE *f_oper = fopen(sys_oper, "r");
                if (f_oper) {
                    if (fgets(oper_buf, sizeof(oper_buf), f_oper) != NULL) {
                        oper_buf[strcspn(oper_buf, "\r\n \t")] = '\0';
                        if (strcmp(oper_buf, "down") == 0) {
                            fclose(f_oper);
                            continue;
                        }
                    }
                    fclose(f_oper);
                }

                // Determine radio band from phy
                char vif_band[8] = {0};
                if (strcmp(phy_buf, "phy0") == 0) {
                    strncpy(vif_band, "BAND2G", sizeof(vif_band) - 1);
                } else if (strcmp(phy_buf, "phy1") == 0) {
                    strncpy(vif_band, "BAND5G", sizeof(vif_band) - 1);
                } else {
                    continue; // Skip if phy is neither phy0 nor phy1
                }

                // Get SSID using iw command
                FILE *fp;
                char cmd[512];
                char line[256];
                snprintf(cmd, sizeof(cmd), "iw dev %.64s info 2>/dev/null | grep 'ssid' | cut -d ' ' -f 2-", entry->d_name);
                fp = popen(cmd, "r");
                char ssid_str[SSID_MAX_LEN] = {0};
                if (fp) {
                    if (fgets(line, sizeof(line), fp) != NULL) {
                        line[strcspn(line, "\r\n")] = '\0';
                        char *start = line;
                        while (*start == ' ' || *start == '\t') start++;
                        char *end = start + strlen(start) - 1;
                        while (end > start && (*end == ' ' || *end == '\t')) end--;
                        *(end + 1) = '\0';
                        if (*start) {
                            strncpy(ssid_str, start, sizeof(ssid_str) - 1);
                        }
                    }
                    pclose(fp);
                }
                
                // Only count as active VIF if SSID is valid and non-empty
                if (ssid_str[0] != '\0') {
                    strncpy(vif_info->vif[vif_info->n_vif].radio, vif_band,
                            sizeof(vif_info->vif[vif_info->n_vif].radio) - 1);
                    strncpy(vif_info->vif[vif_info->n_vif].ssid, ssid_str,
                            sizeof(vif_info->vif[vif_info->n_vif].ssid) - 1);

                    // Update dynamic radio channel from this active VIF
                    int cur_ch = stamonitord_vif_monitor_get_channel(entry->d_name);
                    if (cur_ch < 1 || cur_ch > 196) {
                        cur_ch = get_channel_from_cmd(entry->d_name);
                    }
                    if (cur_ch >= 1 && cur_ch <= 196) {
                        if (strcmp(phy_buf, "phy0") == 0) {
                            vif_info->radio[0].channel = (uint8_t)cur_ch;
                        } else if (strcmp(phy_buf, "phy1") == 0) {
                            vif_info->radio[1].channel = (uint8_t)cur_ch;
                        }
                    }
                    vif_info->n_vif++;
                }
            }
        }
        closedir(net_dir);
    }
    
    // Failproof sanity check: channels must never be 0 or 255
    if (vif_info->radio[0].channel < 1 || vif_info->radio[0].channel > 196) {
        vif_info->radio[0].channel = 1;
    }
    if (vif_info->radio[1].channel < 1 || vif_info->radio[1].channel > 196) {
        vif_info->radio[1].channel = 36;
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
