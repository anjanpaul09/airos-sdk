#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ifaddrs.h>   
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <net/if.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/wireless.h>

#include "nl80211.h"
#include "../../../platform/mtk/target/target_nl80211.h"

// Forward declaration for if_nametoindex (from net/if.h but conflicting with linux/if.h)
// Using function declaration to avoid header conflict
unsigned int if_nametoindex(const char *ifname);
#define MAX_LINE_LENGTH 100
#define IFACE_NAME_LEN 16

static int num_iface;

static int nl80211_parse_wiface(struct nl_msg *msg, void *arg) 
{
    char (*wlan_ifname)[IFACE_NAME_LEN] = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFNAME]) {
        strncpy(wlan_ifname[num_iface], nla_get_string(tb[NL80211_ATTR_IFNAME]), IFACE_NAME_LEN - 1);
        wlan_ifname[num_iface][IFACE_NAME_LEN - 1] = '\0';
        num_iface++;
    }

    return NL_SKIP;
}

int nl80211_get_wiface(char (*wlan_ifname)[16]) 
{
    struct nl_msg *msg;

    msg = nlmsg_init(get_nl_sm_global(), NL80211_CMD_GET_INTERFACE, 1);
    if (!msg)
        return -EINVAL;

    return nlmsg_send_and_recv(get_nl_sm_global(), msg, nl80211_parse_wiface, wlan_ifname);
}

static int nl80211_check_if_ssid_matches(struct nl_msg *msg, void *arg) 
{
    struct {
        int *ssid_match;
        const char *target_ssid;
        const char *iface_name;
    } *match_data = arg;

    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFNAME] && strcmp(nla_get_string(tb[NL80211_ATTR_IFNAME]), match_data->iface_name) != 0) {
        return NL_SKIP; 
    }

    if (tb[NL80211_ATTR_SSID]) {
        char ssid[IW_ESSID_MAX_SIZE + 1];
        strncpy(ssid, nla_get_string(tb[NL80211_ATTR_SSID]), IW_ESSID_MAX_SIZE);
        ssid[IW_ESSID_MAX_SIZE] = '\0';

        if (strcmp(ssid, match_data->target_ssid) == 0) {
            *match_data->ssid_match = 1;
            return NL_STOP;  
        }
    }

    return NL_SKIP;
}

static int parse_ssid_cb(struct nl_msg *msg, void *arg) 
{
    struct nlattr **tb = arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);
    return NL_OK;
}

bool ifname_has_ssid(const char *ifname, const char *target_ssid) 
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    if (!nl_sm_global) return false;

    struct nl_msg *msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_INTERFACE, 0);
    if (!msg) return false;

    int ifidx = if_nametoindex(ifname);
    if (ifidx == 0) return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifidx);

    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};

    if (nlmsg_send_and_recv(nl_sm_global, msg, parse_ssid_cb, tb) < 0)
        return false;

    if (!tb[NL80211_ATTR_SSID])
        return false;

    char ssid[33] = {0};
    int ssid_len = nla_len(tb[NL80211_ATTR_SSID]);
    memcpy(ssid, nla_data(tb[NL80211_ATTR_SSID]), ssid_len);
    ssid[ssid_len] = '\0';

    return strcmp(ssid, target_ssid) == 0;
}


int check_interface_ssid(const char *iface_name, const char *target_ssid) {
    struct nl_msg *msg;
    int ssid_match = 0;
    struct {
        int *ssid_match;
        const char *target_ssid;
        const char *iface_name;
    } match_data = { &ssid_match, target_ssid, iface_name };

    msg = nlmsg_init(get_nl_sm_global(), NL80211_CMD_GET_INTERFACE, 1);
    if (!msg)
        return -EINVAL;

    nla_put_string(msg, NL80211_ATTR_IFNAME, iface_name);

    int ret = nlmsg_send_and_recv(get_nl_sm_global(), msg, nl80211_check_if_ssid_matches, &match_data);

    if (ret < 0) {
        fprintf(stderr, "Failed to get SSID for interface '%s'\n", iface_name);
        return -1;
    }

    if (ssid_match) {
        printf("Interface '%s' has SSID matching '%s'\n", iface_name, target_ssid);
        return 1;
    } else {
        printf("Interface '%s' does not have SSID matching '%s'\n", iface_name, target_ssid);
        return 0;
    }
}

int target_acl_add_blacklist(char *ifname, char *macaddr)
{
    char hostapd_cmd[256];

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s set macaddr_acl 0", ifname);
    system(hostapd_cmd);

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s deny_acl ADD_MAC %s",ifname, macaddr);
    system(hostapd_cmd);

    return 0;
}

int target_acl_del_blacklist(char *ifname, char *macaddr)
{
    char hostapd_cmd[256];

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s deny_acl DEL_MAC %s",ifname, macaddr);
    system(hostapd_cmd);

    return 0;
}


int target_acl_flush_blacklist(char *ifname)
{
    char hostapd_cmd[256];

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s deny_acl CLEAR", ifname);
    system(hostapd_cmd);

    return 0;
}

void trim_whitespace(char *str) 
{
    char *end;

    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) {
        return; 
    }

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    end[1] = '\0';
}

int check_acl_empty(const char *iface) 
{
    char command[256];
    snprintf(command, sizeof(command), "hostapd_cli -i %s accept_acl SHOW", iface);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }

    char buffer[256];
    int acl_empty = 1;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        trim_whitespace(buffer);
        if (strlen(buffer) > 0) {
            acl_empty = 0;
            break;
        }
    }

    pclose(fp);
    return acl_empty;
}

int target_acl_add_whitelist(char *ifname, char *macaddr)
{
    char hostapd_cmd[256];

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s set macaddr_acl 1", ifname);
    system(hostapd_cmd);

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s accept_acl ADD_MAC %s",ifname, macaddr);
    system(hostapd_cmd);

    return 0;
}

int target_acl_del_whitelist(char *ifname, char *macaddr)
{
    char hostapd_cmd[256];
    int acl_check;

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s accept_acl DEL_MAC %s",ifname, macaddr);
    system(hostapd_cmd);
    
    acl_check = check_acl_empty(ifname);
    if ( acl_check == 1) {
        memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
        sprintf(hostapd_cmd, "hostapd_cli -i %s set macaddr_acl 0", ifname);
        system(hostapd_cmd);
    }

    return 0;
}

//for all active ifname
int target_acl_flush_whitelist(char *ifname)
{
    char hostapd_cmd[256];

    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s accept_acl CLEAR", ifname);
    system(hostapd_cmd);
    
    memset(hostapd_cmd, 0, sizeof(hostapd_cmd));
    sprintf(hostapd_cmd, "hostapd_cli -i %s set macaddr_acl 0", ifname);
    system(hostapd_cmd);

    return 0;
}

bool get_ssid_from_interface(const char *ifname, char *essid)
{
    FILE *fp;
    char cmd[MAX_LINE_LENGTH];
    char line[MAX_LINE_LENGTH];
    char *ssid = NULL;
 
    // Check if the interface exists
    if (if_nametoindex(ifname) == 0) {
        fprintf(stderr, "Interface %s does not exist: %s\n", ifname, strerror(errno));
        return false;
    }

    snprintf(cmd, sizeof(cmd), "iw dev %s info | grep ssid | cut -d ' ' -f 2-", ifname);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return false;
    }

    if (fgets(line, sizeof(line), fp) != NULL) {
        char *newline = strchr(line, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }
        ssid = strdup(line);
        if (ssid) {
            strcpy(essid, ssid);
            free(ssid);  // FIX: Free strdup'd memory immediately after use
            ssid = NULL;
        }
    }

    pclose(fp);

    return true;
}
void mac_to_lower(char *mac) {
    for (int i = 0; mac[i]; i++) {
        mac[i] = tolower(mac[i]);
    }
}

int compare_mac_addresses(const char *mac1, const char *mac2) {
    char mac1_lower[18], mac2_lower[18];
    strcpy(mac1_lower, mac1);
    strcpy(mac2_lower, mac2);
    mac_to_lower(mac1_lower);
    mac_to_lower(mac2_lower);
    return strcmp(mac1_lower, mac2_lower);
}

bool check_sta_mac_addresses(const char *iface, const char *target_mac) 
{
    char command[256];
    bool found = false;

    snprintf(command, sizeof(command), "iw dev %s station dump", iface);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return found;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strncmp(buffer, "Station", 7) == 0) {
            char mac_address[18];
            sscanf(buffer, "Station %17s", mac_address);
            printf("MAC Address: %s\n", mac_address);

            if (compare_mac_addresses(mac_address, target_mac) == 0) {
                printf("MAC Address %s matches the target MAC %s\n", mac_address, target_mac);
                found = true;
                break;
            }
        }
    }

    pclose(fp);
    return found;
}

bool netconf_handle_add_blacklist(char *mac)
{
    char wlan_ifname[8][16];
    __attribute__((unused)) char target_ssid[64];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);
#if 0
    for (int i = 0; i < num_iface; i++) {
        if (check_sta_mac_addresses(wlan_ifname[i], mac)) {
            if (get_ssid_from_interface(wlan_ifname[i], target_ssid) == 0) {
                break;
            } else {
                fprintf(stderr, "Failed to get SSID from interface '%s'\n", wlan_ifname[i]);
            }
        }
    }
#endif

    for (int i = 0; i < num_iface; ++i) {
        if (strlen(wlan_ifname[i]) == 0){
            continue;
        }

        target_acl_add_blacklist(wlan_ifname[i], mac);
    }

    return true;
}

bool netconf_handle_add_blacklist_ssid(char *mac, char *target_ssid)
{
    char wlan_ifname[8][16];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);
    for (int i = 0; i < num_iface; ++i) {
        if (strlen(wlan_ifname[i]) == 0)
            continue;

        if (ifname_has_ssid(wlan_ifname[i], target_ssid)) {
            target_acl_add_blacklist(wlan_ifname[i], mac);
        }
    }

    return true;
}

bool netconf_handle_remove_blacklist(char *mac)
{
    char wlan_ifname[8][16];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);

    for (int i = 0; i < num_iface; i++) {
        target_acl_del_blacklist(wlan_ifname[i], mac);
    }

    return true;
}

bool netconf_handle_add_whitelist(char *mac)
{
    char wlan_ifname[8][16];
    __attribute__((unused)) char target_ssid[64];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);

#if 0
    for (int i = 0; i < num_iface; i++) {
        if (check_sta_mac_addresses(wlan_ifname[i], mac)) {
            if (get_ssid_from_interface(wlan_ifname[i], target_ssid) == 0) {
                break;
            } else {
                fprintf(stderr, "Failed to get SSID from interface '%s'\n", wlan_ifname[i]);
            }
        }
    }
#endif

    for (int i = 0; i < num_iface; ++i) {
        if (strlen(wlan_ifname[i]) == 0) {
            continue;
        }

        target_acl_add_whitelist(wlan_ifname[i], mac);
    }

    return true;
}

bool netconf_handle_add_whitelist_ssid(char *mac, char *target_ssid)
{
    char wlan_ifname[8][16];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);
    for (int i = 0; i < num_iface; ++i) {
        if (strlen(wlan_ifname[i]) == 0)
            continue;

        if (ifname_has_ssid(wlan_ifname[i], target_ssid)) {
            target_acl_add_whitelist(wlan_ifname[i], mac);
        }
    }

    return true;
}

bool netconf_handle_remove_whitelist(char *mac)
{
    char wlan_ifname[8][16];
    num_iface = 0;

    nl80211_get_wiface(wlan_ifname);

    for (int i = 0; i < num_iface; i++) {
        target_acl_del_whitelist(wlan_ifname[i], mac);
    }

    return true;
}
