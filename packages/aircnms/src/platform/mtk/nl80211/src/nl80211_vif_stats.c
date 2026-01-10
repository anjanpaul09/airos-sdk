#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>

#include "os.h"
#include "nl80211.h"
#include "target_nl80211.h"
#include "nl80211_client.h"
#include "nl80211_survey.h"
#include "stats_report.h"
#include <ctype.h>
//Anjan

// Forward declaration
bool nl80211_stats_survey_get(radio_entry_t *radio_cfg,
                              uint32_t channel,
                              uint32_t *chan_busy,
                              uint32_t *chan_active);

#define MODULE_ID LOG_MODULE_ID_TARGET
#define MAX_LINE_LENGTH 100

#define MAX_IFACES 8
#define IFACE_NAME_LEN 16
#define PROC_FILE "cat /proc/airpro/stainfo"

int iface_count;
/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
int get_channel_from_cmd(const char *iface)
{
    char cmd[256], buf[64];
    FILE *fp;

    snprintf(cmd, sizeof(cmd),
        "iwinfo %s info | sed -n 's/.*Channel: \\([0-9]\\+\\).*/\\1/p'",
        iface);

    fp = popen(cmd, "r");
    if (!fp)
        return -1;

    if (!fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return -1;
    }

    pclose(fp);
    return atoi(buf);
}

static int nl80211_parse_wiface(struct nl_msg *msg, void *arg) 
{
    char (*wlan_ifname)[IFACE_NAME_LEN] = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFNAME]) {
        strncpy(wlan_ifname[iface_count], nla_get_string(tb[NL80211_ATTR_IFNAME]), IFACE_NAME_LEN - 1);
        wlan_ifname[iface_count][IFACE_NAME_LEN - 1] = '\0';
        iface_count++;
    }

    return NL_SKIP;
}

static int nl80211_get_wiface(char (*wlan_ifname)[16]) 
{
    struct nl_msg *msg;

    msg = nlmsg_init(get_nl_sm_global(), NL80211_CMD_GET_INTERFACE, 1);
    if (!msg)
        return -EINVAL;

    return nlmsg_send_and_recv(get_nl_sm_global(), msg, nl80211_parse_wiface, wlan_ifname);
}

void rtrimws(char *str)
{
    int len;
    len = strlen(str);
    while (len > 0 && isspace(str[len - 1]))
        str[--len] = 0;
}

int util_file_read(const char *path, char *buf, int len)
{
    int fd;
    int err;
    int errno2;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    err = read(fd, buf, len);
    errno2 = errno;
    close(fd);
    errno = errno2;
    return err;
}


int util_file_read_str(const char *path, char *buf, int len)
{
    int rlen;
    buf[0] = 0;
    rlen = util_file_read(path, buf, len);
    if (rlen < 0)
        return rlen;
    buf[rlen] = 0;
    LOGT("%s: '%s' (%d)", path, buf, rlen);
    return rlen;
}


int util_get_vif_radio(const char *in_vif, char *phy_buf, int len)
{
    char sys_path[BFR_SIZE_128];

    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%s/phy80211/name", in_vif);
    if (util_file_read_str(sys_path, phy_buf, len) < 0)
        return -1;

    rtrimws(phy_buf);
    return 0;
}

long long str_to_ll(const char *str) {
    if (str == NULL) return 0;

    char *endptr;
    long long value = strtoll(str, &endptr, 10);
    if (*endptr != '\0') {
        // Conversion failed
        return 0;
    }
    return value;
}

int get_num_sta(char* target_ifname)
{
    FILE *fp;
    char line[256], ifname[12];
    int count = 0;

    fp = popen(PROC_FILE, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%*s %*s %*s %8s", ifname) == 1) {
            if (strcmp(ifname, target_ifname) == 0) {
                count++;
            }
        }
    }

    pclose(fp);
    return count;
}

bool get_essid(const char *ifname, char *essid)
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
        strcpy(essid, ssid);
    }

    pclose(fp);

    return true;
}

bool nl80211_stats_vap_get(vif_record_t *record)
{
    char essid[IW_ESSID_MAX_SIZE + 1];
    char buf[16];
    char sys_path[128];
    long long tx_bytes = 0, rx_bytes = 0;
    long tx_mb, rx_mb;
    char wlan_ifname[MAX_IFACES][IFACE_NAME_LEN];
    iface_count = 0;

    if( nl80211_get_wiface(wlan_ifname) < 0) {
        return false;
    }

    record->stats.n_vif = iface_count;
    /* Info fields (radio, SSID) are now handled by netevd */
    for (int i = 0; i < record->stats.n_vif; i++) {
        util_get_vif_radio(wlan_ifname[i], buf, sizeof(buf));
        if (strcmp(buf, "phy0") == 0) {
            strcpy(record->stats.vif[i].radio, "BAND2G");
        } else if ( strcmp(buf, "phy1") == 0) {
            strcpy(record->stats.vif[i].radio, "BAND5G");
        }

        if (get_essid(wlan_ifname[i], essid)) {
            strcpy(record->stats.vif[i].ssid, essid);
        }

        record->stats.vif[i].statNumSta = get_num_sta(wlan_ifname[i]);

        memset(buf, 0, sizeof(buf));
        memset(sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/tx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, buf, sizeof(buf)) > 0) {
            rtrimws(buf);

            tx_bytes = str_to_ll(buf);

            if (tx_bytes >= 0) {
                tx_mb = tx_bytes / (1024 * 1024);
                record->stats.vif[i].statUplinkMb = tx_mb;
            } else {
                printf("Invalid tx_bytes value for %s\n", wlan_ifname[i]);
                record->stats.vif[i].statUplinkMb = 0; 
            }
        } else {
            printf("Failed to retrieve tx bytes of %s\n", wlan_ifname[i]);
            record->stats.vif[i].statUplinkMb = 0; 
        }

        memset(buf, 0, sizeof(buf));
        memset(sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/rx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, buf, sizeof(buf)) > 0) { 
            rtrimws(buf);

            rx_bytes = str_to_ll(buf);

            if (rx_bytes >= 0) { 
                rx_mb = rx_bytes / (1024 * 1024);
                record->stats.vif[i].statDownlinkMb = rx_mb;
            } else {
                printf("Invalid rx_bytes value for %s\n", wlan_ifname[i]);
                record->stats.vif[i].statDownlinkMb = 0; 
            }
        } else {
            printf("Failed to retrieve rx bytes of %s\n", wlan_ifname[i]);
            record->stats.vif[i].statDownlinkMb = 0;
        }    

    }
    return true;
}

int get_channel_utilization(const char *band, uint8_t channel)
{
    radio_entry_t radio_cfg;
    uint8_t utilization = 0;
    uint32_t chan_busy = 0, chan_active = 0;
    
    if ( strcmp(band, "BAND2G") == 0) {
        strcpy(radio_cfg.if_name, "phy0-ap0");
    } else { 
        strcpy(radio_cfg.if_name, "phy1-ap0");
    }
    radio_cfg.chan = channel;

    if (nl80211_stats_survey_get(&radio_cfg, channel, &chan_busy, &chan_active)) {
        if (chan_active > 0) {
            utilization = (chan_busy * 100) / chan_active;
        } else {
            printf("Warning: chan_active is zero, cannot compute utilization.\n");
        }
    }

    return utilization;
}

bool nl80211_stats_radio_get(vif_record_t *record)
{
    char phyname[8];

    record->stats.n_radio = 2;
    /* Info fields (band, channel, txpower) are now handled by netevd */

    //2G - Fill stats only
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy0");

    strcpy(record->stats.radio[0].band, "BAND2G");
    
    uint8_t ch = get_channel_from_cmd("phy0-ap0");
    if (!ch) {
        ch = 6;
    } 
    uint8_t channel_2g = ch;

    // Fill stats - channel utilization
    record->stats.radio[0].channel_utilization = get_channel_utilization("BAND2G", channel_2g);

    //5G - Fill stats only
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy1");

    strcpy(record->stats.radio[1].band, "BAND5G");

    ch = get_channel_from_cmd("phy1-ap0");
    if (!ch) {
        ch = 36;
    } 
    uint8_t channel_5g = ch;
    
    // Fill stats - channel utilization
    record->stats.radio[1].channel_utilization = get_channel_utilization("BAND5G", channel_5g);
    
    return true;
}

bool nl80211_stats_vif_get(vif_record_t *record)
{
    nl80211_stats_vap_get(record);
    nl80211_stats_radio_get(record);

    return true;
}
