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
#include "report.h"
//Anjan

#define MODULE_ID LOG_MODULE_ID_TARGET
#define MAX_LINE_LENGTH 100

#define MAX_IFACES 8
#define IFACE_NAME_LEN 16
#define PROC_FILE "cat /proc/airpro/stainfo"

static int iface_count;
/******************************************************************************
 *  VIF definitions
 *****************************************************************************/

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
    int ret;
    char essid[IW_ESSID_MAX_SIZE + 1];
    char buf[16];
    char sys_path[128];
    long long tx_bytes = 0, rx_bytes = 0;
    long tx_mb, rx_mb;
    char wlan_ifname[MAX_IFACES][IFACE_NAME_LEN];
    radio_type_t rtype;
    iface_count = 0;

    if( nl80211_get_wiface(wlan_ifname) < 0) {
        return false;
    }

    record->n_vif = iface_count;
    for (int i = 0; i < record->n_vif; i++) {
        util_get_vif_radio(wlan_ifname[i], &buf, 4);
        if (strcmp(buf, "phy0") == 0) {
            strcpy(record->vif[i].radio, "BAND2G");
        rtype = RADIO_TYPE_2G;
        } else if ( strcmp(buf, "phy1") == 0) {
            strcpy(record->vif[i].radio, "BAND5G");
        rtype = RADIO_TYPE_5G;
        }

        if (get_essid(wlan_ifname[i], essid)) {
            strcpy(record->vif[i].ssid, essid);
        }

        record->vif[i].num_sta = get_num_sta(wlan_ifname[i]);

        memset(&buf, 0, sizeof(buf));
        memset(&sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/tx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, &buf, sizeof(buf)) > 0) {
            rtrimws(buf);

            tx_bytes = str_to_ll(buf);

            if (tx_bytes >= 0) {
                tx_mb = tx_bytes / (1024 * 1024);
                record->vif[i].uplink_mb = tx_mb;
            } else {
                printf("Invalid tx_bytes value for %s\n", wlan_ifname[i]);
                record->vif[i].uplink_mb = 0; 
            }
        } else {
            printf("Failed to retrieve tx bytes of %s\n", wlan_ifname[i]);
            record->vif[i].uplink_mb = 0; 
        }

        memset(&buf, 0, sizeof(buf));
        memset(&sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/rx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, &buf, sizeof(buf)) > 0) { 
            rtrimws(buf);

            rx_bytes = str_to_ll(buf);

            if (rx_bytes >= 0) { 
                rx_mb = rx_bytes / (1024 * 1024);
                record->vif[i].downlink_mb = rx_mb;
            } else {
                printf("Invalid rx_bytes value for %s\n", wlan_ifname[i]);
                record->vif[i].downlink_mb = 0; 
            }
        } else {
            printf("Failed to retrieve rx bytes of %s\n", wlan_ifname[i]);
            record->vif[i].downlink_mb = 0;
        }    

    }
    return true;
}

int get_channel_utilization(radio_stats_t *radio_info)
{
    radio_entry_t radio_cfg;
    uint8_t utilization = 0;
    uint32_t chan_busy = 0, chan_active = 0;
    
    if ( strcmp(radio_info->band, "BAND2G") == 0) {
        strcpy(radio_cfg.if_name, "phy0-ap0");
    } else { 
        strcpy(radio_cfg.if_name, "phy1-ap0");
    }
    radio_cfg.chan = radio_info->channel;

    if (nl80211_stats_survey_get(&radio_cfg, radio_cfg.chan, &chan_busy, &chan_active)) {
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
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    char phyname[4];
    char param[4];
    int channel, channel_busy;
    int ret;

    record->n_radio = 2;

    //2G
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy0");

    strcpy(record->radio[0].band, "BAND2G");
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    rc = cmd_buf("uci get wireless.wifi1.channel", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return;
    }
    sscanf(buf, "%s", param);
    record->radio[0].channel = atoi(param);    

    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    rc = cmd_buf("uci get wireless.wifi1.txpower", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return;
    }
    sscanf(buf, "%s", param);
    record->radio[0].txpower = atoi(param);    

    record->radio[0].channel_utilization = get_channel_utilization(&record->radio[0]);

    //5G
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy1");

    strcpy(record->radio[1].band, "BAND5G");

    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    rc = cmd_buf("uci get wireless.wifi0.channel", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return;
    }
    sscanf(buf, "%s", param);
    record->radio[1].channel = atoi(param);    

    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    rc = cmd_buf("uci get wireless.wifi0.txpower", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return;
    }
    sscanf(buf, "%s", param);
    record->radio[1].txpower = atoi(param);    

    record->radio[1].channel_utilization = get_channel_utilization(&record->radio[1]);
    
    return true;
}

bool nl80211_stats_vif_get(vif_record_t *record)
{
    nl80211_stats_vap_get(record);
    nl80211_stats_radio_get(record);

    return true;
}
