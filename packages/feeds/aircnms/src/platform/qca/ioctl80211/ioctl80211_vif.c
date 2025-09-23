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
//#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/wireless.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "util.h"

#include "ioctl80211.h"
#include "ioctl80211_client.h"

#include "dpp_vif_stats.h"

typedef ioctl80211_client_record_t target_client_record_t;
//#include "target_qca.h"
//Anjan

#define MODULE_ID LOG_MODULE_ID_TARGET

/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
#define MAX_LINE_LENGTH 100

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

long long str_to_ll(const char *str) 
{
    if (str == NULL) return 0;

    char *endptr;
    long long value = strtoll(str, &endptr, 10);
    if (*endptr != '\0') {
        // Conversion failed
        return 0;
    }
    return value;
}

bool check_wlan_iface_exists(const char *ifname, char *protocol)
{
    int sock = -1;
    struct iwreq pwrq;

    memset(&pwrq, 0, sizeof(pwrq));
    strncpy(pwrq.ifr_name, ifname, IFNAMSIZ);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return 0;
    }

    if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1) {
        if (protocol) {
            strncpy(protocol, pwrq.u.name, IFNAMSIZ);
	}
        close(sock);
        return true;
    }

    close(sock);

    return false;
}


int get_num_wlan_iface(char (*wifname)[16])
{
    struct ifaddrs *ifaddr, *ifa;
    int num_iface = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        char protocol[IFNAMSIZ]  = {0};

        if (ifa->ifa_addr == NULL ||
            ifa->ifa_addr->sa_family != AF_PACKET) continue;

        if (check_wlan_iface_exists(ifa->ifa_name, protocol)) {
            strcpy(wifname[num_iface], ifa->ifa_name);
            num_iface++;
        } else {
            printf("interface %s is not wireless\n", ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);

    return num_iface;
}


int get_num_sta(char* ifname, char *ssid, int rtype)
{
    radio_entry_t radio_cfg;
    radio_essid_t essid;
    ds_dlist_t client_list = DS_DLIST_INIT(target_client_record_t, node);
    void *client_ctx = NULL;
    target_client_record_t *cl;
    int ret, num_client = 0;

    strcpy(radio_cfg.if_name, ifname);
    radio_cfg.type = rtype;
    strcpy(essid, ssid);

    ioctl_status_t rc;
    ret = ioctl80211_client_list_get(&radio_cfg, NULL, &client_list);

    while (!ds_dlist_is_empty(&client_list)) {
        cl = ds_dlist_head(&client_list);
	if (!strcmp(cl->info.essid, ssid)) {
            num_client++;
        }
        ds_dlist_remove(&client_list, cl);
    }

    return num_client;
}

bool get_essid(const char *ifname, char *essid)
{
    FILE *fp;
    char cmd[MAX_LINE_LENGTH];
    char line[MAX_LINE_LENGTH];
    char *ssid = NULL;

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
    }

    pclose(fp);

    strcpy(essid, ssid);

    return true;
}

bool ioctl80211_stats_vap_get(dpp_vif_record_t *record)
{
    char essid[IW_ESSID_MAX_SIZE + 1];
    char buf[16];
    char sys_path[128];
    long long tx_bytes = 0, rx_bytes = 0;
    long tx_mb, rx_mb;
    int num_sta = 0;
    char wlan_ifname[8][16];
    radio_type_t rtype;

    record->n_vif = get_num_wlan_iface(wlan_ifname);
    for (int i = 0; i < record->n_vif; i++) {

        printf("Anjan: wiface = %s\n", wlan_ifname[i]);

        util_get_vif_radio(wlan_ifname[i], &buf, 4);
        printf("Anjan: vif radio = %s\n", buf);

        if (strcmp(buf, "phy1") == 0) {
            strcpy(record->vif[i].radio, "BAND2G");
	    rtype = RADIO_TYPE_2G;
        } else if ( strcmp(buf, "phy0") == 0) {
            strcpy(record->vif[i].radio, "BAND5G");
	    rtype = RADIO_TYPE_5G;
        }


        if (get_essid(wlan_ifname[i], essid)) {
            printf("Anjan: ESSID of %s: %s\n", wlan_ifname[i], essid);
            strcpy(record->vif[i].ssid, essid);
        } else {
            printf("Failed to get ESSID \n");
        }

        record->vif[i].num_sta = get_num_sta(wlan_ifname[i], essid, rtype);

        memset(&buf, 0, sizeof(buf));
        memset(&sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/tx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, &buf, sizeof(buf)) < 0) {
            printf("Failed to retrive tx bytes of %s\n", wlan_ifname[i]);
        }
        rtrimws(buf);

        tx_bytes = str_to_ll(buf);;
        tx_mb = tx_bytes / (1024 * 1024);
        record->vif[i].uplink_mb = tx_mb;


        memset(&buf, 0, sizeof(buf));
        memset(&sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/rx_bytes", wlan_ifname[i]);
        if (util_file_read_str(sys_path, &buf, sizeof(buf)) == 0) {
            printf("Failed to retrive rx bytes of %s\n", wlan_ifname[i]);
        }
        rtrimws(buf);

        rx_bytes = str_to_ll(buf);;
        printf("Anjan: rx bytes = %lld\n", rx_bytes);
        rx_mb = rx_bytes / (1024 * 1024);
        record->vif[i].downlink_mb = rx_mb;
        printf("Anjan: rx mb = %ld\n", rx_mb);

        printf("-----------------------\n");
    }

    return true;
}

bool ioctl80211_stats_radio_get(dpp_vif_record_t *record)
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    char phyname[4];
    char param[4];
    int channel;
    int ret;

    record->n_radio = 2;

	//2G
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy1");

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

    record->radio[0].channel_utilization = 20;

    //5G
    memset(phyname, 0, sizeof(phyname));
    strcpy(phyname, "phy0");

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

    record->radio[1].channel_utilization = 20;
	
    return true;
}

bool ioctl80211_stats_vif_get(dpp_vif_record_t *record)
{
    ioctl80211_stats_vap_get(record);
    ioctl80211_stats_radio_get(record);

    return true;
}
