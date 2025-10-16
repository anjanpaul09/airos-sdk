#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <glob.h>
#include <sys/ioctl.h>  
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
#include "report.h"

#define PROC_FILE "cat /proc/airpro/stainfo"

#define MAX_IFACES 10
#define IFACE_LEN  32
#define CMD_BUF_SIZE 128
#define READ_BUF_SIZE 256

/*
typedef enum
{
    RADIO_TYPE_NONE = 0,
    RADIO_TYPE_2G,
    RADIO_TYPE_5G,
    RADIO_TYPE_5GL,
    RADIO_TYPE_5GU,
    RADIO_TYPE_6G
} radio_type_t;
*/

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


int util_get_vif_radio(const char *in_vif, char *phy_buf)
{
    if (!in_vif || !phy_buf) {
        return -1;  // Handle null pointers
    }

    if (strncmp(in_vif, "rax", 3) == 0) {
        strcpy(phy_buf, "rax0");
    } else if (strncmp(in_vif, "ra", 2) == 0) {
        strcpy(phy_buf, "ra0");
    } else {
        return -1;  // Invalid input
    }

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


int get_num_wlan_iface(char (*wifname)[IFACE_LEN])
{
    int num_iface = 0;
    glob_t globbuf;
    int ret;

    ret = glob("/sys/class/net/ra*", 0, NULL, &globbuf);
    if (ret != 0) {
        perror("glob");
        return -1;
    }

    for (size_t i = 0; i < globbuf.gl_pathc; i++) {
        char *path = globbuf.gl_pathv[i];
        // Extract interface name: it's the part after the last '/'
        char *iface = strrchr(path, '/');
        if (iface && *(iface + 1) != '\0') {
            iface++;  // Move past the '/'
        } else {
            iface = path; // Fallback, should not happen.
        }
        strcpy(wifname[num_iface], iface);
        num_iface++;
    }

    globfree(&globbuf);

    return num_iface;
}


int get_num_sta(char *target_ifname, char *ssid, int rtype)
{
    FILE *fp;
    char line[256], ifname[8];
    int count = 0;

    fp = popen(PROC_FILE, "r");
    if (fp == NULL) {
        perror("popen");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%*s %*s %*s %7s", ifname) == 1) {
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

    snprintf(cmd, sizeof(cmd), "iwconfig %s | grep 'ESSID' | awk -F '\"' '{print $2}'", ifname);

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
       
        strcpy(essid, line);
    }

    pclose(fp);

    return true;
}

// This function executes "ip link show <ifname>" and checks for "state UP"
bool is_interface_up(const char *ifname) 
{
    char command[CMD_BUF_SIZE];
    char buffer[READ_BUF_SIZE];
    bool up = false;
    FILE *fp;

    // Construct the command: "ip link show <ifname>"
    snprintf(command, sizeof(command), "ip link show %s", ifname);

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return false;
    }

    // Read each line from the output.
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Check if the output contains "state UP"
        if (strstr(buffer, "state UP") != NULL || strstr(buffer, "state UNKNOWN") != NULL) {
            up = true;
            break;
        }
    }

    pclose(fp);
    return up;
}

int jedi_check_wlan_iface(char (*wlan_ifname)[IFACE_LEN], int count_ifname)
{
    int j = 0;  // Index for valid entries

    for (int i = 0; i < count_ifname; i++) {
        rtrimws(wlan_ifname[i]);
                
        if (!is_interface_up(wlan_ifname[i])) {
            continue;
        }

        strcpy(wlan_ifname[j], wlan_ifname[i]);
        j++;  // Move to next valid index
    }

    return j;
}

bool ioctl80211_jedi_stats_vap_get(vif_record_t *record)
{
    char essid[IW_ESSID_MAX_SIZE + 1];
    char buf[64];
    char sys_path[128];
    long long tx_bytes = 0, rx_bytes = 0;
    long tx_mb, rx_mb;
    char wlan_ifaces[MAX_IFACES][IFACE_LEN];
    radio_type_t rtype;
    int count_ifname;

    count_ifname = get_num_wlan_iface(wlan_ifaces);
    record->n_vif = jedi_check_wlan_iface(wlan_ifaces, count_ifname);

    for (int i = 0; i < record->n_vif; i++) {
        
        util_get_vif_radio(wlan_ifaces[i], buf);
        if (strcmp(buf, "ra0") == 0) {
            strcpy(record->vif[i].radio, "BAND2G");
	    rtype = RADIO_TYPE_2G;
        } else if ( strcmp(buf, "rax0") == 0) {
            strcpy(record->vif[i].radio, "BAND5G");
	    rtype = RADIO_TYPE_5G;
        }
        if (get_essid(wlan_ifaces[i], essid)) {
            strcpy(record->vif[i].ssid, essid);
        } else {
            printf("Failed to get ESSID \n");
        }


        record->vif[i].num_sta = get_num_sta(wlan_ifaces[i], essid, rtype);

        memset(buf, 0, sizeof(buf));
        memset(sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/tx_bytes", wlan_ifaces[i]);
        if (util_file_read_str(sys_path, buf, sizeof(buf)) < 0) {
            printf("Failed to retrive tx bytes of %s\n", wlan_ifaces[i]);
        }
        rtrimws(buf);

        tx_bytes = str_to_ll(buf);;
        tx_mb = tx_bytes / (1024 * 1024);
        record->vif[i].uplink_mb = tx_mb;

        memset(buf, 0, sizeof(buf));
        memset(sys_path, 0, sizeof(sys_path));

        sprintf(sys_path, "/sys/class/net/%s/statistics/rx_bytes", wlan_ifaces[i]);
        if (util_file_read_str(sys_path, buf, sizeof(buf)) == 0) {
            printf("Failed to retrive rx bytes of %s\n", wlan_ifaces[i]);
        }
        rtrimws(buf);

        rx_bytes = str_to_ll(buf);;
        rx_mb = rx_bytes / (1024 * 1024);
        record->vif[i].downlink_mb = rx_mb;

    }

    return true;
}

bool ioctl80211_jedi_stats_radio_get(vif_record_t *record)
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    char param[4];

    record->n_radio = 2;
    sprintf(record->radio[0].band, "%s", "BAND2G");  
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    cmd_buf("uci get wireless.wifi1.channel", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return false;
    }
    sscanf(buf, "%s", param);
    record->radio[0].channel = atoi(param);    

    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    cmd_buf("uci get wireless.wifi1.txpower", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return false;
    }
    sscanf(buf, "%s", param);
    record->radio[0].txpower = atoi(param);    
    record->radio[0].channel_utilization = 0;

    sprintf(record->radio[1].band, "%s", "BAND5G");  
    
    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    cmd_buf("uci get wireless.wifi0.channel", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return false;
    }
    sscanf(buf, "%s", param);
    record->radio[1].channel = atoi(param);    

    memset(buf, 0, sizeof(buf));
    memset(param, 0, sizeof(param));
    cmd_buf("uci get wireless.wifi0.txpower", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
        return false;
    }
    sscanf(buf, "%s", param);
    record->radio[1].txpower = atoi(param);    
    
    record->radio[1].channel_utilization = 0;      
    
    return true;
}

bool ioctl80211_jedi_stats_vif_get(vif_record_t *record)
{
    ioctl80211_jedi_stats_vap_get(record);
    ioctl80211_jedi_stats_radio_get(record);

    return true;
}
