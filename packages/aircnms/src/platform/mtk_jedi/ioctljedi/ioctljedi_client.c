#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <linux/wireless.h>

#include "const.h"
#include "log.h"
#include "os.h"

#define STATS_DELTA(n, o) ((n) < (o) ? (n) : (n) - (o))
//#include "ioctljedi.h"
#include "ioctl80211_jedi.h"
#include "report.h"
#define PROC_FILE "cat /proc/airpro/stainfo"
#define STA_TEMP_FILE "/tmp/stainfo.txt"
#define MAX_LINE_LENGTH 100

#if WIRELESS_EXT <= 11
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE                              0x8BE0
#endif
#define SIOCIWFIRSTPRIV                             SIOCDEVPRIVATE
#endif

#define RT_PRIV_IOCTL                               (SIOCIWFIRSTPRIV + 0x01) /* Sync. with AP for wsc upnp daemon */
#define RTPRIV_IOCTL_SET                            (SIOCIWFIRSTPRIV + 0x02)
#define RTPRIV_IOCTL_BBP                            (SIOCIWFIRSTPRIV + 0x03)
#define RTPRIV_IOCTL_MAC                            (SIOCIWFIRSTPRIV + 0x05)
#define RTPRIV_IOCTL_SHOW                           (SIOCIWFIRSTPRIV + 0x11)

#define MAX_NUM_STA                                  64

struct staInfo {
    uint8_t addr[6];
    char rssi[4];
};

struct staIoctlData {
    uint16_t numSta;
    struct staInfo sInfo[MAX_NUM_STA];
};

// Function to convert MAC address to lowercase
void to_lowercase(char *str) 
{
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

int get_rssi(unsigned char *mac) 
{
    struct staIoctlData *staData;
    char *data = NULL;
    int sock = -1, ret = -1, staCnt = 0, rssi = 0;
    struct iwreq wrq;
    const char *ifname = "ra0";

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("error opening socket\n");
        return -1;
    }
    data = (char *)malloc(sizeof(struct staIoctlData));
    if (!data) {
        return -1;
    }

    memset(data, 0, sizeof(data));
    sprintf(data, "%s", "stainfo");
    strcpy(wrq.ifr_name, ifname);
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;
    ret = ioctl(sock, RTPRIV_IOCTL_SHOW, &wrq);
    if (ret < 0) {
        printf("error calling ioctl..\n");
        return -1;
    }
    if (wrq.u.data.length > 0) {
        memcpy(data, wrq.u.data.pointer, sizeof(struct staIoctlData));
    }
    staData = (struct staIoctlData *)data;
    printf("Anjan: numSta=%d\n", staData->numSta);
    for (staCnt = 0; staCnt < staData->numSta; staCnt++) {
        if (memcmp(staData->sInfo[staCnt].addr, mac, 6) == 0) {
            rssi = staData->sInfo[staCnt].rssi[0];
            break;
        }
    }

    free(data);
    close(sock);

    return rssi;
}

void get_interface_essid(char *ifname, char *essid)
{
    FILE *fp;
    char cmd[MAX_LINE_LENGTH];
    char line[MAX_LINE_LENGTH];

    snprintf(cmd, sizeof(cmd), "iwconfig %s | grep 'ESSID' | awk -F '\"' '{print $2}'", ifname);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return;
    }

    if (fgets(line, sizeof(line), fp) != NULL) {
        char *newline = strchr(line, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }
        strncpy(essid, line, MAX_LINE_LENGTH - 1);
        essid[MAX_LINE_LENGTH - 1] = '\0';
    }

    pclose(fp);

    return;
}

radio_type_t get_radio_type(const char *ifname) 
{
    if (strncmp(ifname, "rax", 3) == 0 ) {
        return RADIO_TYPE_5G;
    } else if (strncmp(ifname, "ra", 2) == 0) {
        return RADIO_TYPE_2G;  
    } else {
        return RADIO_TYPE_NONE;
    }
}

int get_channel(radio_type_t radio) 
{
#define UCI_BUF_LEN 256
#define PHY_NAME_LEN 6  // Enough for "wifi0" or "wifi1"

    char cmd[UCI_BUF_LEN] = {0};
    char buf[UCI_BUF_LEN] = {0};
    char param[4];
    int channel = -1;  // Default to -1 if retrieval fails

    const char *phyname = (radio == RADIO_TYPE_2G) ? "wifi1" : "wifi0";

    snprintf(cmd, sizeof(cmd), "uci get wireless.%s.channel", phyname);

    if (cmd_buf(cmd, buf, UCI_BUF_LEN) != 0 || buf[0] == '\0') {
        LOGI("%s: No UCI found: CMD: %s", __func__, cmd);
        return -1;
    }

    if (sscanf(buf, "%3s", param) == 1) {
        channel = atoi(param);
    }

    return channel;
}

bool ioctl80211_jedi_client_fetch_dummy(client_report_data_t *report)
{
    // Set timestamp
    report->n_client = MAX_CLIENTS;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        // Dummy MAC address
        report->record[i].macaddr[0] = 0x00;
        report->record[i].macaddr[1] = 0x11;
        report->record[i].macaddr[2] = 0x22;
        report->record[i].macaddr[3] = 0x33;
        report->record[i].macaddr[4] = 0x44;
        report->record[i].macaddr[5] = i;  // Different last byte

        // Dummy hostname
        snprintf(report->record[i].hostname, HOSTNAME_MAX_LEN, "Client_%d", i);

        // Dummy IP address
        snprintf(report->record[i].ipaddr, IPADDR_MAX_LEN, "192.168.1.%d", 100 + i);

        // Dummy SSID
        snprintf(report->record[i].ssid, SSID_MAX_LEN, "Dummy_SSID");

        // Dummy data usage
        report->record[i].rx_bytes = 100000 + (i * 5000);
        report->record[i].tx_bytes = 50000 + (i * 2500);

        // Dummy RSSI
        report->record[i].rssi = -40 - i * 5;

        // Connection status
        report->record[i].is_connected = 1;

        // Connection duration
        report->record[i].duration_ms = 3600000 * (i + 1);  // 1 hour per client

        // Dummy radio type and channel
        report->record[i].radio_type = (i % 2 == 0) ? RADIO_TYPE_5G : RADIO_TYPE_2G;
        report->record[i].channel = (i % 2 == 0) ? 36 : 6;
    }

    return true;
}

/* Convert MAC string "xx:xx:xx:xx:xx:xx" to uint8_t[6] */
void parse_mac(const char *mac_str, uint8_t *mac)
{
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

/* Fix numeric parsing to handle possible commas in numbers */
uint64_t parse_number(const char *num_str)
{
    char clean_str[32] = {0}; // To hold cleaned number (without commas)
    int j = 0;

    // Remove commas from number
    for (int i = 0; num_str[i] != '\0' && j < sizeof(clean_str) - 1; i++) {
        if (num_str[i] != ',') {
            clean_str[j++] = num_str[i];
        }
    }

    return strtoull(clean_str, NULL, 10);
}

// Get the real UNIX timestamp (absolute time in seconds)
static inline uint64_t get_unix_timestamp(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        perror("clock_gettime");
        return 0;
    }
    return ts.tv_sec;  // Returns the current UNIX timestamp
}

uint64_t calculate_duration_ms(uint64_t connected_tms) 
{
    uint64_t current_time = get_unix_timestamp();
    return (current_time - connected_tms) * 1000;  // Convert to milliseconds
}

ioctl_status_t ioctl80211_jedi_clients_list_fetch(client_report_data_t *report)
{
    FILE *fp = fopen("/proc/airpro/stainfo", "r");
    if (!fp) {
        perror("Failed to open /proc/airpro/stainfo");
        return IOCTL_STATUS_ERROR; 
    }

    char line[256];
    int client_count = 0;
    while (fgets(line, sizeof(line), fp) && client_count < MAX_CLIENTS) {
        client_record_t *client = &report->record[client_count];
        memset(client, 0, sizeof(client_record_t));

        char mac_str[18], ipaddr[IPADDR_MAX_LEN], hostname[HOSTNAME_MAX_LEN], ifname[SSID_MAX_LEN];
        char rx_str[32], tx_str[32], tms_str[32];  // Strings to store RX and TX bytes
        uint64_t tms;

        /* Parse the line */
        if (sscanf(line, "%17s %15s %31s %31s %31s %31s %31s",
                   mac_str, ipaddr, hostname, ifname, rx_str, tx_str, tms_str) != 7) {
            fprintf(stderr, "Invalid format: %s\n", line);
            continue;
        }

        /* Fill client record - only stats */
        parse_mac(mac_str, client->macaddr);
        
        // Fill stats only
        client->stats.rx_bytes = parse_number(rx_str);
        client->stats.tx_bytes = parse_number(tx_str);
        client->stats.rssi = get_rssi(client->macaddr);
        
        tms = parse_number(tms_str);
        client->stats.duration_ms = calculate_duration_ms(tms);
        
        // Fill other stats fields with dummy/default values for now
        client->stats.snr = 28;
        client->stats.tx_rate_mbps = 173;
        client->stats.rx_rate_mbps = 72;
        client->stats.tx_packets = 928133;
        client->stats.rx_packets = 421023;
        client->stats.tx_retries = 12011;
        client->stats.tx_failures = 42;
        client->stats.tx_phy_rate = 433;
        client->stats.rx_phy_rate = 200;
        client->stats.signal_avg = -70;

        client_count++;
    }

    fclose(fp);
    report->n_client = client_count;
    return IOCTL_STATUS_OK;
}


ioctl_status_t ioctl80211_jedi_clients_list_get(client_report_data_t *client_list)
{
    ioctl_status_t                  status;

    //ioctl80211_jedi_client_fetch_dummy(client_list);
    status = ioctl80211_jedi_clients_list_fetch(client_list);
    return status;
}

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_jedi_client_list_get(client_report_data_t *client_list)
{
    ioctl_status_t                  status;
    if (NULL == client_list)
    {
        return IOCTL_STATUS_ERROR;
    }
    status = ioctl80211_jedi_clients_list_get(client_list);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

