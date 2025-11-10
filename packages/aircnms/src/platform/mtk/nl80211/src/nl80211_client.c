#define _GNU_SOURCE
#include "nl80211.h"
#include "nl80211_stats.h"
#include "target_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <linux/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/genl/family.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include "stats_report.h"
#include "ext_event.h"

#define MAX_IFACES 8
#define IFACE_NAME_LEN 16
#define MAX_LINE_LENGTH 100

static int iface_count;

typedef struct {
    client_report_data_t *data;
    const char *ifname;
} client_cb_ctx_t;

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

int nl80211_get_wiface(char (*wlan_ifname)[16]) 
{
    struct nl_msg *msg;

    msg = nlmsg_init(get_nl_sm_global(), NL80211_CMD_GET_INTERFACE, 1);
    if (!msg)
        return -EINVAL;

    return nlmsg_send_and_recv(get_nl_sm_global(), msg, nl80211_parse_wiface, wlan_ifname);
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

bool get_interface_essid(const char *ifname, char *essid)
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

void fill_client_info_from_proc(client_record_t *rec, char *sta_ifname)
{
    FILE *fp = fopen("/proc/airpro/stainfo", "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    char line[256];
    char mac_str[18], ip[IPADDR_MAX_LEN], hostname[HOSTNAME_MAX_LEN], ifname[IFACE_NAME_LEN];
    char tms_str[32];
    uint64_t tms;
    bool mac_found = false;

    while (fgets(line, sizeof(line), fp)) {
        int rx, tx;
        if (sscanf(line, "%17s %15s %31s %31s %d %d %31s",
                   mac_str, ip, hostname, ifname, &rx, &tx, tms_str) == 7) {

            // Match MAC address
            char rec_mac_str[18];
            snprintf(rec_mac_str, sizeof(rec_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     rec->macaddr[0], rec->macaddr[1], rec->macaddr[2],
                     rec->macaddr[3], rec->macaddr[4], rec->macaddr[5]);

            if (strcasecmp(mac_str, rec_mac_str) == 0) {
                mac_found = true;
                strncpy(rec->ipaddr, ip, IPADDR_MAX_LEN - 1);
                strncpy(rec->hostname, hostname, HOSTNAME_MAX_LEN - 1);
                //strncpy(rec->ssid, ifname, SSID_MAX_LEN - 1);
                break;
            }
        }
    }

    fclose(fp);
    
    if (!mac_found) {
        strncpy(rec->ipaddr, "0.0.0.0", IPADDR_MAX_LEN - 1);
        strncpy(rec->hostname, "unknown", HOSTNAME_MAX_LEN - 1);
        LOG(INFO, "NOT FOUND IN ADPI: ADDING STA %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       ifname, rec->macaddr[0], rec->macaddr[1], rec->macaddr[2], rec->macaddr[3], rec->macaddr[4], rec->macaddr[5]);
        //nl_ext_event_enqueue(NL80211_CMD_NEW_STATION, rec->macaddr, sta_ifname);
    }
}

/* Helper function to grow the records array */
static int grow_report_data(client_report_data_t *data)
{
    int new_capacity = (data->capacity == 0) ? 1 : data->capacity * 2;
    client_record_t *new_record = (client_record_t *)realloc(data->record,
                                                               new_capacity * sizeof(client_record_t));
    if (!new_record) {
        LOG(ERR, "Failed to reallocate memory for client records");
        return -1;
    }
    data->record = new_record;
    data->capacity = new_capacity;
    return 0;
}

static int nl80211_parse_station_cb(struct nl_msg *msg, void *arg)
{
    client_cb_ctx_t *ctx = (client_cb_ctx_t *)arg;
    client_report_data_t *data = ctx->data;
    const char *ifname = ctx->ifname;
    client_record_t *rec;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_STA_INFO] || !tb[NL80211_ATTR_MAC])
        return NL_SKIP;

    if (data->n_client >= MAX_CLIENTS)
        return NL_SKIP;

    if (data->n_client >= data->capacity) {
        if (grow_report_data(data) < 0) {
            LOG(ERR, "Failed to grow report data");
            return NL_SKIP;
        }
    }

    rec = &data->record[data->n_client++];
    memset(rec, 0, sizeof(*rec));

    memcpy(rec->macaddr, nla_data(tb[NL80211_ATTR_MAC]), 6);

    nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], NULL);

    if (sinfo[NL80211_STA_INFO_RX_BYTES64])
        rec->rx_bytes = nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);

    if (sinfo[NL80211_STA_INFO_TX_BYTES64])
        rec->tx_bytes = nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);

    if (sinfo[NL80211_STA_INFO_ACK_SIGNAL_AVG]) {
        rec->rssi = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_ACK_SIGNAL_AVG]);
    }

    if (sinfo[NL80211_STA_INFO_CONNECTED_TIME]) {
        uint32_t connected_sec = nla_get_u32(sinfo[NL80211_STA_INFO_CONNECTED_TIME]);
        rec->duration_ms = connected_sec * 1000;
    }
    
    get_interface_essid(ifname, rec->ssid);
            
    /* Determine radio type */
    if (strstr(ifname, "phy1")) {
        rec->radio_type = RADIO_TYPE_5G;
    } else if (strstr(ifname, "phy0")) {
        rec->radio_type = RADIO_TYPE_2G;
    } else {
        rec->radio_type = RADIO_TYPE_NONE;
    }
    rec->channel = get_channel(rec->radio_type);

    strncpy(rec->osinfo, "other", sizeof(rec->osinfo) - 1);
    rec->osinfo[sizeof(rec->osinfo) - 1] = '\0';

    strncpy(rec->client_type, "wireless", sizeof(rec->client_type) - 1);
    rec->client_type[sizeof(rec->client_type) - 1] = '\0';


    rec->is_connected = 1;
    fill_client_info_from_proc(rec, ifname);
    
    return NL_SKIP;
}

#if 0
void print_client_report(const client_report_data_t *report)
{
    printf("Number of Clients: %d\n", report->n_client);

    for (int i = 0; i < report->n_client; ++i) {
        const client_record_t *rec = &report->record[i];

        printf("\nClient #%d:\n", i + 1);
        printf("  MAC Address    : %02X:%02X:%02X:%02X:%02X:%02X\n",
               rec->macaddr[0], rec->macaddr[1], rec->macaddr[2],
               rec->macaddr[3], rec->macaddr[4], rec->macaddr[5]);

        printf("  Hostname       : %s\n", rec->hostname[0] ? rec->hostname : "N/A");
        printf("  IP Address     : %s\n", rec->ipaddr[0] ? rec->ipaddr : "N/A");
        printf("  SSID           : %s\n", rec->ssid[0] ? rec->ssid : "N/A");
        printf("  RSSI           : %d dBm\n", rec->rssi);
        printf("  RX Bytes       : %llu\n", rec->rx_bytes);
        printf("  TX Bytes       : %llu\n", rec->tx_bytes);
        printf("  Duration       : %llu ms\n", rec->duration_ms);
        printf("  Connected      : %s\n", rec->is_connected ? "Yes" : "No");
        printf("  Channel        : %u\n", rec->channel);
        printf("  Radio Type     : %d\n", rec->radio_type);
    }
}
#endif

bool nl80211_stats_clients_get(client_report_data_t *client_list)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    char wlan_ifname[MAX_IFACES][IFACE_NAME_LEN];
    int ifindex, i;

    iface_count = 0;
    client_list->n_client = 0;

    if( nl80211_get_wiface(wlan_ifname) < 0) {
        return false;
    }

    for (i = 0; i < iface_count; ++i) {
    ifindex = if_nametoindex(wlan_ifname[i]);
    if (ifindex == 0) continue;

    struct nl_msg *msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_STATION, NLM_F_DUMP);
    if (!msg) continue;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    client_cb_ctx_t ctx = {
        .data = client_list,
        .ifname = wlan_ifname[i]
    };

    nlmsg_send_and_recv(nl_sm_global, msg, nl80211_parse_station_cb, &ctx);
    }

    //print_client_report(client_list);

    return true;
}

