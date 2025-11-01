#define _GNU_SOURCE
#include "nl80211.h"
#include "nl80211_stats.h"
#include "target_nl80211.h"

#include <stdbool.h>
#include <unistd.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <linux/genetlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include <time.h>
#include "stats_report.h" 
#include "MT7621.h"

#define CHAN_WIDTH_20MHZ      20
#define CHAN_WIDTH_40MHZ      40
#define CHAN_WIDTH_80MHZ      80
#define CHAN_WIDTH_160MHZ     160
#define CHAN_WIDTH_8080MHZ    8080  // You can use 8080 to represent 80+80 MHz
#define CHAN_WIDTH_UNKNOWN    0

#define BASE_INTERFACE_2G "phy0-ap0"
#define BASE_INTERFACE_5G "phy1-ap0"

void mac_addr_to_str(const uint8_t *mac, char *str, int len) {
    snprintf(str, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void parse_ssid_from_ie(const uint8_t *ie, int ie_len, char *ssid_out, int maxlen) {
    int pos = 0;
    while (pos + 2 <= ie_len) {
        uint8_t id = ie[pos];
        uint8_t len = ie[pos + 1];
        if (id == 0 && (pos + 2 + len) <= ie_len) {  // SSID
            memcpy(ssid_out, &ie[pos + 2], len);
            ssid_out[len < maxlen ? len : maxlen - 1] = '\0';
            return;
        }
        pos += 2 + len;
    }
    strcpy(ssid_out, "<hidden>");
}

int freq_to_channel(uint32_t freq) {
    if (freq == 2484) return 14;
    if (freq < 2484) return (freq - 2407) / 5;
    if (freq >= 5000 && freq <= 5900) return (freq - 5000) / 5;
    return 0;
}

int get_phy_index_by_name(const char *phyname) {
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/index", phyname);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    int index = -1;
    if (fscanf(fp, "%d", &index) != 1 || index < 0) {
        printf("Failed to read phy index from %s\n", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return index;
}

static int nl80211_scan_dump_recv(struct nl_msg *msg, void *arg)
{
    neighbor_report_data_t *data = (neighbor_report_data_t *)arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    neighbor_record_t *rec;

    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_TSF]                  = { .type = NLA_U64 },
        [NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
        [NL80211_BSS_BSSID]                = { 0 },
        [NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { 0 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS] || data->n_entry >= MAX_NEIGHBOUR)
        return NL_SKIP;

    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy))
        return NL_SKIP;

    rec = &data->record[data->n_entry++];

    if (bss[NL80211_BSS_BSSID])
        mac_addr_to_str(nla_data(bss[NL80211_BSS_BSSID]), rec->bssid, MAX_BSSID_LEN);

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        const uint8_t *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        int len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        parse_ssid_from_ie(ie, len, rec->ssid, SSID_MAX_LEN);

        rec->chan_width = CHAN_WIDTH_UNKNOWN;
        int remaining = len;

        while (remaining >= 2) {
            uint8_t id = ie[0];
            uint8_t ilen = ie[1];
            
            if (ilen + 2 > remaining) break;

            if (id == 0x3D && ilen >= 2) {
                // HT Operation Element — 40 MHz if bit 2 (0x04) of byte 0 is set
                if (ie[2] & 0x04)
                    rec->chan_width = CHAN_WIDTH_40MHZ;
                else
                    rec->chan_width = CHAN_WIDTH_20MHZ;
            } else if (id == 0xC0 && ilen >= 3) {
                // VHT Operation Element — byte 2 indicates channel width
                switch (ie[2]) {
                    case 0: rec->chan_width = CHAN_WIDTH_80MHZ; break;
                    case 1: rec->chan_width = CHAN_WIDTH_160MHZ; break;
                    case 2: rec->chan_width = CHAN_WIDTH_8080MHZ; break;
                    default: rec->chan_width = CHAN_WIDTH_UNKNOWN; break;
                }
            }

            remaining -= ilen + 2;
            ie += ilen + 2;
        }
    }

    if (bss[NL80211_BSS_SIGNAL_MBM])
        rec->rssi = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]) / 100;

    if (bss[NL80211_BSS_TSF])
        rec->tsf = nla_get_u64(bss[NL80211_BSS_TSF]);

    if (bss[NL80211_BSS_FREQUENCY]) {
        uint32_t freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        rec->channel = freq_to_channel(freq);

        if (freq >= 2412 && freq <= 2484)
            rec->radio_type = RADIO_TYPE_2G;
        else if (freq >= 5180 && freq <= 5895)
            rec->radio_type = RADIO_TYPE_5G;
        else if (freq >= 5925 && freq <= 7125)
            rec->radio_type = RADIO_TYPE_6G;
        else
           rec->radio_type = RADIO_TYPE_NONE;
    }

    return NL_SKIP;
}


bool nl80211_get_scan_results(const char *phy_name, neighbor_report_data_t *scan_results)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    int if_index;
    struct nl_msg *msg;

    if ((if_index = util_sys_ifname_to_idx(phy_name)) < 0) {
        return -EINVAL;
    }

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_SCAN, true);
    if (!msg) {
        return -EINVAL;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    return nlmsg_send_and_recv(nl_sm_global, msg, nl80211_scan_dump_recv, scan_results);

}



static void print_neighbor_report(const neighbor_report_data_t *report) 
{
    printf("Neighbor Scan Report:\n");
    if (report->n_entry == 0) {
        printf("No neighbors found!\n");
        return;
    }
    for (int i = 0; i < report->n_entry; ++i) {
        const neighbor_record_t *rec = &report->record[i];
        printf(" [%d] BSSID: %s, SSID: %s, RSSI: %d dBm, CH: %u, Width: %u, TSF: %llu\n",
               i + 1, rec->bssid, rec->ssid, rec->rssi, rec->channel, rec->chan_width, rec->tsf);
    }
}

void generate_dummy_neighbor_report(neighbor_report_data_t *report) 
{
    srand(time(NULL));  // Initialize random number generator

    report->timestamp_ms = (uint64_t)time(NULL) * 1000; // Current timestamp in milliseconds
    report->n_entry = 10;  // Set number of dummy entries

    for (int i = 0; i < report->n_entry; ++i) {
        neighbor_record_t *rec = &report->record[i];

        // Randomly fill the radio_type
        rec->radio_type = (rand() % 2 == 0) ? RADIO_TYPE_2G : RADIO_TYPE_5G;

        // Generate a dummy BSSID (e.g., "00:11:22:33:44:55")
        snprintf(rec->bssid, sizeof(rec->bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
                 rand() % 256, rand() % 256, rand() % 256, rand() % 256, rand() % 256, rand() % 256);

        // Generate a dummy SSID (e.g., "SSID_XXXX")
        snprintf(rec->ssid, sizeof(rec->ssid), "SSID_%04d", rand() % 10000);

        // Generate random RSSI between -100 and -30 dBm
        rec->rssi = -(rand() % 71 + 30);

        // Generate a dummy TSF (timestamp value)
        rec->tsf = rand() % 1000000000;  // Random TSF for demonstration

        // Generate a random channel width (e.g., 20 or 40 MHz)
        rec->chan_width = (rand() % 2 == 0) ? 20 : 40;

        // Generate a random channel number (e.g., 1-11 for 2.4GHz or 36-48 for 5GHz)
        if (rec->radio_type == RADIO_TYPE_2G) {
            rec->channel = (rand() % 11) + 1;  // Random 2.4GHz channel (1-11)
        } else {
            rec->channel = (rand() % 9) + 36;  // Random 5GHz channel (36-48)
        }
    }
}


bool nl80211_stats_scan_get(neighbor_report_data_t *report)
{
    char scancmd[128];

    /* 2.4Ghz Neighbour List */
    LOG(INFO, "Scanning 2.4GHZ Neighbour");
    sprintf(scancmd,"iw dev %s scan > /dev/null 2>&1", BASE_INTERFACE_2G);
    system(scancmd);
    nl80211_get_scan_results("phy0-ap0", report);
    
    /* 5Ghz Neighbour List */
    LOG(INFO, "Scanning 5GHZ Neighbour");
    sprintf(scancmd,"iw dev %s scan > /dev/null 2>&1", BASE_INTERFACE_5G);
    system(scancmd);
    nl80211_get_scan_results("phy1-ap1", report);

    //generate_dummy_neighbor_report(report);
    print_neighbor_report(report);
    return true;
}

