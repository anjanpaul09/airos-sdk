#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "netconf.h"

// Channel switch state tracking for serialization
typedef struct {
    bool in_progress;
    char radio_name[32];
    time_t start_time;
} chan_switch_state_t;

static chan_switch_state_t g_chan_switch_state = {false, "", 0};
static pthread_mutex_t g_chan_switch_mutex = PTHREAD_MUTEX_INITIALIZER;

// Channel to center frequency mapping structure
typedef struct {
    int primary_channel;
    int bandwidth;
    int center_freq;
} ChannelMap;

// 2.4 GHz mappings
static const ChannelMap map_24ghz_20[] = {
    {1, 20, 2412}, {2, 20, 2417}, {3, 20, 2422}, {4, 20, 2427},
    {5, 20, 2432}, {6, 20, 2437}, {7, 20, 2442}, {8, 20, 2447},
    {9, 20, 2452}, {10, 20, 2457}, {11, 20, 2462}, {12, 20, 2467},
    {13, 20, 2472}, {14, 20, 2484}
};

static const ChannelMap map_24ghz_40[] = {
    {1, 40, 2422}, {2, 40, 2427}, {3, 40, 2432}, {4, 40, 2437},
    {5, 40, 2442}, {6, 40, 2447}, {7, 40, 2452}, {8, 40, 2457},
    {9, 40, 2462}
};

// 5 GHz mappings
static const ChannelMap map_5ghz_20[] = {
    {36, 20, 5180}, {40, 20, 5200}, {44, 20, 5220}, {48, 20, 5240},
    {52, 20, 5260}, {56, 20, 5280}, {60, 20, 5300}, {64, 20, 5320},
    {100, 20, 5500}, {104, 20, 5520}, {108, 20, 5540}, {112, 20, 5560},
    {116, 20, 5580}, {120, 20, 5600}, {124, 20, 5620}, {128, 20, 5640},
    {132, 20, 5660}, {136, 20, 5680}, {140, 20, 5700}, {144, 20, 5720},
    {149, 20, 5745}, {153, 20, 5765}, {157, 20, 5785}, {161, 20, 5805},
    {165, 20, 5825}
};

// 5 GHz - 40 MHz: All primary channels within each 40 MHz block
static const ChannelMap map_5ghz_40[] = {
    {36, 40, 5190}, {40, 40, 5190},
    {44, 40, 5230}, {48, 40, 5230},
    {52, 40, 5270}, {56, 40, 5270},
    {60, 40, 5310}, {64, 40, 5310},
    {100, 40, 5510}, {104, 40, 5510},
    {108, 40, 5550}, {112, 40, 5550},
    {116, 40, 5590}, {120, 40, 5590},
    {124, 40, 5630}, {128, 40, 5630},
    {132, 40, 5670}, {136, 40, 5670},
    {140, 40, 5710}, {144, 40, 5710},
    {149, 40, 5755}, {153, 40, 5755},
    {157, 40, 5795}, {161, 40, 5795}
};

// 5 GHz - 80 MHz: All primary channels within each 80 MHz block
static const ChannelMap map_5ghz_80[] = {
    {36, 80, 5210}, {40, 80, 5210}, {44, 80, 5210}, {48, 80, 5210},
    {52, 80, 5290}, {56, 80, 5290}, {60, 80, 5290}, {64, 80, 5290},
    {100, 80, 5530}, {104, 80, 5530}, {108, 80, 5530}, {112, 80, 5530},
    {116, 80, 5610}, {120, 80, 5610}, {124, 80, 5610}, {128, 80, 5610},
    {132, 80, 5690}, {136, 80, 5690}, {140, 80, 5690}, {144, 80, 5690},
    {149, 80, 5775}, {153, 80, 5775}, {157, 80, 5775}, {161, 80, 5775}
};

int util_chan_to_freq(int chan)
{
    if (chan == 14)
        return 2484;
    else if (chan < 14)
        return 2407 + chan * 5;
    else if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
    else
        return 5000 + chan * 5;
}

// Get center frequency based on primary channel and bandwidth
int get_center_freq(int primary_channel, int bandwidth)
{
    const ChannelMap *map = NULL;
    int map_size = 0;

    if (primary_channel <= 14) {
        if (bandwidth == 20) {
            map = map_24ghz_20;
            map_size = sizeof(map_24ghz_20) / sizeof(map_24ghz_20[0]);
        } else if (bandwidth == 40) {
            map = map_24ghz_40;
            map_size = sizeof(map_24ghz_40) / sizeof(map_24ghz_40[0]);
        }
    } else {
        if (bandwidth == 20) {
            map = map_5ghz_20;
            map_size = sizeof(map_5ghz_20) / sizeof(map_5ghz_20[0]);
        } else if (bandwidth == 40) {
            map = map_5ghz_40;
            map_size = sizeof(map_5ghz_40) / sizeof(map_5ghz_40[0]);
        } else if (bandwidth == 80) {
            map = map_5ghz_80;
            map_size = sizeof(map_5ghz_80) / sizeof(map_5ghz_80[0]);
        }
    }

    if (map == NULL) {
        return -1;
    }

    for (int i = 0; i < map_size; i++) {
        if (map[i].primary_channel == primary_channel) {
            return map[i].center_freq;
        }
    }

    return -1;
}

// Parse bandwidth from htmode string
int parse_bandwidth(const char *htmode)
{
    if (strstr(htmode, "20") != NULL) {
        return 20;
    } else if (strstr(htmode, "40") != NULL) {
        return 40;
    } else if (strstr(htmode, "80") != NULL) {
        return 80;
    } else if (strstr(htmode, "160") != NULL) {
        return 160;
    }
    return 20;
}

// Trigger CSA using ubus with correct parameters
static bool trigger_csa_on_interface(struct ubus_context *ctx, uint32_t id,
                                      const char *ifname, int freq, int center_freq1,
                                      int bandwidth, int bcn_count)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "freq", freq);
    blobmsg_add_u32(&b, "bcn_count", bcn_count);
    blobmsg_add_u32(&b, "center_freq1", center_freq1);
    blobmsg_add_u32(&b, "bandwidth", bandwidth);
    
    // Add boolean flags for ht/vht/he
    blobmsg_add_u8(&b, "ht", 1);
    blobmsg_add_u8(&b, "vht", 1);
    blobmsg_add_u8(&b, "he", 1);

    LOG(INFO, "[CHAN_SWITCH] Triggering CSA on %s: freq=%d center_freq1=%d bw=%d bcn_count=%d",
        ifname, freq, center_freq1, bandwidth, bcn_count);
    
    // Print the complete ubus message for debugging
    char *msg_str = blobmsg_format_json_indent(b.head, true, 0);
    LOG(INFO, "[CHAN_SWITCH] UBUS Message:\n%s", msg_str);
    free(msg_str);

    ret = ubus_invoke(ctx, id, "switch_chan", b.head, NULL, NULL, 10000);

    blob_buf_free(&b);

    if (ret == UBUS_STATUS_OK) {
        LOG(INFO, "[CHAN_SWITCH] ✓ CSA triggered successfully on %s", ifname);
        return true;
    } else {
        LOG(ERR, "[CHAN_SWITCH] ✗ CSA failed on %s: %s", ifname, ubus_strerror(ret));
        return false;
    }
}

bool target_chan_switch(const char *radio_name, int channel)
{
    char ifname[12];
    char phyname[8];
    char cmd[256];
    char htmode[32];
    int freq = 0;
    int center_freq = 0;
    int bandwidth = 0;
    bool success = false;

    // ========== SERIALIZATION ==========
    const int MAX_WAIT_TIME_SEC = 10;
    const int STALE_OPERATION_SEC = 15;
    int waited_ms = 0;

    LOG(INFO, "[CHAN_SWITCH] Request for %s to channel %d", radio_name, channel);

    while (waited_ms < MAX_WAIT_TIME_SEC * 1000) {
        pthread_mutex_lock(&g_chan_switch_mutex);

        if (!g_chan_switch_state.in_progress) {
            g_chan_switch_state.in_progress = true;
            strncpy(g_chan_switch_state.radio_name, radio_name, sizeof(g_chan_switch_state.radio_name) - 1);
            g_chan_switch_state.radio_name[sizeof(g_chan_switch_state.radio_name) - 1] = '\0';
            g_chan_switch_state.start_time = time(NULL);
            pthread_mutex_unlock(&g_chan_switch_mutex);
            LOG(INFO, "[CHAN_SWITCH] Acquired lock for %s (waited %d ms)", radio_name, waited_ms);
            break;
        }

        time_t now = time(NULL);
        time_t elapsed = now - g_chan_switch_state.start_time;

        if (elapsed > STALE_OPERATION_SEC) {
            LOG(ERR, "[CHAN_SWITCH] WARNING: Stale operation detected for %s (started %ld sec ago), forcing release",
                    g_chan_switch_state.radio_name, (long)elapsed);
            g_chan_switch_state.in_progress = false;
            pthread_mutex_unlock(&g_chan_switch_mutex);
            continue;
        }

        LOG(INFO, "[CHAN_SWITCH] Waiting for %s to complete (elapsed: %ld sec)...",
               g_chan_switch_state.radio_name, (long)elapsed);
        pthread_mutex_unlock(&g_chan_switch_mutex);

        usleep(100000);
        waited_ms += 100;
    }

    pthread_mutex_lock(&g_chan_switch_mutex);
    bool acquired = g_chan_switch_state.in_progress &&
                    strcmp(g_chan_switch_state.radio_name, radio_name) == 0;
    pthread_mutex_unlock(&g_chan_switch_mutex);

    if (!acquired) {
        LOG(ERR, "[CHAN_SWITCH] ERROR: Timeout waiting for lock (waited %d ms)", waited_ms);
        return false;
    }

    if (strcmp(radio_name, "wifi0") == 0) {
        strcpy(ifname, "phy1-ap0");
        strcpy(phyname, "phy1");
    } else if (strcmp(radio_name, "wifi1") == 0) {
        strcpy(ifname, "phy0-ap0");
        strcpy(phyname, "phy0");
    } else {
        fprintf(stderr, "[CHAN_SWITCH] Invalid radio name: %s\n", radio_name);
        goto cleanup_lock;
    }

    freq = util_chan_to_freq(channel);
    if (freq <= 0) {
        LOG(ERR, "[CHAN_SWITCH] Invalid channel %d for %s", channel, radio_name);
        goto cleanup_lock;
    }

    snprintf(cmd, sizeof(cmd), "uci get wireless.%s.htmode 2>/dev/null", radio_name);

    if (execute_uci_command(cmd, htmode, sizeof(htmode)) != 0 || strlen(htmode) == 0) {
        LOG(ERR, "[CHAN_SWITCH] Failed to read htmode for %s", radio_name);
        goto cleanup_lock;
    }
    htmode[strcspn(htmode, "\n")] = 0;

    bandwidth = parse_bandwidth(htmode);
    LOG(INFO, "[CHAN_SWITCH] Parsed bandwidth: %d MHz from htmode: %s", bandwidth, htmode);

    center_freq = get_center_freq(channel, bandwidth);
    if (center_freq < 0) {
        LOG(ERR, "[CHAN_SWITCH] Failed to determine center frequency for channel %d, bandwidth %d",
            channel, bandwidth);
        goto cleanup_lock;
    }

    LOG(INFO, "[CHAN_SWITCH] Channel %d, Bandwidth %d MHz -> Primary freq: %d MHz, Center freq: %d MHz",
        channel, bandwidth, freq, center_freq);

    // ========== APPLY CSA TO PRIMARY VAP USING UBUS ==========
    // Secondary VAPs (ap1, ap2, etc.) will follow the primary VAP automatically
    
    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "[CHAN_SWITCH] Failed to connect to ubus");
        goto cleanup_lock;
    }

    char ubus_path[64];
    snprintf(ubus_path, sizeof(ubus_path), "hostapd.%s", ifname);
    LOG(INFO, "[CHAN_SWITCH] Applying CSA to primary VAP: %s", ubus_path);

    uint32_t id;
    int ret = ubus_lookup_id(ctx, ubus_path, &id);
    if (ret != UBUS_STATUS_OK) {
        LOG(ERR, "[CHAN_SWITCH] ERROR: Failed to lookup '%s': %s - using wifi reload fallback",
            ubus_path, ubus_strerror(ret));
        ubus_free(ctx);
        
        // Fallback: Update UCI and reload wifi
        char uci_cmd[256];
        snprintf(uci_cmd, sizeof(uci_cmd),
                 "uci set wireless.%s.channel=%d && uci commit wireless && wifi reload %s",
                 radio_name, channel, radio_name);
        
        printf("[CHAN_SWITCH] Executing fallback: %s\n", uci_cmd);
        if (system(uci_cmd) == 0) {
            printf("[CHAN_SWITCH] Wifi reload completed successfully\n");
            usleep(3000000); // Wait 3 seconds for wifi reload
            success = true;
        } else {
            fprintf(stderr, "[CHAN_SWITCH] ERROR: Wifi reload also failed\n");
            success = false;
        }
        goto cleanup_lock;
    }

    // Trigger CSA on primary VAP using ubus
    if (trigger_csa_on_interface(ctx, id, ifname, freq, center_freq, bandwidth, 5)) {
        LOG(INFO, "[CHAN_SWITCH] Waiting for CSA to complete (bcn_count=5)...");
        usleep(2000000); // Wait 2 seconds for CSA to complete
        success = true;
    } else {
        LOG(ERR, "[CHAN_SWITCH] CSA failed on %s - using wifi reload fallback", ifname);
        
        // Fallback: Update UCI and reload wifi
        char uci_cmd[256];
        snprintf(uci_cmd, sizeof(uci_cmd),
                 "uci set wireless.%s.channel=%d && uci commit wireless && wifi reload %s",
                 radio_name, channel, radio_name);
        
        printf("[CHAN_SWITCH] Executing fallback: %s\n", uci_cmd);
        if (system(uci_cmd) == 0) {
            printf("[CHAN_SWITCH] Wifi reload completed successfully\n");
            usleep(3000000); // Wait 3 seconds for wifi reload
            success = true;
        } else {
            fprintf(stderr, "[CHAN_SWITCH] ERROR: Wifi reload also failed\n");
            success = false;
        }
    }

    ubus_free(ctx);

    if (success) {
        LOG(INFO, "[CHAN_SWITCH] Channel switch completed for %s", radio_name);
    }

cleanup_lock:
    pthread_mutex_lock(&g_chan_switch_mutex);
    if (g_chan_switch_state.in_progress &&
        strcmp(g_chan_switch_state.radio_name, radio_name) == 0) {
        g_chan_switch_state.in_progress = false;
        LOG(INFO, "[CHAN_SWITCH] Released lock for %s (success=%d)", radio_name, success);
    }
    pthread_mutex_unlock(&g_chan_switch_mutex);

    return success;
}

