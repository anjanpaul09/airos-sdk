#ifndef PROTO_CMB_H
#define PROTO_CMB_H

#include <proto/ethernet.h>

#define CMB_ETHER_TYPE      0x8941
#define CMB_ETHER_SUB_TYPE  0x10

// Never ever add any new message type into middle of the existing message types and never change the numbering of existing message types
#define CMB_NOTIFY_MSG_TYPE_ROAM                             1
#define CMB_NOTIFY_MSG_TYPE_GA_UPDATE                        2
#define CMB_NOTIFY_MSG_TYPE_PMK_UPDATE                       3
#define CMB_NOTIFY_MSG_TYPE_FT_RRB                           4
#define CMB_NOTIFY_MSG_TYPE_BANDSTEER_STATUS                 5
#define CMB_NOTIFY_MSG_TYPE_CI_SESSION_UPDATE                6
#define CMB_NOTIFY_MSG_TYPE_ROAM_DATA_READY_UPDATE_REQ       7
#define CMB_NOTIFY_MSG_TYPE_ACCT_STATS_UPDATE_RSP            8
#define CMB_NOTIFY_MSG_TYPE_GA_LOGIN_UPDATE_ROAMED_CLIENT    9
#define CMB_NOTIFY_MSG_TYPE_DRF_NBR                         10
#define CMB_NOTIFY_MSG_TYPE_DRF_NBR_CHAN_ASSIGN             11
#define CMB_NOTIFY_MSG_TYPE_DRF_NBR_RADIO_MAC_INFO          12
#define CMB_NOTIFY_MSG_TYPE_DRF_NBR_DEV_INFO                13
#define CMB_NOTIFY_MSG_TYPE_AUTOPILOT                       14
#define CMB_NOTIFY_MSG_TYPE_CLB_UPDATE                      15
#define CMB_NOTIFY_MSG_TYPE_ARF_LDR                         16
#define CMB_NOTIFY_MSG_TYPE_ARF_DEVINFO                     17
#define CMB_NOTIFY_MSG_TYPE_ARF_NBRINFO                     18
#define CMB_NOTIFY_MSG_TYPE_ARF_CHANGE                      19
#define CMB_NOTIFY_MSG_TYPE_MAX                             21

#define CMB_GA_VER    2
#define CMB_GA_ACCOUNTING_ENABLED (1<<0)

struct cmb_ga_msg {
    uint8_t  ver; // version of the msg
    uint16_t vlan; // n/w order
    uint8_t  mac[MAC_ADDR_LEN];
    char     user_name[256]; // max of 255 size of username
    uint32_t session_time; // zero session time means hotspot session is no longer valid
    uint32_t inactivity_timeout; // inactivity timeout for the client, can be give by RADIUS server too 
    uint32_t acct_interim_interval; // radius accounting interval as received by RADIUS server 
    uint32_t rl_up; // up rate limit as received by RADIUS server or controller
    uint32_t rl_down; // down rate limit as received by RADIUS server or controller
    uint8_t  flags; // update accounting flag if enabled
    uint8_t  session_id[10]; // used for accounting, ap_mac+session_id, client mac is added when radius pkt is formed
    int8_t   radius_server_idx; // the server index which was used for doing radius auth and ongoing accounting
    uint8_t  quota_type; // quota type for data limit for client
    uint32_t quota_up; // quota limit as received by RADIUS server or controller
    uint32_t quota_down; // quota limit as received by RADIUS server or controller
    uint8_t  access_type;
    char     ssid[36]; // Change from char to uint8_t to make it of same data type as that of wlan config.
    uint8_t hostname[16];
    uint8_t dev_type[16];
} __attribute__ ((packed));

#define CMB_ROAM_VER    1

struct cmb_roam_msg {
    uint8_t  ver; // version of the msg
    uint8_t  radio_type;
    uint16_t vlan; // n/w order
    uint8_t  mac[MAC_ADDR_LEN];
    uint8_t  ssid[36];
    uint8_t hostname[16];
    uint8_t dev_type[16];
} __attribute__ ((packed));

#define CMB_PMK_UPDATE_VER  1

struct cmb_pmk_update_msg {
    uint8_t  ver; // version of the msg
    uint8_t  radio_id;
    uint8_t  mac[MAC_ADDR_LEN];
    uint8_t  ssid[36]; // 33 really, just rounding to nearest roundish number
    uint8_t  pmk[32];
    uint16_t vlan_id;
} __attribute__ ((packed));

struct cmb_cflags_msg {
    uint8_t ver; // version of message
    uint8_t mac[MAC_ADDR_LEN]; // client mac
    uint32_t flags;
} __attribute__ ((packed));

#define CMB_CI_SESS_VER    2

struct cmb_ci_sess_msg {
    uint8_t  ver; // version of the msg
    uint16_t vlan; // n/w order
    uint8_t  mac[MAC_ADDR_LEN];
    char     user_name[256]; // max of 255 size of username
    uint32_t session_time; // zero session time means hotspot session is no longer valid
    uint32_t inactivity_timeout; // inactivity timeout for the client, can be give by RADIUS server too
    uint32_t acct_interim_interval; // radius accounting interval as received by RADIUS server
    uint32_t rl_up; // up rate limit as received by RADIUS server or controller
    uint32_t rl_down; // down rate limit as received by RADIUS server or controller
    uint8_t  flags; // update accounting flag if enabled
    uint8_t  session_id[10]; // used for accounting, ap_mac+session_id, client mac is added when radius pkt is formed
    int8_t   radius_server_idx; // the server index which was used for doing radius auth and ongoing accounting
    uint8_t  quota_type; // quota type for data limit for client
    uint32_t quota_up; // quota limit as received by RADIUS server or controller
    uint32_t quota_down; // quota limit as received by RADIUS server or controller
    uint8_t  ssid[36];
} __attribute__ ((packed));

#define CMB_ROAM_DATA_READY_UPDATE_REQ_VER    1

struct cmb_roam_data_ready_update_msg {
    uint8_t  ver; // version of the msg
    uint8_t  do_acct_stop; // if set the old AP will do accounting stop
    uint8_t  mac[MAC_ADDR_LEN];
} __attribute__ ((packed));

#define CMB_ACCT_STATS_VER    1

struct cmb_acct_stats_msg {
    uint8_t  ver; // version of the msg
    uint8_t  acct_running; // if this is set then the accounting update should be ignored
    uint8_t  mac[MAC_ADDR_LEN];
    uint8_t  session_id[10]; // used for accounting, if current AP session-id mismatches then AP2 will send accounting stop
    uint32_t session_time; // in case the current AP has to do stop then it can pick the session time from this message
    uint32_t ip; // IP address of the client
    uint32_t acct_interim_delay; // seconds after which interim update should be sent out for the roaming client
    uint32_t tx_pkts;
    uint32_t rx_pkts;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} __attribute__ ((packed));

#define CMB_CLB_UPDATE_VER    1

struct cmb_clb_update_msg {
    uint8_t ver;                // version of the msg
    uint8_t mac[MAC_ADDR_LEN];  // AP mac
    uint8_t radio_idx;          // Radio index
    uint8_t enabled;            // CLB enabled / not
    uint8_t client_count;       // Num clients on this radio
} __attribute__ ((packed));

struct cmb_notify_hdr {
    uint8_t             sub_type; // part of ethernet hdr type to be always CMB_ETHER_SUB_TYPE
    uint8_t             type;
    uint8_t             ap_mac[MAC_ADDR_LEN]; // AP mac from where the msg was generated
    uint16_t            len; // length is the size of what follows
    uint8_t             data[0];
} __attribute__ ((packed));

#define CMB_ARF_VER    1
struct cmb_arf_leader_msg {
    uint8_t ver;                // version of the msg
    uint8_t mac[MAC_ADDR_LEN];
    uint8_t priority;
    uint32_t elected;
} __attribute__ ((packed));

struct cmb_arf_radio {
    uint8_t mac[MAC_ADDR_LEN];  // Radio mac
    uint8_t radio_idx:1;    // Radio index
    uint8_t status:1;       // Radio ON / Off
    uint8_t auto_power:1;   // Power is automatic?
    uint8_t channel;        // Current channel
    uint8_t width;          // Current width
    uint8_t power;          // Current power
    uint8_t cfg_channel;    // Configured channel
    uint8_t cfg_power;      // Configured power
    uint8_t cfg_width;      // Configured width
} __attribute__ ((packed));

struct cmb_arf_devinfo_msg {
    uint8_t ver;                // version of the msg
    uint8_t mac[MAC_ADDR_LEN];  // Device mac
    struct cmb_arf_radio radios[2];
} __attribute__ ((packed));

struct cmb_arf_nbr {
    uint8_t bss[MAC_ADDR_LEN];  // Neighbor mac
    uint8_t channel;            // Channel heard
    uint8_t rssi;               // RSSI
    uint8_t noise;              // Noise
} __attribute__ ((packed));

struct cmb_arf_nbrinfo_msg {
    uint8_t ver;                // version of the msg
    uint8_t mac[MAC_ADDR_LEN];  // Device mac
    uint8_t cur_channel;        // Current channel
    uint8_t cur_width;          // Current width
    uint8_t num_nbrs;           // Num neighbors
    uint8_t radio_idx:1;        // Radio index
    uint8_t forced:1;           // Forced assignment - no channel change diff
    struct cmb_arf_nbr nbrs[0];
} __attribute__ ((packed));

struct cmb_arf_rfchange_msg {
    uint8_t ver;                // version of the msg
    uint8_t mac[MAC_ADDR_LEN];  // Device mac
    uint8_t radio_idx:1;        // Radio index
    uint8_t channel_change:1;   // channel change
    uint8_t power_change:1;     // power change
    uint8_t cur_channel;        // Current channel
    uint8_t cur_width;          // current width
    uint8_t cur_power;          // current power
    uint8_t channel;            // New channel
    uint8_t width;              // New width
    uint8_t power;              // New power
    uint8_t cur_if;             // current channel interference
    uint8_t new_if;             // new channel interference
} __attribute__ ((packed));

#endif
