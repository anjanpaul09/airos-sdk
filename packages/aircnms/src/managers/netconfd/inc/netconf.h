#ifndef NETCONF_H_INCLUDED
#define NETCONF_H_INCLUDED

#include <common.h>
#include "ev.h"

#include "ds_list.h"
#include "ds_dlist.h"
#include "unixcomm.h"
#include "config.h"
#include "air_util.h"
#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "netconf_validate.h"
#include <radio_vif.h>

#define NETCONF_MAX_QUEUE_DEPTH (200)
#define NETCONF_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define NETCONF_LOG_QUEUE_SIZE (100*1024) // 100k
#define UCI_OPTION_SSID             "ssid"
#define UCI_OPTION_TXPOWER          "txpower"
#define UCI_OPTION_CHANNEL          "channel"

#define RA_PROFILE "/etc/wireless/mediatek/mt7915.dbdc.b0.dat"
#define RAX_PROFILE "/etc/wireless/mediatek/mt7915.dbdc.b1.dat"

// Define flag bits with the new numbering
#define FLAG_NO_CHANGE        (1 << 0)  // Bit 0: 0b0001 => Value 1
#define FLAG_WIRELESS_CHANGE  (1 << 1)  // Bit 1: 0b0010 => Value 2
#define FLAG_NETWORK_CHANGE   (1 << 2)  // Bit 2: 0b0100 => Value 4

extern uint32_t flags;  // Declaration: flags is defined elsewhere

extern char fw_id[128];

// Function to set a flag
static inline void set_flag(uint32_t *flags, uint32_t flag) {
    *flags |= flag;
}

// Function to clear a flag
static inline void clear_flag(uint32_t *flags, uint32_t flag) {
    *flags &= ~flag;
}

// Function to check if a flag is set
static inline bool is_flag_set(uint32_t flags, uint32_t flag) {
    return (flags & flag) != 0;
}

typedef enum netconf_intf_reset {
    NETCONF_INTF_RESET_STOP = 0,
    NETCONF_INTF_RESET_START,
} netconf_intf_reset_t;

typedef enum netconf_radio_status {
    RADIO_SETTING_PRIMARY = 1, // wireless
    RADIO_SETTING_SECONDARY,   // radio planning
} netconf_radio_status_t;

typedef enum netconf_vif_status {
    VIF_ADD = 1,
    VIF_DISABLE,
    VIF_MODIFY,
} netconf_vif_status_t;

typedef struct netconf_uci{
    const char *nodeId;
    const char *radioType;
    const char *ifName;
    const char *phyName;
    const char *channel;
    const char *txPower;
    const char *ssid;
} netconf_uci_t;

// Minimal request/response and data type definitions for internal NETCONF queueing
typedef enum netconf_req_data_type
{
    NETCONF_DATA_RAW = 0,
    NETCONF_DATA_TEXT,
    NETCONF_DATA_STATS,
    NETCONF_DATA_LOG,
    NETCONF_DATA_INI,
    NETCONF_DATA_CONF,
    NETCONF_DATA_CMD,
    NETCONF_DATA_ACL,
    NETCONF_DATA_RL
} netconf_data_type_t;

typedef struct netconf_request
{
    uint32_t data_size;
    uint32_t data_type; // netconf_data_type_t
} netconf_request_t;

enum netconf_response_type
{
    NETCONF_RESPONSE_ERROR    = 0,
    NETCONF_RESPONSE_STATUS   = 1,
    NETCONF_RESPONSE_RECEIVED = 2,
    NETCONF_RESPONSE_IGNORED  = 3,
};

enum netconf_res_error
{
    NETCONF_ERROR_NONE   = 0,
    NETCONF_ERROR_GENERAL= 100,
    NETCONF_ERROR_QUEUE  = 103,
};

typedef struct netconf_response
{
    uint32_t response;
    uint32_t error;
    uint32_t qdrop;
} netconf_response_t;

// queue item

typedef struct netconf_item
{
    netconf_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} netconf_item_t;

typedef struct netconf_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} netconf_queue_t;

extern netconf_queue_t g_netconf_queue;
extern char *g_netconf_log_buf;
extern int   g_netconf_log_buf_size;
extern int   g_netconf_log_drop_count;
extern bool  netconf_log_enabled;

int netconf_ovsdb_init(void);

bool netconf_mqtt_init(void);
void netconf_mqtt_stop(void);
bool netconf_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void netconf_mqtt_set_log_interval(int log_interval);
void netconf_mqtt_set_agg_stats_interval(int agg_stats_interval);
bool netconf_mqtt_is_connected();
bool netconf_mqtt_config_valid();
bool netconf_mqtt_send_message(netconf_item_t *qi, netconf_response_t *res);
void netconf_mqtt_send_queue();
void netconf_mqtt_reconnect();

void netconf_queue_item_free_buf(netconf_item_t *qi);
void netconf_queue_item_free(netconf_item_t *qi);
void netconf_queue_init();
int netconf_queue_length();
int netconf_queue_size();
bool netconf_queue_head(netconf_item_t **qitem);
bool netconf_queue_tail(netconf_item_t **qitem);
bool netconf_queue_remove(netconf_item_t *qitem);
bool netconf_queue_drop_head();
bool netconf_queue_make_room(netconf_item_t *qi, netconf_response_t *res);
bool netconf_queue_put(netconf_item_t **qitem, netconf_response_t *res);
bool netconf_queue_get(netconf_item_t **qitem);

bool netconf_event_init();
bool netconf_dequeue_timer_init();
bool netconf_queue_msg_process();
bool netconf_process_msg(netconf_item_t *qi);

// Time-event logs collector and report generator
void mqtt_telog_init(struct ev_loop *ev);
void mqtt_telog_fini(void);

bool set_intf_reset_progress_indication(netconf_intf_reset_t reset);
int target_netconfd_fw_upgrade(); 
int netconf_send_event_to_cloud(event_type type, event_status status);

// UBUS and unixcomm initialization functions
bool netconf_ubus_service_init(void);
void netconf_ubus_service_cleanup(void);
bool netconf_unixcomm_server_init(void);
void netconf_unixcomm_server_cleanup(void);

// ACL functions
bool netconf_handle_add_blacklist_ssid(char *mac, char *ssid);
bool netconf_handle_add_whitelist_ssid(char *mac, char *ssid);

// VLAN functions
void check_existing_vlan(const char *section_name);
void set_vlan_network(int vlan, const char* section_name);

int netconf_process_set_msg(char* buf);
int netconf_process_acl_msg(char *buf);
int netconf_process_user_rl_msg(char *buf);
bool target_config_vif_set(vif_record_t *record);
bool target_config_radio_set(radio_record_t *record);
int netconf_handle_add_blacklist(char *mac);
int netconf_handle_remove_blacklist(char *mac);
int netconf_handle_add_whitelist(char *mac);
int netconf_handle_remove_whitelist(char *mac);
int netconf_handle_nat_config(nat_config_t *config);
void netconf_handle_captive_portal(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
void air_user_rate_limit(uint8_t *mac, int rate, int dir);
//void check_existing_vlan(const char *section_name);
//void set_vlan_network(int vlan, const char* section_name);
bool netconf_check_wifi_config(void); 
void air_interface_rate_limit(char *vif_name, int rate, int dir, char *type);

int execute_uci_command(const char *command, char *result, size_t result_size); 
int uci_set_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params);
int uci_get_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params);
int uci_get_all_section_names(char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names);
int uci_get_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
int uci_set_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
int jedi_set_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
int jedi_set_primary_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params);
int jedi_set_secondary_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params);
int jedi_del_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
bool sanitize_and_validate_vif_params(struct airpro_mgr_wlan_vap_params *p);
bool sanitize_and_validate_primary_radio_settings(const char *band, struct airpro_mgr_wlan_radio_params *params);
bool sanitize_and_validate_secondary_radio_settings(const char *radio_name, const char *band, struct airpro_mgr_wlan_radio_params *params);
void get_ht_mode(char *htmode, struct airpro_mgr_wlan_radio_params rp, const char *radio_name);
void get_encryption_type(char *encrypt_type, const char *encryption);

const char *get_config_file(const char *iface); 
int map_interface_to_index(const char *iface); 
#endif /* NETCONF_H_INCLUDED */
