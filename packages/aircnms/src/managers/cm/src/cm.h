#ifndef CM_H_INCLUDED
#define CM_H_INCLUDED

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
//#include "uci_ops.h"
#include <radio_vif.h>

#define CM_MAX_QUEUE_DEPTH (200)
#define CM_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define CM_LOG_QUEUE_SIZE (100*1024) // 100k
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

typedef enum cm_intf_reset {
    CM_INTF_RESET_STOP = 0,
    CM_INTF_RESET_START,
} cm_intf_reset_t;

typedef enum cm_radio_status {
    RADIO_SETTING_PRIMARY = 1, // wireless
    RADIO_SETTING_SECONDARY,   // radio planning
} cm_radio_status_t;

typedef enum cm_vif_status {
    VIF_ADD = 1,
    VIF_DISABLE,
    VIF_MODIFY,
} cm_vif_status_t;

typedef struct cm_uci{
    const char *nodeId;
    const char *radioType;
    const char *ifName;
    const char *phyName;
    const char *channel;
    const char *txPower;
    const char *ssid;
} cm_uci_t;

// Minimal request/response and data type definitions for internal CM queueing
typedef enum cm_req_data_type
{
    CM_DATA_RAW = 0,
    CM_DATA_TEXT,
    CM_DATA_STATS,
    CM_DATA_LOG,
    CM_DATA_INI,
    CM_DATA_CONF,
    CM_DATA_CMD,
    CM_DATA_ACL,
    CM_DATA_RL
} cm_data_type_t;

typedef struct cm_request
{
    uint32_t data_size;
    uint32_t data_type; // cm_data_type_t
} cm_request_t;

enum cm_response_type
{
    CM_RESPONSE_ERROR    = 0,
    CM_RESPONSE_STATUS   = 1,
    CM_RESPONSE_RECEIVED = 2,
    CM_RESPONSE_IGNORED  = 3,
};

enum cm_res_error
{
    CM_ERROR_NONE   = 0,
    CM_ERROR_GENERAL= 100,
    CM_ERROR_QUEUE  = 103,
};

typedef struct cm_response
{
    uint32_t response;
    uint32_t error;
    uint32_t qdrop;
} cm_response_t;

// queue item

typedef struct cm_item
{
    cm_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} cm_item_t;

typedef struct cm_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} cm_queue_t;

extern cm_queue_t g_cm_queue;
extern char *g_cm_log_buf;
extern int   g_cm_log_buf_size;
extern int   g_cm_log_drop_count;
extern bool  cm_log_enabled;

int cm_ovsdb_init(void);

bool cm_mqtt_init(void);
void cm_mqtt_stop(void);
bool cm_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void cm_mqtt_set_log_interval(int log_interval);
void cm_mqtt_set_agg_stats_interval(int agg_stats_interval);
bool cm_mqtt_is_connected();
bool cm_mqtt_config_valid();
bool cm_mqtt_send_message(cm_item_t *qi, cm_response_t *res);
void cm_mqtt_send_queue();
void cm_mqtt_reconnect();

void cm_queue_item_free_buf(cm_item_t *qi);
void cm_queue_item_free(cm_item_t *qi);
void cm_queue_init();
int cm_queue_length();
int cm_queue_size();
bool cm_queue_head(cm_item_t **qitem);
bool cm_queue_tail(cm_item_t **qitem);
bool cm_queue_remove(cm_item_t *qitem);
bool cm_queue_drop_head();
bool cm_queue_make_room(cm_item_t *qi, cm_response_t *res);
bool cm_queue_put(cm_item_t **qitem, cm_response_t *res);
bool cm_queue_get(cm_item_t **qitem);

bool cm_event_init();
bool cm_dequeue_timer_init();
bool cm_queue_msg_process();
bool cm_process_msg(cm_item_t *qi);

// Time-event logs collector and report generator
void mqtt_telog_init(struct ev_loop *ev);
void mqtt_telog_fini(void);

bool set_intf_reset_progress_indication(cm_intf_reset_t reset);
int target_cmd_fw_upgrade(); 
int cm_send_event_to_cloud(event_type type, event_status status);

int cm_process_set_msg(char* buf);
int cm_process_acl_msg(char *buf);
int cm_process_user_rl_msg(char *buf);
bool target_config_vif_set(vif_record_t *record);
bool target_config_radio_set(radio_record_t *record);
int cm_handle_add_blacklist(char *mac);
int cm_handle_remove_blacklist(char *mac);
int cm_handle_add_whitelist(char *mac);
int cm_handle_remove_whitelist(char *mac);
int cm_handle_nat_config(nat_config_t *config);
void cm_handle_captive_portal(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
void air_user_rate_limit(uint8_t *mac, int rate, int dir);
//void check_existing_vlan(const char *section_name);
//void set_vlan_network(int vlan, const char* section_name);
bool cm_check_wifi_config(void); 
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


const char *get_config_file(const char *iface); 
int map_interface_to_index(const char *iface); 
#endif /* CM_H_INCLUDED */
