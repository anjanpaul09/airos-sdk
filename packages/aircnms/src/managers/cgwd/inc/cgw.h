#ifndef CGW_H_INCLUDED
#define CGW_H_INCLUDED

#include "ev.h"
#include <pthread.h>

#include "device_config.h"
#include "stats_report.h"
#include "air_util.h"
#include "ds_list.h"
#include "ds_dlist.h"
#include <libubox/blobmsg.h>

struct blob_buf;  // Forward declaration

#define CGW_MAX_QUEUE_DEPTH (200)
#define CGW_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define CGW_LOG_QUEUE_SIZE (100*1024) // 100k

//updebug.log file
#define CGW_UPDEBUG_LOG "/tmp/updebug.log" 
//downdebug.log file
#define CGW_DOWNDEBUG_LOG "/tmp/downdebug.log" 
#define CGW_MAX_TOPIC_LEN 264

static inline char *cgw_timestamp_ms_to_date (uint64_t   timestamp_ms)
{
    struct tm      *dt;
    time_t          t = timestamp_ms / 1000;
    static char     b[32];

    dt = localtime((time_t *)&t);

    memset (b, 0, sizeof(b));
    strftime(b, sizeof(b), "%F %T%z", dt);

    return b;
}

enum cgw_response_type
{
    CGW_RESPONSE_ERROR    = 0, // error response
    CGW_RESPONSE_STATUS   = 1, // status response
    CGW_RESPONSE_RECEIVED = 2, // message received confirmation
    CGW_RESPONSE_IGNORED  = 3, // response ignored
};

// error type
enum cgw_res_error
{
    CGW_ERROR_NONE        = 0,   // no error
    CGW_ERROR_GENERAL     = 100, // general error
    CGW_ERROR_CONNECT     = 101, // error connecting to CGW
    CGW_ERROR_INVALID     = 102, // invalid response
    CGW_ERROR_QUEUE       = 103, // error enqueuing message
    CGW_ERROR_SEND        = 104, // error sending to mqtt (for immediate flag)
};

typedef struct cgw_response
{
    char tag[8];
    uint32_t ver;
    uint32_t seq;
    uint32_t response;
    uint32_t error;
    uint32_t flags;
    uint32_t conn_status;
    // stats
    uint32_t qlen;  // queue length - number of messages
    uint32_t qsize; // queue size - bytes
    uint32_t qdrop; // num queued messages dropped due to queue full
    uint32_t log_size; // log buffer size
    uint32_t log_drop; // log dropped lines
} cgw_response_t;

typedef struct cgw_request
{
    char tag[4];
    uint32_t ver;
    uint32_t seq;
    uint32_t cmd;
    uint32_t flags;
    char sender[16]; // prog name

    uint8_t set_qos; // if 1 use qos_val instead of ovsdb cfg
    uint8_t qos_val;
    uint8_t compress;
    uint8_t data_type;

    uint32_t interval;
    uint32_t topic_len;
    uint32_t data_size;
    uint32_t reserved;
} cgw_request_t;

// queue item
typedef struct cgw_item
{
    cgw_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} cgw_item_t;

typedef struct cgw_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} cgw_queue_t;

extern cgw_queue_t g_cgw_queue;
extern pthread_mutex_t g_cgw_queue_mutex;
extern pthread_cond_t  g_cgw_queue_cond;

typedef struct topic_list
{
    int n_topic;
    char topic[16][CGW_MAX_TOPIC_LEN];
} cgw_mqtt_topic_list;

extern cgw_mqtt_topic_list cgw_topic_lst;

// Structure to hold stats topic information
typedef struct {
    char device[CGW_MAX_TOPIC_LEN];
    char client[CGW_MAX_TOPIC_LEN];
    char vif[CGW_MAX_TOPIC_LEN];
    char neighbor[CGW_MAX_TOPIC_LEN];
    char config[CGW_MAX_TOPIC_LEN];
    char cmdr[CGW_MAX_TOPIC_LEN];
} stats_topic_t;

extern stats_topic_t stats_topic;

typedef struct air_device{
    char device_id[32];
    char serial_num[32];
    char macaddr[32];
    char air_stat_topic[64];
    char air_get_topic[64];
    char air_set_topic[64];
    char org_id[128];
    char username[128];
    char password[128];
} air_device_t;

extern air_device_t air_dev;

extern char *g_cgw_log_buf;
extern int   g_cgw_log_buf_size;
extern int   g_cgw_log_drop_count;
extern bool  cgw_log_enabled;

bool cgw_mqtt_init(void);
void cgw_mqtt_stop(void);
bool cgw_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void cgw_mqtt_set_agg_stats_interval(int agg_stats_interval);
bool cgw_mqtt_is_connected();
bool cgw_mqtt_config_valid();
void cgw_mqtt_reconnect();
bool cgw_mqtt_start_worker();
void cgw_mqtt_stop_worker();

void cgw_queue_item_free_buf(cgw_item_t *qi);
void cgw_queue_item_free(cgw_item_t *qi);
void cgw_queue_init();
int cgw_queue_length();
int cgw_queue_size();
bool cgw_queue_head(cgw_item_t **qitem);
bool cgw_queue_tail(cgw_item_t **qitem);
bool cgw_queue_remove(cgw_item_t *qitem);
bool cgw_queue_drop_head();
bool cgw_queue_make_room(cgw_item_t *qi, cgw_response_t *res);
bool cgw_queue_put(cgw_item_t **qitem, cgw_response_t *res);
bool cgw_queue_get(cgw_item_t **qitem);

// unixcomm server lifecycle
bool cgw_unixcomm_server_init(void);
void cgw_unixcomm_server_cleanup(void);

// Time-event logs collector and report generator
void mqtt_telog_init(struct ev_loop *ev);
void mqtt_telog_fini(void);

int cgw_check_debug_status();


bool cgw_parse_device_newjson(device_report_data_t *device, char *data);
bool cgw_parse_vif_newjson(vif_report_data_t *vif, char *data);
bool cgw_parse_client_newjson(client_report_data_t *client, char *data);
int cgw_parse_config_newjson(device_conf_t *conf, char *data);
bool cgw_parse_alarm_newjson(alarm_msg_t *alarm, char *data);
bool cgw_parse_event_newjson(event_msg_t *event, char *data);
bool cgw_parse_neighbor_newjson(neighbor_report_data_t *rpt, char *data); 

bool cgw_send_event_cloud(cgw_item_t *qi);
bool cgw_send_config_cloud(cgw_item_t *qi);

void decrypt_aes(const char* encrypted_string, const char* base64_key, char* decrypted_output); 

void cgw_add_topic_aircnms(cgw_mqtt_topic_list *topic_list);
void cgw_add_stats_topic_aircnms(stats_topic_t *stats_topic);
int cgw_update_topic_lst(cgw_mqtt_topic_list *topic_list);
void cgw_get_stats_topic_aircnms(stats_topic_t *stats_topic);

// Device state management functions
bool cgw_check_valid_device_id(void);
bool cgw_device_discovery_request(void);
bool cgw_set_online_status(void);

// Utility functions
int cmd_buf(const char *command, char *buffer, size_t buffer_size);

// WebSocket functions
int ws_init(void);
void ws_cleanup(void);

// UBUS TX functions
int call_netconfd_method(const char *method, struct blob_buf *b);
int call_cmdexec_method(const char *method, struct blob_buf *b);
int call_netstats_method(const char *method, struct blob_buf *b);

// Initialization functions
bool cgw_params_init(void);
bool cgw_ubus_rx_service_init(void);
bool cgw_ubus_service_init(void);
void cgw_ubus_service_cleanup(void);
void cgw_ubus_rx_service_cleanup(void);

// Message handling functions
bool cgw_send_msg_to_cm(char *payload, long payloadlen, char *topic);
void cgw_mqtt_signal_new_item(void);

#endif /* CGW_H_INCLUDED */
