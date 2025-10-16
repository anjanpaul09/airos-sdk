#ifndef QM_H_INCLUDED
#define QM_H_INCLUDED

#include "ev.h"
#include <pthread.h>

#include "device_config.h"
#include "report.h"
#include "air_util.h"
#include "ds_list.h"
#include "ds_dlist.h"
//#include "qm_conn.h"
//#include "../../../libs/datapipeline/inc/dppline.h"

#define QM_MAX_QUEUE_DEPTH (200)
#define QM_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define QM_LOG_QUEUE_SIZE (100*1024) // 100k

//updebug.log file
#define QM_UPDEBUG_LOG "/tmp/updebug.log" 
//downdebug.log file
#define QM_DOWNDEBUG_LOG "/tmp/downdebug.log" 
#define QM_MAX_TOPIC_LEN 264

static inline char *qm_timestamp_ms_to_date (uint64_t   timestamp_ms)
{
    struct tm      *dt;
    time_t          t = timestamp_ms / 1000;
    static char     b[32];

    dt = localtime((time_t *)&t);

    memset (b, 0, sizeof(b));
    strftime(b, sizeof(b), "%F %T%z", dt);

    return b;
}

enum qm_response_type
{
    QM_RESPONSE_ERROR    = 0, // error response
    QM_RESPONSE_STATUS   = 1, // status response
    QM_RESPONSE_RECEIVED = 2, // message received confirmation
    QM_RESPONSE_IGNORED  = 3, // response ignored
};

// error type
enum qm_res_error
{
    QM_ERROR_NONE        = 0,   // no error
    QM_ERROR_GENERAL     = 100, // general error
    QM_ERROR_CONNECT     = 101, // error connecting to QM
    QM_ERROR_INVALID     = 102, // invalid response
    QM_ERROR_QUEUE       = 103, // error enqueuing message
    QM_ERROR_SEND        = 104, // error sending to mqtt (for immediate flag)
};

typedef struct qm_response
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
} qm_response_t;

typedef struct qm_request
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
} qm_request_t;

// queue item
typedef struct qm_item
{
    qm_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} qm_item_t;

typedef struct qm_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} qm_queue_t;

extern qm_queue_t g_qm_queue;
extern pthread_mutex_t g_qm_queue_mutex;
extern pthread_cond_t  g_qm_queue_cond;

typedef struct topic_list
{
    int n_topic;
    char topic[16][QM_MAX_TOPIC_LEN];
} qm_mqtt_topic_list;

extern qm_mqtt_topic_list qm_topic_lst;

// Structure to hold stats topic information
typedef struct {
    char device[QM_MAX_TOPIC_LEN];
    char client[QM_MAX_TOPIC_LEN];
    char vif[QM_MAX_TOPIC_LEN];
    char neighbor[QM_MAX_TOPIC_LEN];
    char config[QM_MAX_TOPIC_LEN];
    char cmdr[QM_MAX_TOPIC_LEN];
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

extern char *g_qm_log_buf;
extern int   g_qm_log_buf_size;
extern int   g_qm_log_drop_count;
extern bool  qm_log_enabled;

int qm_ovsdb_init(void);

bool qm_mqtt_init(void);
void qm_mqtt_stop(void);
bool qm_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void qm_mqtt_set_log_interval(int log_interval);
void qm_mqtt_set_agg_stats_interval(int agg_stats_interval);
bool qm_mqtt_is_connected();
bool qm_mqtt_config_valid();
void qm_mqtt_reconnect();
bool qm_mqtt_start_worker();
void qm_mqtt_stop_worker();

void qm_queue_item_free_buf(qm_item_t *qi);
void qm_queue_item_free(qm_item_t *qi);
void qm_queue_init();
int qm_queue_length();
int qm_queue_size();
bool qm_queue_head(qm_item_t **qitem);
bool qm_queue_tail(qm_item_t **qitem);
bool qm_queue_remove(qm_item_t *qitem);
bool qm_queue_drop_head();
bool qm_queue_make_room(qm_item_t *qi, qm_response_t *res);
bool qm_queue_put(qm_item_t **qitem, qm_response_t *res);
bool qm_queue_get(qm_item_t **qitem);

// unixcomm server lifecycle
bool qm_unixcomm_server_init(void);
void qm_unixcomm_server_cleanup(void);

// Time-event logs collector and report generator
void mqtt_telog_init(struct ev_loop *ev);
void mqtt_telog_fini(void);

int qm_check_debug_status();


bool qm_parse_device_newjson(device_report_data_t *device, char *data);
bool qm_parse_vif_newjson(vif_report_data_t *vif, char *data);
bool qm_parse_client_newjson(client_report_data_t *client, char *data);
int qm_parse_config_newjson(device_conf_t *conf, char *data);
bool qm_parse_alarm_newjson(alarm_msg_t *alarm, char *data);
bool qm_parse_event_newjson(event_msg_t *event, char *data);
bool qm_parse_neighbor_newjson(neighbor_report_data_t *rpt, char *data); 

bool qm_send_event_cloud(qm_item_t *qi);
bool qm_send_config_cloud(qm_item_t *qi);

void decrypt_aes(const char* encrypted_string, const char* base64_key, char* decrypted_output); 

void qm_add_topic_aircnms(qm_mqtt_topic_list *topic_list);
void qm_add_stats_topic_aircnms(stats_topic_t *stats_topic);
int qm_update_topic_lst(qm_mqtt_topic_list *topic_list);
void qm_get_stats_topic_aircnms(stats_topic_t *stats_topic);

#endif /* QM_H_INCLUDED */
