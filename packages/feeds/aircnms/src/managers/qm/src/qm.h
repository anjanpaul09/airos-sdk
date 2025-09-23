#ifndef QM_H_INCLUDED
#define QM_H_INCLUDED

#include "ev.h"

#include "device_config.h"
#include "report.h"
#include "air_util.h"
#include "ds_list.h"
#include "ds_dlist.h"
#include "qm_conn.h"
//#include "../../../libs/datapipeline/inc/dppline.h"

#define QM_MAX_QUEUE_DEPTH (200)
#define QM_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define QM_LOG_QUEUE_SIZE (100*1024) // 100k

//updebug.log file
#define QM_UPDEBUG_LOG "/tmp/updebug.log" 
//downdebug.log file
#define QM_DOWNDEBUG_LOG "/tmp/downdebug.log" 
#define QM_MAX_TOPIC_LEN 264

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
bool qm_mqtt_send_message(qm_item_t *qi, qm_response_t *res);
void qm_mqtt_send_queue();
void qm_mqtt_reconnect();

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

bool qm_event_init();

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
