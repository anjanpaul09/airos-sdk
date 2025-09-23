#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H
#include <common.h>
#include <jansson.h>
#include "ev.h"
#include "air_util.h"
#include "device_config.h"

#include "ds_list.h"
#include "ds_dlist.h"
#include "dm_conn.h"
#include "dppline.h"

#define DM_MAX_QUEUE_DEPTH (200)
#define DM_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define FW_OUTPUT_TAR "/tmp/downloaded_file.tar.gz"
#define FW_EXTRACTED_FOLDER  "/tmp/air-image"
#define DM_LOG_QUEUE_SIZE (100*1024) // 100k

extern char fw_id[128];
extern char cmd_id[128];    

typedef enum {
    EVENT = 1,
    CONF = 2
} DmMsgType;

// Define the DeviceInfo structure
typedef struct {
    char fw_info[64];
    char hw_version[16];
    char mgmt_ip[16];
    char egress_ip[16];
} DeviceConfig;

extern DeviceConfig g_previous_config;
// queue item

typedef struct dm_item
{
    dm_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} dm_item_t;

typedef struct dm_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} dm_queue_t;

extern dm_queue_t g_dm_queue;
extern char *g_dm_log_buf;
extern int   g_dm_log_buf_size;
extern int   g_dm_log_drop_count;
extern bool  dm_log_enabled;

// Define `command_func`
typedef void (*command_func)(json_t *root);

// Command mapping struct
typedef struct {
    const char* keyword;
    command_func handler;
} CommandMapping;

// Command Function declarations
void handle_reboot(json_t *root);
void handle_device_delete(json_t *root);
void handle_device_upgrade(json_t *root);

int dm_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id);
bool dm_mqtt_init(void);
bool dm_event_init();
bool dm_dequeue_timer_init();
int dm_monitor_config_change();
bool dm_mqtt_publish(long mlen, void *mbuf, DmMsgType type);
int dm_process_cmd_msg(char* buf);
bool dm_queue_msg_process();
bool dm_process_msg(dm_item_t *qi);
bool dm_queue_put(dm_item_t **qitem, dm_response_t *res);
void dm_queue_item_free(dm_item_t *qi);
void dm_queue_init(void);
int target_cmd_reboot();
int target_cmd_device_delete();
int target_cmd_device_upgrade(); 
bool target_exec_cmd_ping(char *dest);
bool target_exec_cmd_arp();
bool target_exec_cmd_custom(char *cmd);

#endif // DEVICE_CONFIG_H

