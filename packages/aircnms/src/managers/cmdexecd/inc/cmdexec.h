#ifndef CMDEXEC_H
#define CMDEXEC_H
#include <common.h>
#include <jansson.h>
#include "ev.h"
#include "air_util.h"
#include "device_config.h"

#include "ds_list.h"
#include "ds_dlist.h"
#include "unixcomm.h"
#include "dppline.h"

#define CMDEXEC_MAX_QUEUE_DEPTH (200)
#define CMDEXEC_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define FW_OUTPUT_TAR "/tmp/downloaded_file.tar.gz"
#define FW_EXTRACTED_FOLDER  "/tmp/air-image"
#define CMDEXEC_LOG_QUEUE_SIZE (100*1024) // 100k

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

typedef struct cmdexec_response
{
    char tag[4];
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
} cmdexec_response_t;

typedef struct cmdexec_request
{
    uint32_t data_size;
    uint32_t data_type; // cmdexec_data_type_t
} cmdexec_request_t;

typedef struct cmdexec_item
{
    cmdexec_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} cmdexec_item_t;

typedef struct cmdexec_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} cmdexec_queue_t;

extern cmdexec_queue_t g_cmdexec_queue;
extern char *g_cmdexec_log_buf;
extern int   g_cmdexec_log_buf_size;
extern int   g_cmdexec_log_drop_count;
extern bool  cmdexec_log_enabled;

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

int cmdexec_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id);
bool cmdexec_mqtt_init(void);
bool cmdexec_event_init();
bool cmdexec_dequeue_timer_init();
int cmdexec_monitor_config_change();
bool cmdexec_mqtt_publish(long mlen, void *mbuf, DmMsgType type);
int cmdexec_process_cmd_msg(char* buf);
bool cmdexec_queue_msg_process();
bool cmdexec_process_msg(cmdexec_item_t *qi);
// Minimal response and constants for queue operations
//typedef struct { uint32_t response; uint32_t error; uint32_t qdrop; } cmdexec_response_t;
//enum { CMDEXEC_DATA_LOG = 3, CMDEXEC_DATA_CMD = 7 };
enum { CMDEXEC_RESPONSE_ERROR = 0 };
enum { CMDEXEC_ERROR_QUEUE = 103 };

bool cmdexec_queue_put(cmdexec_item_t **qitem, cmdexec_response_t *res);
void cmdexec_queue_item_free(cmdexec_item_t *qi);
void cmdexec_queue_init(void);
int target_cmd_reboot();
int target_cmd_device_delete();
int target_cmd_device_upgrade(); 
bool target_exec_cmd_ping(char *dest);
bool target_exec_cmd_arp();
bool target_exec_cmd_custom(char *cmd);

// UBUS service functions
bool cmdexec_ubus_tx_service_init(void);
void cmdexec_ubus_tx_service_cleanup(void);
bool cmdexec_ubus_rx_service_init(void);
void cmdexec_ubus_rx_service_cleanup(void);

// UBUS method call function
struct blob_buf;
int call_cmdexec_method(const char *method, struct blob_buf *b);

#endif // CMDEXEC_H

