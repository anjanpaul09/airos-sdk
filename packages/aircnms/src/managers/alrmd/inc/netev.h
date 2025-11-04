#ifndef NETEV_H
#define NETEV_H
#include <common.h>
#include <jansson.h>
#include "ev.h"
#include "air_util.h"
#include "device_config.h"

#include "ds_list.h"
#include "ds_dlist.h"
#include "unixcomm.h"
#include "dppline.h"
#include <libubox/blobmsg.h>

#define NETEV_MAX_QUEUE_DEPTH (200)
#define NETEV_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

#define NETEV_LOG_QUEUE_SIZE (100*1024) // 100k

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


// Define `command_func`
typedef void (*command_func)(json_t *root);

int netev_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id);
int netev_monitor_config_change();
bool netev_mqtt_publish(long mlen, void *mbuf, DmMsgType type);
enum { NETEV_RESPONSE_ERROR = 0 };
enum { NETEV_ERROR_QUEUE = 103 };

// UBUS service functions
bool netev_ubus_tx_service_init(void);
void netev_ubus_tx_service_cleanup(void);

// Monitor functions
bool netev_monitor_init(void);

// UBUS method call function
struct blob_buf;
int call_netev_method(const char *method, struct blob_buf *b);

#endif // NETEV_H

