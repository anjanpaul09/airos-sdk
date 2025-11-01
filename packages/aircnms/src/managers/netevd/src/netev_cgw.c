#include <limits.h>
#include <stdio.h>
#include <libubox/blobmsg_json.h>
#include <netev.h>

#include "os_time.h"
#include "os_nif.h"
#include "dppline.h"
#include "log.h"
#include "device_config.h"
#include "unixcomm.h"
#include "ipc_dir.h"

static uint8_t          netev_mqtt_buf[STATS_MQTT_BUF_SZ];
static struct ev_timer  netev_mqtt_timer;
static double           netev_mqtt_timer_interval = 10;

bool netev_mqtt_publish(long mlen, void *mbuf, DmMsgType type)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", mbuf, mlen);
    blobmsg_add_u32(&b, "size", mlen);
    if (type == EVENT) {
        call_netev_method("netev.event", &b);
    } else if (type == CONF) {
        call_netev_method("netev.conf", &b);
    }
    blob_buf_free(&b);
    return 0;
}

void netev_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    netev_monitor_config_change();
        
}

bool netev_monitor_init(void)
{
    ev_timer_init(&netev_mqtt_timer, netev_mqtt_timer_handler, netev_mqtt_timer_interval, netev_mqtt_timer_interval);

    netev_mqtt_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &netev_mqtt_timer);

    return true;
}

int netev_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id)
{
    int rc;
    uint32_t buf_len;
    event_msg_t info;

    memset(&info, 0, sizeof(event_msg_t));

    info.type = type;
    info.status = status;

    if (type == EVENT_TYPE_CMD) {
        strncpy(info.cloud_id, id, MAX_DATA_LEN - 1);
        info.cloud_id[MAX_DATA_LEN - 1] = '\0';

        strncpy(info.data, data, MAX_DATA_LEN - 1);
        info.data[MAX_DATA_LEN - 1] = '\0';
    }
    else if (type == EVENT_TYPE_UPGRADE) {
        get_fw_id_frm_aircnms(info.cloud_id);  // Pass array directly
    }

    // Serialize the event message
    memcpy(netev_mqtt_buf, &info, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);

    // Send event via MQTT
    rc = netev_mqtt_publish(buf_len, netev_mqtt_buf, EVENT);

    return rc;
}


