#include <limits.h>
#include <stdio.h>
#include <libubox/blobmsg_json.h>
#include <cmdexec.h>

#include "os_time.h"
#include "os_nif.h"
#include "dppline.h"
#include "log.h"
#include "device_config.h"
#include "unixcomm.h"
#include "ipc_dir.h"

char fw_id[128];    
static uint8_t          cmdexec_mqtt_buf[STATS_MQTT_BUF_SZ];

bool cmdexec_mqtt_publish(long mlen, void *mbuf, DmMsgType type)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", mbuf, mlen);
    blobmsg_add_u32(&b, "size", mlen);
    call_cmdexec_method("cmdexec.event", &b);
    blob_buf_free(&b);
    return 0;
}

int cmdexec_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id)
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
    memcpy(cmdexec_mqtt_buf, &info, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);

    // Send event via MQTT
    rc = cmdexec_mqtt_publish(buf_len, cmdexec_mqtt_buf, EVENT);

    return rc;
}


