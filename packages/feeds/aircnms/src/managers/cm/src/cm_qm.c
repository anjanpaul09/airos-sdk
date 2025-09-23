#include <limits.h>
#include <stdio.h>

#include "os_time.h"
#include "os_nif.h"
#include "log.h"

#include "dppline.h"
#include "qm_conn.h"
#include "cm.h"
#include "device_config.h"

static uint8_t          cm_mqtt_buf[STATS_MQTT_BUF_SZ];

static
bool cm_mqtt_publish(long mlen, void *mbuf)
{
    qm_response_t res;
    bool ret;
    strcpy(res.tag, "event");
    ret = qm_conn_send_stats(mbuf, mlen, &res);
    return ret;
}
#if 0
void cm_mqtt_handler(uint8_t *cm_mqtt_buf, uint32_t buf_len)
{
    static bool qm_err = false;
    //uint32_t buf_len;

    // Do not report any stats if QM is not running
    if (!qm_conn_get_status(NULL)) {
        if (!qm_err) {
            // don't repeat same error
            LOG(INFO, "Cannot connect to QM (QM not running?)");
        }

        qm_err = true;
        return;
    }

    qm_err = false;
    //if (buf_len <= 0) continue;
    if (!cm_mqtt_publish(buf_len, cm_mqtt_buf)) {
            LOGE("Publish report failed.\n");
           // break;
    }
}
#endif

int cm_mqtt_handler(uint8_t *cm_mqtt_buf, uint32_t buf_len) 
{
    static bool qm_err = false;

    // Do not report any stats if QM is not running
    if (!qm_conn_get_status(NULL)) {
        if (!qm_err) {
            LOG(INFO, "Cannot connect to QM (QM not running?)");
        }

        qm_err = true;
        return -1;
    }

    qm_err = false;

    // Attempt to publish the MQTT message
    if (!cm_mqtt_publish(buf_len, cm_mqtt_buf)) {
        LOGE("Publish report failed.\n");
        return -1; 
    }

    return 0; 
}

int cm_send_event_to_cloud(event_type type, event_status status)
{
    int rc;
    uint32_t buf_len;
    event_msg_t info;

    memset(&info, 0, sizeof(event_info));

    info.type = type;
    info.status = status;
    if (status == DOWNLOADED || status == FAILED || status == UPGRADING) {
        //strcpy(info.data, fw_id);
    } else if (status == UPGRADED) {
        get_fw_id_frm_aircnms(info.data);
    }
    
    // Serialize the event message
    memcpy(cm_mqtt_buf, &info, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);
   
    rc = cm_mqtt_handler(cm_mqtt_buf, buf_len);

    return rc;
}
