#include <limits.h>
#include <stdio.h>
#include <dm.h>

#include "os_time.h"
#include "os_nif.h"
#include "dppline.h"
#include "log.h"
#include "device_config.h"
#include "unixcomm.h"
#include "ipc_dir.h"

#define DM_QM_INTERVAL         1.0    /* Default (MAX) report interval in seconds -- float */
#define DM_QM_INTERVAL_MIN     0.1    /* Minimal report interval in seconds -- float */
char fw_id[128];    

/* Global MQTT instance */
static struct ev_timer  dm_mqtt_timer;
static double           dm_mqtt_timer_interval = DM_QM_INTERVAL;
static uint8_t          dm_mqtt_buf[STATS_MQTT_BUF_SZ];

void dm_mqtt_interval_set(int interval)
{
    double dm_qm_interv;

    dm_qm_interv = (interval != 0) ? interval / 10.0 : DM_QM_INTERVAL;

    if (dm_qm_interv < DM_QM_INTERVAL_MIN) {
        dm_qm_interv = DM_QM_INTERVAL_MIN;
    }

    if (dm_qm_interv > DM_QM_INTERVAL) {
        dm_qm_interv = DM_QM_INTERVAL;
    }

    if (dm_qm_interv == dm_mqtt_timer_interval) {
        return;
    }

    LOGD("DM-QM timer interval is set to %f s", dm_qm_interv);
    dm_mqtt_timer_interval = dm_qm_interv;
    dm_mqtt_timer.repeat = dm_qm_interv;
    ev_timer_again(EV_DEFAULT, &dm_mqtt_timer);
}

bool dm_mqtt_publish(long mlen, void *mbuf, DmMsgType type)
{
    unixcomm_message_t *message = unixcomm_message_create(mbuf, mlen);
    if (!message) return false;
    unixcomm_message_set_type(message, UNIXCOMM_MSG_NOTIFICATION);
    message->request.data_size = mlen;
    bool ret;
    if (type == EVENT) {
        message->request.data_type = DATA_EVENT;
        message->topic = strdup("event");
    } else if (type == CONF) {
        message->request.data_type = DATA_CONF;
        message->topic = strdup("conf");
    }
    message->request.topic_len = strlen(message->topic);
    bool ok = unixcomm_send_to_process(UNIXCOMM_PROCESS_QM, message, NULL);
    unixcomm_message_destroy(message);
    return ok;
}

void dm_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    //static bool qm_err = false;
    //uint32_t buf_len;
    
    //if (!dm_check_alarm(dm_mqtt_buf, sizeof(dm_mqtt_buf), &buf_len)) {
      //  LOGE("Get report failed.\n");
    //}
    //check_memory_alarm();
    //check_cpu_alarm();

    dm_monitor_config_change();
        
}

bool dm_mqtt_init(void)
{
    ev_timer_init(&dm_mqtt_timer, dm_mqtt_timer_handler, dm_mqtt_timer_interval, dm_mqtt_timer_interval);

    dm_mqtt_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &dm_mqtt_timer);

    return true;
}

int dm_send_event_to_cloud(event_type_t type, event_status_t status, char *data, char *id)
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
    memcpy(dm_mqtt_buf, &info, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);

    // Send event via MQTT
    rc = dm_mqtt_publish(buf_len, dm_mqtt_buf, EVENT);

    return rc;
}


