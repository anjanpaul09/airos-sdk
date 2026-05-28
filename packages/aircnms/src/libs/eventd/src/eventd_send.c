#include <errno.h>
#include <string.h>
#include <time.h>

#include "libeventd.h"
#include "eventd_internal.h"
#include "log.h"

#define STATS_MQTT_BUF_SZ        (128*1024)    // 128 KB
#define MAX_RETRY_ATTEMPTS        3
#define RETRY_INITIAL_DELAY_MS  1000
#define RETRY_MAX_DELAY_MS      8000
#define RETRY_BACKOFF_MULTIPLIER 2

static void eventd_safe_strncpy(char *dest, const char *src, size_t dest_size)
{
    if (!dest || dest_size == 0)
        return;

    if (!src) {
        dest[0] = '\0';
        return;
    }

    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static void eventd_sleep_ms(uint32_t ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static uint32_t eventd_retry_delay(uint32_t attempt)
{
    uint32_t delay = RETRY_INITIAL_DELAY_MS;
    uint32_t i;

    for (i = 0; i < attempt; i++) {
        delay *= RETRY_BACKOFF_MULTIPLIER;
        if (delay > RETRY_MAX_DELAY_MS)
            return RETRY_MAX_DELAY_MS;
    }

    return delay;
}

static int eventd_send_event(event_msg_t *event)
{
    static uint8_t mqtt_buf[STATS_MQTT_BUF_SZ];
    uint32_t attempt;
    bool rc;
    int ret = -EIO;

    if (!event)
        return -EINVAL;

    if (!eventd_ubus_is_ready() && eventd_lib_init() != 0)
        return -ENODEV;

    if (sizeof(event_msg_t) > sizeof(mqtt_buf)) {
        LOG(ERR, "eventd: event message too large for MQTT buffer");
        return -ENOMEM;
    }

    memcpy(mqtt_buf, event, sizeof(event_msg_t));

    for (attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            uint32_t delay = eventd_retry_delay(attempt - 1);

            LOG(WARN, "eventd: retry %u/%u after %u ms (type=%d)",
                attempt + 1, MAX_RETRY_ATTEMPTS, delay, event->type);
            eventd_sleep_ms(delay);
        }

        rc = eventd_mqtt_publish(sizeof(event_msg_t), mqtt_buf);
        if (rc) {
            ret = 0;
            LOG(INFO, "eventd: sent event on attempt %u (type=%d)",
                attempt + 1, event->type);
            break;
        }

        LOG(WARN, "eventd: publish failed attempt %u/%u (type=%d)",
            attempt + 1, MAX_RETRY_ATTEMPTS, event->type);
    }

    if (ret != 0) {
        LOG(ERR, "eventd: publish failed after %u attempts (type=%d)",
            MAX_RETRY_ATTEMPTS, event->type);
    }

    return ret;
}

static int eventd_send_typed(event_type_t type,
                             alarm_subtype_t alarm,
                             alert_subtype_t alert,
                             const char *data)
{
    event_msg_t info;

    memset(&info, 0, sizeof(info));
    info.type = type;

    if (type == EVENT_TYPE_ALARM)
        info.alarm_t = alarm;
    else if (type == EVENT_TYPE_ALERT)
        info.alert_t = alert;

    eventd_safe_strncpy(info.data, data, sizeof(info.data));

    return eventd_send_event(&info);
}

// static int eventd_send_event_noretry(event_msg_t *event)
// {
//     static uint8_t mqtt_buf[STATS_MQTT_BUF_SZ];
//     bool rc;

//     if (!event)
//         return -EINVAL;

//     if (!eventd_ubus_is_ready() && eventd_lib_init() != 0)
//         return -ENODEV;

//     if (sizeof(event_msg_t) > sizeof(mqtt_buf)) {
//         LOG(ERR, "eventd: event too large");
//         return -ENOMEM;
//     }

//     memcpy(mqtt_buf, event, sizeof(event_msg_t));

//     /*
//      * Best effort only.
//      * No retries during shutdown/reboot.
//      */
//     rc = eventd_mqtt_publish(sizeof(event_msg_t), mqtt_buf);

//     if (!rc) {
//         LOG(WARN, "eventd: shutdown publish failed (type=%d)",
//             event->type);
//         return -EIO;
//     }

//     LOG(INFO, "eventd: shutdown event sent (type=%d)",
//         event->type);

//     return 0;
// }

// static int eventd_send_typed_noretry(event_type_t type,
//     alarm_subtype_t alarm,
//     alert_subtype_t alert,
//     const char *data)
// {
// event_msg_t info;

// memset(&info, 0, sizeof(info));

// info.type = type;

// if (type == EVENT_TYPE_ALARM)
// info.alarm_t = alarm;
// else if (type == EVENT_TYPE_ALERT)
// info.alert_t = alert;

// eventd_safe_strncpy(info.data, data, sizeof(info.data));

// return eventd_send_event_noretry(&info);
// }

int send_alarm(alarm_subtype_t alarm, const char *data)
{
    if (alarm < ALARM_TYPE_CRITICAL || alarm > ALARM_TYPE_WARNING) {
        LOG(ERR, "eventd: invalid alarm type %d", alarm);
        return -EINVAL;
    }

    return eventd_send_typed(EVENT_TYPE_ALARM, alarm, 0, data);
}

int send_alert(alert_subtype_t alert, const char *data)
{
    if (alert < ALERT_TYPE_INTERFACE || alert > ALERT_TYPE_SYSTEM) {
        LOG(ERR, "eventd: invalid alert type %d", alert);
        return -EINVAL;
    }

    return eventd_send_typed(EVENT_TYPE_ALERT, 0, alert, data);
}
