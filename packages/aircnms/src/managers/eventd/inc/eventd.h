#ifndef EVENTD_H
#define EVENTD_H
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

typedef enum {
    EVENT = 1,
    CONF = 2
} DmMsgType;

// Safe string copy that guarantees null termination
static inline void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) {
        return;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}


// UBUS service functions
bool eventd_ubus_tx_service_init(void);
void eventd_ubus_tx_service_cleanup(void);
int ubus_alarm_init(struct ev_loop *loop);
void ubus_alarm_cleanup(struct ev_loop *loop);
int eventd_send_event_to_cloud(event_msg_t *event);

// Monitor functions
//bool netev_monitor_init(void);

// UBUS method call function
struct blob_buf;
int call_eventd_method(const char *method, struct blob_buf *b);

#endif // NETEV_H

