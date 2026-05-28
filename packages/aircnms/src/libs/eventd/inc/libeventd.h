#ifndef LIBEVENTD_H
#define LIBEVENTD_H

#include <stddef.h>
#include "device_config.h"

#define EVENTD_UBUS_SERVICE    "cgwd"
#define EVENTD_CMDEXEC_METHOD  "cmdexec.event"
#define EVENTD_UBUS_TIMEOUT_MS 3000

/* Initialize ubus connection (required before send_alarm/send_alert). */
int eventd_lib_init(void);

/* Release ubus connection. */
void eventd_lib_cleanup(void);

/*
 * Send an alarm event to the cloud via cgwd cmdexec.event ubus method.
 * @param alarm  Alarm severity (ALARM_TYPE_CRITICAL, MAJOR, WARNING)
 * @param data   Optional detail string (may be NULL)
 * @return 0 on success, negative errno-style code on failure
 */
int send_alarm(alarm_subtype_t alarm, const char *data);

/*
 * Send an alert event to the cloud via cgwd cmdexec.event ubus method.
 * @param alert  Alert category (ALERT_TYPE_INTERFACE, ALERT_TYPE_SYSTEM)
 * @param data   Optional detail string (may be NULL)
 * @return 0 on success, negative errno-style code on failure
 */
int send_alert(alert_subtype_t alert, const char *data);

#endif /* LIBEVENTD_H */
