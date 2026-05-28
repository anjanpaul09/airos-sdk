#ifndef EVENTD_DAEMON_H
#define EVENTD_DAEMON_H

#include <ev.h>
#include "libeventd.h"

int ubus_alarm_init(struct ev_loop *loop);
void ubus_alarm_cleanup(struct ev_loop *loop);
void check_and_send_reboot_alarm(void);

#endif /* EVENTD_DAEMON_H */
