#ifndef LOGD_UBUS_H_INCLUDED
#define LOGD_UBUS_H_INCLUDED

#include "logd.h"

bool logd_ubus_init(struct ev_loop *loop);
void logd_ubus_cleanup(void);

#endif /* LOGD_UBUS_H_INCLUDED */
