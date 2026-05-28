#ifndef STAMONITORD_UBUS_TX_H
#define STAMONITORD_UBUS_TX_H

#include <stdbool.h>
#include <stddef.h>
#include "stamonitord.h"

/* Publish info event to cgwd */
void stamonitord_publish_info_event(void *buf, size_t size);

/* Initialize ubus TX service */
bool stamonitord_ubus_tx_service_init(void);

/* Cleanup ubus TX service */
void stamonitord_ubus_tx_service_cleanup(void);

#endif // STAMONITORD_UBUS_TX_H

