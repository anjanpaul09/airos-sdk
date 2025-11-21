#ifndef NETEVD_UBUS_TX_H
#define NETEVD_UBUS_TX_H

#include <stdbool.h>
#include <stddef.h>

/* Publish info event to cgwd */
void netev_publish_info_event(void *buf, size_t size);

/* Initialize ubus TX service */
bool netev_ubus_tx_service_init(void);

/* Cleanup ubus TX service */
void netev_ubus_tx_service_cleanup(void);

#endif // NETEVD_UBUS_TX_H

