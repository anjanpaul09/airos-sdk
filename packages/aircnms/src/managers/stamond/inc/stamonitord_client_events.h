#ifndef STAMONITORD_CLIENT_EVENTS_H
#define STAMONITORD_CLIENT_EVENTS_H

#include <stdint.h>
#include <stdbool.h>

/* Handle client connect event */
void stamonitord_handle_client_connect(const uint8_t *macaddr, const char *ifname);

/* Handle client disconnect event */
void stamonitord_handle_client_disconnect(const uint8_t *macaddr, const char *ifname);

#endif // STAMONITORD_CLIENT_EVENTS_H

