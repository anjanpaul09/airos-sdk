#ifndef STAMONITORD_CLIENT_EVENTS_H
#define STAMONITORD_CLIENT_EVENTS_H

#include <stdint.h>
#include <stdbool.h>

/* Handle client connect event */
void stamonitord_handle_client_connect(const uint8_t *macaddr, const char *ifname);

/* Handle client disconnect event */
void stamonitord_handle_client_disconnect(const uint8_t *macaddr, const char *ifname);

/* Notification when DHCP IP/identity is resolved for a station */
void stamonitord_client_events_on_dhcp_resolved(const uint8_t *macaddr);

/* Clean up pending connect timers on daemon exit */
void stamonitord_client_events_cleanup(void);

#endif // STAMONITORD_CLIENT_EVENTS_H

