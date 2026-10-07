#ifndef STAMONITORD_HISTORY_H
#define STAMONITORD_HISTORY_H

#include <ev.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STAMONITORD_HISTORY_DEFAULT_OUTPUT "/tmp/ap-history.json"

/*
 * Start STAMONITORD history capture.
 *
 * This does NOT call ev_run().
 * It only registers watchers on the provided libev loop.
 *
 * Returns:
 *   0  success
 *  -1  failure
 */
int stamonitord_history_start(struct ev_loop *loop);

/*
 * Stop STAMONITORD history capture and free resources.
 * Safe to call even if not started.
 */
void stamonitord_history_stop(void);

/*
 * Optional manual JSON flush.
 */
void stamonitord_history_flush(void);

/*
 * Optional manual interface resync.
 */
void stamonitord_history_resync(void);
void stamonitord_history_notify_station_connect(const uint8_t *mac, const char *ifname);
void stamonitord_history_notify_station_disconnect(const uint8_t *mac, const char *ifname);
bool stamonitord_history_lookup_station_ip(const uint8_t *mac, char *ipaddr, size_t ipaddr_len);
bool stamonitord_history_lookup_client_identity(const uint8_t *mac,
                                                char *ipaddr,
                                                size_t ipaddr_len,
                                                char *hostname,
                                                size_t hostname_len,
                                                char *dhcp_options,
                                                size_t dhcp_options_len,
                                                char *dhcp_vendor,
                                                size_t dhcp_vendor_len);
bool stamonitord_history_is_station_associated(const uint8_t *mac);

/*
 * Visit every station stored in the history table.
 */
void stamonitord_history_foreach_station(void (*cb)(const uint8_t mac[6], void *ctx),
                                         void *ctx);
bool stamonitord_history_fill_identity_from_leases_and_arp(const uint8_t *mac,
                                                           char *ipaddr,
                                                           size_t ipaddr_len,
                                                           char *hostname,
                                                           size_t hostname_len);
#ifdef __cplusplus
}
#endif

#endif
