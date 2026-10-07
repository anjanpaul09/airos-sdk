#ifndef STAMONITORD_NL80211_H
#define STAMONITORD_NL80211_H

#include <ev.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * Initialize nl80211 generic netlink listener for station events.
 * This will:
 *  - Resolve nl80211 family ID
 *  - Subscribe to "mlme" and "config" multicast groups
 *  - Set up libev I/O watcher on the netlink socket
 *  - Track station connects, disconnects, roams
 *
 * Returns:
 *   0 on success
 *  -1 on failure
 */
int stamonitord_nl80211_start(struct ev_loop *loop);

/**
 * Stop nl80211 listener and cleanup resources.
 */
void stamonitord_nl80211_stop(void);

/**
 * Check if a station is currently connected.
 */
bool stamonitord_nl80211_is_sta_connected(const uint8_t *mac);

/**
 * Copy link details for a connected station.
 * Returns false when the station is not in the live table.
 */
bool stamonitord_nl80211_get_sta(const uint8_t *mac,
                                 char *ifname,
                                 size_t ifname_len,
                                 int *link_id,
                                 time_t *connect_time);

/**
 * Visit every station currently in the live table.
 */
void stamonitord_nl80211_foreach_sta(void (*cb)(const uint8_t mac[6], void *ctx),
                                     void *ctx);

#endif
