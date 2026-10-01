#ifndef STAMONITORD_NL80211_H
#define STAMONITORD_NL80211_H

#include <ev.h>

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

#endif
