#ifndef STAMONITORD_HISTORY_H
#define STAMONITORD_HISTORY_H

#include <ev.h>
#include <stdint.h>

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
#ifdef __cplusplus
}
#endif

#endif
