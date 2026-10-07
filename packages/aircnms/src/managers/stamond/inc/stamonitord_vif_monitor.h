#ifndef STAMONITORD_VIF_MONITOR_H
#define STAMONITORD_VIF_MONITOR_H

#include <stdbool.h>
#include <stdint.h>
#include <ev.h>

/**
 * Start the VIF monitor service.
 * Registers UBUS event handlers, starts libev watchers, and initializes the debounce engine.
 *
 * @param loop libev event loop
 * @return true on success, false on failure
 */
bool stamonitord_vif_monitor_start(struct ev_loop *loop);

/**
 * Stop the VIF monitor service and cleanup resources.
 */
void stamonitord_vif_monitor_stop(void);

/**
 * Trigger a VIF change evaluation with a descriptive reason.
 * Thread-safe: can be called from any thread or event callback.
 * Coalesces rapid triggers with a settle window before querying and dispatching.
 *
 * @param reason Human-readable string for logging (e.g. "nl80211: CSA", "ubus: wireless")
 */
void stamonitord_vif_monitor_trigger(const char *reason);

/**
 * Force an immediate VIF evaluation and dispatch without debouncing.
 *
 * @param reason Human-readable string for logging
 */
void stamonitord_vif_monitor_resync_now(const char *reason);

/**
 * Record a dynamic channel update for an interface (e.g. from nl80211 CSA notification).
 *
 * @param ifname Interface name (e.g. "phy0-ap0", "phy1-ap0")
 * @param channel 802.11 channel number
 */
void stamonitord_vif_monitor_update_channel(const char *ifname, uint8_t channel);

/**
 * Get the latest known channel for an interface from dynamic runtime tracking.
 *
 * @param ifname Interface name
 * @return Channel number if tracked, or 0 if unknown
 */
uint8_t stamonitord_vif_monitor_get_channel(const char *ifname);

/**
 * Helper to convert frequency (MHz) to 802.11 channel number.
 *
 * @param freq Frequency in MHz
 * @return Channel number (1-14 for 2.4G, 36-177 for 5G, 1-233 for 6G), or 0 on error
 */
uint8_t stamonitord_freq_to_channel(uint32_t freq);

#endif /* STAMONITORD_VIF_MONITOR_H */
