#ifndef NETEVD_INFO_EVENTS_H
#define NETEVD_INFO_EVENTS_H

#include <stdint.h>
#include <stdbool.h>
#include "info_events.h"

/* Send client info event */
bool netev_send_client_info_event(client_info_event_t *client_info, uint64_t timestamp_ms);

/* Send VIF info event */
bool netev_send_vif_info_event(vif_info_event_t *vif_info, uint64_t timestamp_ms);

/* Send device info event */
bool netev_send_device_info_event(device_info_event_t *device_info, uint64_t timestamp_ms);

#endif // NETEVD_INFO_EVENTS_H

