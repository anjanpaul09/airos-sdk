#ifndef NETEVD_INFO_EVENTS_H
#define NETEVD_INFO_EVENTS_H

#include <ev.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include "info_events.h"

static inline uint64_t get_timestamp_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }

    return (uint64_t)ts.tv_sec * 1000ULL +
           (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Send client info event */
bool netev_send_client_info_event(client_info_event_t *client_info, uint64_t timestamp_ms);

/* Send VIF info event */
bool netev_send_vif_info_event(vif_info_event_t *vif_info, uint64_t timestamp_ms);

/* Send device info event */
bool netev_send_device_info_event(device_info_event_t *device_info, uint64_t timestamp_ms);

#endif // NETEVD_INFO_EVENTS_H

