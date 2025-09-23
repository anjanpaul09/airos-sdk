#ifndef IOCTL80211_CAPACITY_H_INCLUDED
#define IOCTL80211_CAPACITY_H_INCLUDED

#include "dpp_capacity.h"

#include "ioctl80211_api.h"

typedef struct
{
    uint64_t                        chan_active;
    uint64_t                        chan_tx;
    uint64_t                        bytes_tx;
    uint64_t                        samples;
    uint64_t                        queue[RADIO_QUEUE_MAX_QTY];
} ioctl80211_capacity_data_t;

ioctl_status_t ioctl80211_capacity_results_get(
        radio_entry_t              *radio_cfg,
        ioctl80211_capacity_data_t *capacity_result);

ioctl_status_t ioctl80211_capacity_enable(
        radio_entry_t              *radio_cfg,
        bool                        enabled);

#endif /* IOCTL80211_CAPACITY_H_INCLUDED */
