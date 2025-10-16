#ifndef IOCTL80211_DEVICE_H_INCLUDED
#define IOCTL80211_DEVICE_H_INCLUDED

#include "dpp_device.h"

#include "ioctl80211_api.h"

ioctl_status_t ioctl80211_device_temp_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_temp_t          *temp);

ioctl_status_t ioctl80211_device_txchainmask_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask);

#endif /* IOCTL80211_DEVICE_H_INCLUDED */
