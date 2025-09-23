#ifndef IOCTL80211_RADIO_H_INCLUDED
#define IOCTL80211_RADIO_H_INCLUDED

#include "ioctl80211_api.h"

int ioctl80211_radio_init();

ioctl_status_t ioctl80211_radio_tx_stats_enable(
        radio_entry_t              *radio_cfg,
        bool                        status);

ioctl_status_t ioctl80211_radio_fast_scan_enable(
        radio_entry_t              *radio_cfg,
        ifname_t                    if_name);

#endif /* IOCTL80211_RADIO_H_INCLUDED */
