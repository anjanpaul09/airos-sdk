#ifndef IOCTL80211_SCAN_H_INCLUDED
#define IOCTL80211_SCAN_H_INCLUDED

#include "dpp_neighbor.h"

#include "ioctl80211_api.h"

typedef bool ioctl80211_scan_cb_t(
        void                       *scan_ctx,
        int                         status);

ioctl_status_t ioctl80211_scan_init();

ioctl_status_t ioctl80211_scan_channel(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        int32_t                     dwell_time,
        ioctl80211_scan_cb_t       *scan_cb,
        void                       *scan_ctx);

ioctl_status_t ioctl80211_scan_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_report_data_t *scan_results);

ioctl_status_t ioctl80211_scan_stop(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type);

#endif /* IOCTL80211_SCAN_H_INCLUDED */
