#ifndef NL80211_SCAN_H_INCLUDED
#define NL80211_SCAN_H_INCLUDED

#if 0
#include "ds_tree.h"
#include <net/if.h>
//#include "dpp_neighbor.h"

typedef bool target_scan_cb_t(
        void *scan_ctx,
        int   status);

struct nl80211_scan {
    char name[IFNAMSIZ];
    target_scan_cb_t *scan_cb;
    void *scan_ctx;
    ds_tree_node_t if_node;
    ev_async async;
};

bool nl80211_stats_scan_start(
        radio_entry_t *radio_cfg,
        uint32_t *chan_list,
        uint32_t chan_num,
        radio_scan_type_t scan_type,
        int32_t dwell_time,
        target_scan_cb_t *scan_cb,
        void *scan_ctx
);

bool nl80211_stats_scan_stop(
        radio_entry_t *radio_cfg,
        radio_scan_type_t scan_type
);

bool nl80211_stats_scan_get(
        radio_entry_t *radio_cfg,
        uint32_t *chan_list,
        uint32_t chan_num,
        radio_scan_type_t scan_type,
        dpp_neighbor_report_data_t *scan_results
);

void nl80211_scan_finish(char *name, bool state);
#endif
#endif /* NL80211_SCAN_H_INCLUDED */
