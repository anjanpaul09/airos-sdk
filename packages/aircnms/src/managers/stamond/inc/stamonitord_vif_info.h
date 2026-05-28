#ifndef STAMONITORD_VIF_INFO_H
#define STAMONITORD_VIF_INFO_H

#include <stdbool.h>
#include "info_events.h"
#include "stats_report.h"
#include "ds_tree.h"

extern pthread_mutex_t
    g_vif_info_mutex;
/*****************************************************************************/
/* GLOBAL CACHE TREES */
/*****************************************************************************/

struct radio_state {

    ds_tree_node_t node;

    char ifname[16];

    radio_info_t current;

    bool valid;
};

struct vif_state {

    ds_tree_node_t node;

    char ifname[16];

    vif_info_t current;

    bool valid;
};

struct ethernet_state {

    ds_tree_node_t node;

    char ifname[16];

    ethernet_info_t current;

    bool valid;
};


struct radio_state *radio_cache_lookup_by_ifname(const char *ifname);

struct vif_state *vif_cache_lookup_by_ifname(const char *ifname);

struct ethernet_state *eth_cache_lookup_by_ifname(const char *ifname);

bool radio_cache_lookup_by_band(const char *band, radio_info_t *radio_out);

/* Send VIF info event by calling target_info_vif_get */
bool stamonitord_send_vif_info(void);

#endif // STAMONITORD_VIF_INFO_H

