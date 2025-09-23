
#include "nl80211_client.h"

typedef struct
{
    dpp_client_record_t             entry;
    ds_dlist_t                      result_list;
    target_client_record_t          cache;
    ds_dlist_node_t                 node;
} sm_client_record_t;


typedef struct
{
    bool                            initialized;

    /* Internal structure used to lower layer radio selection */
    radio_entry_t                  *radio_cfg;

    /* Internal structure to store report timers */
    ev_timer                        report_timer;
    ev_timer                        update_timer;
    ev_timer                        init_timer;

    /* Internal structure to store signals */
    ev_signal                       ev_sig;

    /* Structure containing cloud request timer params */
    sm_stats_request_t              request;
    /* Structure pointing to upper layer client storage */
    dpp_client_report_data_t        report;

    /* Structure containing cached client sampling records
       (sm_client_record_t) */
    ds_dlist_t                      record_list;
    uint32_t                        record_qty;

    /* target client temporary list for deriving records */
    ds_dlist_t                      client_list;

    /* Reporting start timestamp used for client duration calculation */
    uint64_t                        duration_ts;
    /* Reporting start timestamp used for reporting timestamp calculation */
    uint64_t                        report_ts;

#ifdef CONFIG_SM_UPLINK_STATS
    /* Uplink information */
    uplink_t                        uplink;
#endif /*  CONFIG_SM_UPLINK_STATS */

    ds_dlist_node_t                 node;
} sm_client_ctx_t;

static ds_dlist_t                   g_client_ctx_list =
                                        DS_DLIST_INIT(sm_client_ctx_t,
                                                      node);
