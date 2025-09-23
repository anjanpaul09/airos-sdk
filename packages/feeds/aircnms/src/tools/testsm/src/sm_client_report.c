#include "dpp_client.h"
#include "sm.h"
#include "nl80211_client.h"

#define SM_CLIENT_REPORT_INTERVAL 2

#define REQUEST_PARAM_UPDATE(TYPE, VAR, FMT) \
    if (request_ctx->VAR != request->VAR) \
    { \
        LOG(DEBUG, \
            "Updated %s %s "#VAR" "FMT" -> "FMT"", \
            radio_get_name_from_cfg(radio_cfg), \
            TYPE, \
            request_ctx->VAR, \
            request->VAR); \
        request_ctx->VAR = request->VAR; \
    }


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

typedef struct
{
    dpp_client_record_t             entry;
    ds_dlist_t                      result_list;
    target_client_record_t          cache;
    ds_dlist_node_t                 node;
} sm_client_record_t;

static struct ev_timer  genmsg_timer;

static ds_tree_t sm_radio_list = DS_TREE_INIT((ds_key_cmp_t*)strcmp,sm_radio_state_t, node);
static ds_dlist_t g_client_ctx_list = DS_DLIST_INIT(sm_client_ctx_t, node);

static inline sm_client_ctx_t * sm_client_ctx_alloc()
{
    sm_client_ctx_t *client_ctx = NULL;

    client_ctx = MALLOC(sizeof(sm_client_ctx_t));
    memset(client_ctx, 0, sizeof(sm_client_ctx_t));

    return client_ctx;
}

static bool sm_client_timer_set(ev_timer *timer, bool enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    }
    else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}


static sm_client_ctx_t *sm_client_ctx_get(radio_entry_t *radio_cfg)
{
    sm_client_ctx_t                *client_ctx = NULL;
    ds_dlist_iter_t                 ctx_iter;
    radio_entry_t                  *radio_entry = NULL;

    for (client_ctx = ds_dlist_ifirst(&ctx_iter,&g_client_ctx_list); client_ctx != NULL; client_ctx = ds_dlist_inext(&ctx_iter)) {
        radio_entry = client_ctx->radio_cfg;

        /* The stats entry has per band (type) and phy_name context */
        if (radio_cfg->type == radio_entry->type) {
            LOG(TRACE, "Fetched %s client reporting context", radio_get_name_from_cfg(radio_entry));
            return client_ctx;
        }
    }

    /* No client ctx found create new ... */
    client_ctx = NULL;
    client_ctx = sm_client_ctx_alloc();
    if(client_ctx) {
        client_ctx->radio_cfg = radio_cfg;
        ds_dlist_insert_tail(&g_client_ctx_list, client_ctx);
        LOG(TRACE, "Created %s client reporting context", radio_get_name_from_cfg(radio_cfg));
    }

    return client_ctx;
}
static bool dpp_client_stats_rx_records_clear(sm_client_ctx_t *client_ctx, ds_dlist_t *stats_rx_list)
{
    dpp_client_stats_rx_t          *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, stats_rx_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        ds_dlist_iremove(&record_iter);
        dpp_client_stats_rx_record_free(record);
        record = NULL;
    }

    return true;
}

static inline double weight_avg(double cnt, double dcnt, double val, double dval)
{
    if (cnt + dcnt == 0)
        return dval;
    else
        return ((cnt * val) + (dcnt * dval)) / (cnt + dcnt);
}


static bool dpp_client_stats_tx_records_clear(sm_client_ctx_t *client_ctx, ds_dlist_t *stats_tx_list)
{
    dpp_client_stats_tx_t          *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, stats_tx_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        ds_dlist_iremove(&record_iter);
        dpp_client_stats_tx_record_free(record);
        record = NULL;
    }

    return true;
}

static bool dpp_client_tid_records_clear(sm_client_ctx_t *client_ctx, ds_dlist_t *tid_record_list)
{
    dpp_client_tid_record_list_t   *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, tid_record_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        ds_dlist_iremove(&record_iter);
        dpp_client_tid_record_free(record);
        record = NULL;
    }

    return true;
}

static bool sm_client_record_clear(sm_client_ctx_t *client_ctx, ds_dlist_t *record_list)
{
    dpp_client_record_t            *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, record_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        dpp_client_stats_rx_records_clear(client_ctx, &record->stats_rx);
        dpp_client_stats_tx_records_clear(client_ctx, &record->stats_tx);
        dpp_client_tid_records_clear(client_ctx, &record->tid_record_list);
        ds_dlist_iremove(&record_iter);
        dpp_client_record_free(record);
        record = NULL;
    }

    return true;
}

static void sm_client_report_stats_calculate_average (sm_client_ctx_t *client_ctx,
                           dpp_client_stats_t *record, dpp_client_stats_t *report)
{

    report->rate_rx = weight_avg(report->frames_rx,
                                 record->frames_rx,
                                 report->rate_rx,
                                 record->rate_rx);
    report->rate_tx = weight_avg(report->frames_tx,
                                 record->frames_tx,
                                 report->rate_tx,
                                 record->rate_tx);

    report->bytes_tx    += record->bytes_tx;
    report->bytes_rx    += record->bytes_rx;
    report->frames_tx   += record->frames_tx;
    report->frames_rx   += record->frames_rx;
}


static void sm_client_report_calculate_average(sm_client_ctx_t *client_ctx, sm_client_record_t *record, dpp_client_record_t *report_entry)
{
    dpp_client_record_t            *record_entry = NULL;
    ds_dlist_iter_t                 record_iter;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;

    for (record_entry = ds_dlist_ifirst(&record_iter, &record->result_list); record_entry != NULL; record_entry = ds_dlist_inext(&record_iter)) {
        sm_client_report_stats_calculate_average(client_ctx, &record_entry->stats, &report_entry->stats);
    }

}

static void sm_client_report_stats(sm_client_ctx_t *client_ctx)
{
    bool                            status;
    ds_dlist_t                     *record_list = &client_ctx->record_list;
    sm_client_record_t             *record = NULL;
    ds_dlist_iter_t                 record_iter;
    dpp_client_record_t            *record_entry = NULL;

    dpp_client_report_data_t       *report_ctx = &client_ctx->report;
    ds_dlist_t                     *report_list = &report_ctx->list;
    dpp_client_record_t            *report_entry = NULL;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;
    sm_stats_request_t             *request_ctx = &client_ctx->request;

    uint64_t timestamp_ms = get_current_timestamp_ms();
	
	report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - client_ctx->report_ts +
        get_timestamp();

    report_ctx->radio_type = radio_cfg_ctx->type;
    report_ctx->channel = radio_cfg_ctx->chan;

    for (record = ds_dlist_ifirst(&record_iter, record_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        record_entry = &record->entry;

        report_entry = dpp_client_record_alloc();

        /* Copy client info */
        memcpy(&report_entry->info, &record_entry->info, sizeof(record_entry->info));

        /* Copy connectivity stats */
        report_entry->is_connected  = record_entry->is_connected;
        report_entry->connected     = record_entry->connected;
        report_entry->disconnected  = record_entry->disconnected;

        report_entry->duration_ms = report_ctx->timestamp_ms - record_entry->connect_ts;
        
        sm_client_report_calculate_average(client_ctx, record, report_entry);
        ds_dlist_insert_tail(report_list, report_entry);
    }

    /* Send records to MQTT FIFO (Skip empty reports) */
    if (!ds_dlist_is_empty(report_list)) {
        dpp_put_client(report_ctx);
    }

    status = sm_client_record_clear(client_ctx, report_list);

}

static bool sm_client_target_clear(sm_client_ctx_t *client_ctx, ds_dlist_t *client_list)
{
    target_client_record_t         *client = NULL;
    ds_dlist_iter_t                 client_iter;

    for (client = ds_dlist_ifirst(&client_iter, client_list); client != NULL; client = ds_dlist_inext(&client_iter)) {
        printf("removing client "MAC_ADDRESS_FORMAT " entry \n",
                MAC_ADDRESS_PRINT(client->info.mac));
        ds_dlist_iremove(&client_iter);
        target_client_record_free(client);
        client = NULL;
    }

    return true;
}

static bool sm_client_records_update_stats(sm_client_ctx_t *client_ctx, sm_client_record_t *record, target_client_record_t *client_entry)
{
    bool                            status;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;
    dpp_client_record_t            *record_entry = NULL;
    dpp_client_record_t            *result_entry = NULL;

    if (NULL == record) {
        return false;
    }

    record_entry = &record->entry;

    result_entry = dpp_client_record_alloc();
    if (NULL == result_entry) {
        LOG(ERR, "Updating %s interface client stats " "(Failed to allocate result memory)", radio_get_name_from_cfg(radio_cfg_ctx));
        return false;
    }

    status = target_stats_clients_convert(client_ctx->radio_cfg, client_entry, &record->cache, result_entry);
    if (true != status) {
        LOG(ERR, "Updating %s interface client stats " "(Failed to convert target data)", radio_get_name_from_cfg(radio_cfg_ctx));
        return false;
    }

    status = sm_rssi_stats_results_update(radio_cfg_ctx, record_entry->info.mac,
                         result_entry->stats.rssi, result_entry->stats.frames_rx,
                              result_entry->stats.frames_tx, RSSI_SOURCE_CLIENT);
    if (true != status) {
        LOG(ERR, "Updating %s interface client stats ""(Failed to update RSSI data)", radio_get_name_from_cfg(radio_cfg_ctx));
        return false;
    }

    ds_dlist_insert_tail(&record->result_list, result_entry);

    memcpy(&record->cache, client_entry, sizeof(record->cache));

    return true;
}

static sm_client_record_t *sm_client_records_mac_find(sm_client_ctx_t *client_ctx, target_client_record_t *client_entry)
{
    ds_dlist_t                     *record_list = &client_ctx->record_list;
    sm_client_record_t             *record = NULL;
    dpp_client_record_t            *record_entry = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, record_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        record_entry = &record->entry;

        if (!memcmp(record_entry->info.mac, client_entry->info.mac, sizeof(record_entry->info.mac)) && (record_entry->info.type == client_entry->info.type)) {
            return record;
        }
    }

    return NULL;
}

static inline sm_client_record_t *sm_client_record_alloc()
{
    sm_client_record_t *record = NULL;

    record = MALLOC(sizeof(sm_client_record_t));
    memset(record, 0, sizeof(sm_client_record_t));

    return record;
}

static bool sm_client_records_update(sm_client_ctx_t *client_ctx, ds_dlist_t *client_list, bool init)
{
    bool                            status;
    sm_stats_request_t             *request_ctx = &client_ctx->request;
    ds_dlist_t                     *record_list = &client_ctx->record_list;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;
    sm_client_record_t             *record = NULL;
    dpp_client_record_t            *record_entry = NULL;
    target_client_record_t         *client_entry = NULL;
    ds_dlist_iter_t                 client_iter;

    for (client_entry = ds_dlist_ifirst(&client_iter, client_list); client_entry != NULL; client_entry = ds_dlist_inext(&client_iter)) {
		record = sm_client_records_mac_find(client_ctx, client_entry);
        if (NULL != record) {
            record_entry = &record->entry;

            record_entry->info = client_entry->info;
            printf("Updating %s client "MAC_ADDRESS_FORMAT " entry \n",
                radio_get_name_from_cfg(radio_cfg_ctx),
                MAC_ADDRESS_PRINT(record_entry->info.mac));

            if(!record_entry->is_connected) {
                record_entry->is_connected = true;
                record_entry->connected++;
                record_entry->connect_ts = request_ctx->reporting_timestamp - client_ctx->report_ts + get_timestamp();

                LOG(DEBUG, "Marked %s client "MAC_ADDRESS_FORMAT " reconnected (cc=%d dc=%d dur=%"PRIu64"ms)",
                    radio_get_name_from_cfg(radio_cfg_ctx), MAC_ADDRESS_PRINT(record_entry->info.mac),
                    record_entry->connected, record_entry->disconnected, record_entry->duration_ms);
                goto update_cache;
            }

            LOG(TRACE, "Updating %s client "MAC_ADDRESS_FORMAT " entry",
                radio_get_name_from_cfg(radio_cfg_ctx),
                MAC_ADDRESS_PRINT(record_entry->info.mac));
        } else {
            record = sm_client_record_alloc();
            if (NULL == record) {
                LOG(ERR, "Updating %s interface client stats " "(Failed to allocate record memory)", radio_get_name_from_cfg(radio_cfg_ctx));
                return false;
            }
            record_entry = &record->entry;

            /* Initialize sampling/result list and add the first entry */
            ds_dlist_init(&record->result_list, dpp_client_record_t, node);

            /* Copy general client info. */
            memcpy(&record_entry->info, &client_entry->info, sizeof(record_entry->info));

            /* Init connectivity stats */
            record_entry->is_connected = true;
            record_entry->connected++;
            record_entry->connect_ts = request_ctx->reporting_timestamp - client_ctx->report_ts + get_timestamp();
            //Ankit
            //record_entry->duration_ms = 0;

            LOG(DEBUG,
                "Marked %s client "MAC_ADDRESS_FORMAT
                " connected (cc=%d dc=%d dur=%"PRIu64"ms)",
                radio_get_name_from_cfg(radio_cfg_ctx),
                MAC_ADDRESS_PRINT(record_entry->info.mac),
                record_entry->connected,
                record_entry->disconnected,
                record_entry->duration_ms);

            /* Insert new entry */
            ds_dlist_insert_tail(record_list, record);
        }
update_cache:
        /* Update old data with current because timer restarted (report/sampling) => delta = 0 */
        if (init) {
            memcpy(&record->cache, client_entry, sizeof(record->cache));
        }

        status = sm_client_records_update_stats(client_ctx, record, client_entry);
        if (true != status) {
            LOG(ERR, "Updating %s interface client stats ""(Failed to allocate record memory)", radio_get_name_from_cfg(radio_cfg_ctx));
            return false;
        }
    }

    client_ctx->record_qty++;

    return true;
}

static bool sm_client_update_list_cb(ds_dlist_t *client_list, void *ctx, int client_status)
{
    bool                            status;
    sm_client_ctx_t                *client_ctx = (sm_client_ctx_t *)ctx;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;

    if (true != client_status) {
        LOG(ERR, "Processing %s client report " "(failed to get stats)", radio_get_name_from_cfg(radio_cfg_ctx));
        goto clear;
    }

    //status = sm_client_records_update(client_ctx, client_list, false);
    if (true != status) {
        LOG(ERR, "Processing %s client report " "(failed to update client list)", radio_get_name_from_cfg(radio_cfg_ctx));
        goto clear;
    }

clear:
    status = sm_client_target_clear(client_ctx, client_list);
    if (true != status) {
        LOG(ERR, "Processing %s client report " "(failed to clear client list)", radio_get_name_from_cfg(radio_cfg_ctx));
        return false;
    }

    return true;
}

static void sm_client_update(EV_P_ ev_timer *w, int revents)
{
    bool                            status;
    sm_client_ctx_t                *client_ctx = (sm_client_ctx_t *) w->data;
    radio_entry_t                  *radio_cfg_ctx = client_ctx->radio_cfg;
    ds_dlist_t                     *client_list = &client_ctx->client_list;

    dpp_client_record_t            *record_entry = NULL;

    ds_dlist_t                     *record_list = &client_ctx->record_list;
    sm_client_record_t             *record = NULL;
    ds_dlist_iter_t                 record_iter;

    printf("Anjan: !!!! UPDATE !!!!!\n");
    /* Check if radio is exists */
    if (target_is_radio_interface_ready(radio_cfg_ctx->phy_name) != true) {
	printf("Error: Radio %s not configured\n", radio_cfg_ctx->phy_name);
	return;
    }

    /* Check if vif interface is exists */
    if (target_is_interface_ready(radio_cfg_ctx->if_name) != true) {
	printf("Error: Interface %s not configured\n", radio_cfg_ctx->if_name);
	return;
    }

    status = target_stats_clients_get(radio_cfg_ctx, NULL, sm_client_update_list_cb, client_list, client_ctx);

    return;
}

static void sm_client_report(EV_P_ ev_timer *w, int revents)
{
    printf("Anjan: !!!! REPORT !!!!\n");
    sm_client_report_stats(w->data);
}

bool sm_client_report_request(radio_entry_t *radio_cfg, sm_stats_request_t *request)
{
    bool                            status;

    sm_client_ctx_t                *client_ctx = NULL;
    sm_stats_request_t             *request_ctx = NULL;
    dpp_client_report_data_t       *report_ctx = NULL;
    ev_timer                       *update_timer = NULL;
    ev_timer                       *report_timer = NULL;

    if (NULL == request) {
        LOG(ERR, "Initializing client reporting " "(Invalid request config)");
        return false;
    }

    client_ctx      = sm_client_ctx_get(radio_cfg);
    request_ctx     = &client_ctx->request;
    report_ctx      = &client_ctx->report;
    update_timer    = &client_ctx->update_timer;
    report_timer    = &client_ctx->report_timer;

	client_ctx->report_ts = get_timestamp();
	
    memset(request_ctx, 0, sizeof(*request_ctx));
    memset(report_ctx, 0, sizeof(*report_ctx));

    ds_dlist_init(&report_ctx->list, dpp_client_record_t, node);
    ds_dlist_init(&client_ctx->record_list, sm_client_record_t, node);

    ev_init (update_timer, sm_client_update);
    update_timer->data = client_ctx;
    ev_timer_set(update_timer, 0.0, 2.0);
    ev_timer_start(EV_DEFAULT, update_timer);

    //ev_init (report_timer, sm_client_report);
    //report_timer->data = client_ctx;
    //ev_timer_set(report_timer, 0.0, 5.0);
    //ev_timer_start(EV_DEFAULT, report_timer);

    REQUEST_PARAM_UPDATE("client", reporting_interval, "%d");
	REQUEST_PARAM_UPDATE("client", reporting_timestamp, "%"PRIu64"");

}

static bool sm_update_stats_config(sm_stats_config_t *stats_cfg)
{
    sm_stats_request_t              req;
    sm_radio_state_t               *radio = NULL;

	struct timespec                 ts;
    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;


    ds_tree_foreach(&sm_radio_list, radio) {
        if (radio->config.type == stats_cfg->radio_type) {
            break;
        }
    }
    /* Stats request */
    memset(&req, 0, sizeof(req));
    req.radio_type = stats_cfg->radio_type;
    req.report_type = stats_cfg->report_type;
    req.scan_type  = stats_cfg->scan_type;

    req.reporting_interval = SM_CLIENT_REPORT_INTERVAL;
    req.reporting_count = 0;
    req.sampling_interval = SM_CLIENT_REPORT_INTERVAL-1;
    req.scan_interval = 100;
   
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    sm_client_report_request(&radio->config, &req);

}

void testqm_init_dpp_client_stats()
{
    sm_radio_state_t               *radio = NULL;
    sm_stats_config_t              *stats;

    /* 1st radio which is 2.4G */
    radio = CALLOC(1, sizeof(sm_radio_state_t));
    radio->config.type = RADIO_TYPE_2G;

    strcpy(radio->config.if_name, "phy0-ap0");
    strcpy(radio->config.phy_name, "phy0");
    radio->config.chan = 1;
    radio->config.tx_power = 30;
    radio->config.chan_mode = RADIO_CHAN_MODE_MANUAL;
    radio->config.chanwidth = RADIO_CHAN_WIDTH_20MHZ;
    radio->config.protocol = RADIO_802_11_AX;
    radio->config.admin_status = RADIO_STATUS_ENABLED;

    ds_tree_insert(&sm_radio_list, radio, "radio2g");
    stats = CALLOC(1, sizeof(sm_stats_config_t));
    stats->radio_type = RADIO_TYPE_2G;
    stats->report_type = REPORT_TYPE_AVERAGE;
    sm_update_stats_config(stats);

    radio = CALLOC(1, sizeof(sm_radio_state_t));
    radio->config.type = RADIO_TYPE_5G;
    strcpy(radio->config.if_name, "phy1-ap0");
    strcpy(radio->config.phy_name, "phy1");

    radio->config.chan = 36;
    radio->config.tx_power = 30;
    radio->config.chan_mode = RADIO_CHAN_MODE_MANUAL;
    radio->config.chanwidth = RADIO_CHAN_WIDTH_80MHZ;
    radio->config.protocol = RADIO_802_11_AX;
    radio->config.admin_status = RADIO_STATUS_ENABLED;

    ds_tree_insert(&sm_radio_list, radio, "radio5g");
    stats = CALLOC(1, sizeof(sm_stats_config_t));
    stats->radio_type = RADIO_TYPE_5G;
    stats->report_type = REPORT_TYPE_AVERAGE;
    sm_update_stats_config(stats);

}

