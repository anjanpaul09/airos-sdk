#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <protobuf-c/protobuf-c.h>
#include <unistd.h>

//#include "target.h"
//#include "osp_unit.h"
#include "dppline.h"
#include "ds.h"
#include "ds_dlist.h"
#include "memutil.h"

#include "dpp_client.h"
#include "dpp_survey.h"
#include "dpp_neighbor.h"
#include "dpp_device.h"
#include "dpp_capacity.h"
//#include "dpp_vif_stats.h"

#ifndef TARGET_NATIVE
#include "os_types.h"
#include "os_nif.h"
#endif

//#include "opensync_stats.pb-c.h"
#include "aircnms_stats.pb-c.h"

#define TARGET_ID_SZ 16
#define MODULE_ID LOG_MODULE_ID_DPP

/* Internal types   */

/* statistics type  */
typedef enum
{
	DPP_T_NEIGHBOR  = 1,
    DPP_T_CLIENT    = 2,
    DPP_T_RSSI      = 3,
    DPP_T_DEVICE    = 4,
	DPP_T_VIF		= 5
} DPP_STS_TYPE;

uint32_t queue_depth;
uint32_t queue_size;

typedef struct
{
    dpp_client_record_t             rec;
    dpp_client_stats_rx_t          *rx;
    int32_t                         rx_qty;
    dpp_client_stats_tx_t          *tx;
    int32_t                         tx_qty;
    dpp_client_tid_record_list_t   *tid;
    int32_t                         tid_qty;
} dppline_client_rec_t;

typedef struct
{
    radio_type_t                    radio_type;
    uint32_t                        channel;
    dppline_client_rec_t           *list;
    uint32_t                        qty;
    uint64_t                        timestamp_ms;
    char                            *uplink_type;
    bool                            uplink_changed;
} dppline_client_stats_t;

typedef struct dpp_device_stats
{
    dpp_device_record_t             record;
    uint64_t                        timestamp_ms;
} dppline_device_stats_t;

typedef struct
{
    radio_type_t                    radio_type;
    report_type_t                   report_type;
    radio_scan_type_t               scan_type;
    dpp_neighbor_record_t          *list;
    uint32_t                        qty;
    uint64_t                        timestamp_ms;
} dppline_neighbor_stats_t;


typedef struct 
{
    dpp_vif_record_t                record;
    uint64_t                        timestamp_ms;
} dppline_vif_stats_t;



/* DPP stats type, used as element in internal double ds */
typedef struct dpp_stats
{
    int                             type;
    int                             size;
    ds_dlist_node_t                 dnode;
    union {
        dppline_neighbor_stats_t    neighbor;
        dppline_client_stats_t      client;
	dppline_device_stats_t      device;
        dppline_vif_stats_t         vif;
    } u;
} dppline_stats_t;

/* Internal variables */
ds_dlist_t  g_dppline_list; /* double linked list used to hold stats queue */

/* private functions    */
static dppline_stats_t * dpp_alloc_stat()
{
    return CALLOC(1, sizeof(dppline_stats_t));
}

/* free allocated memory for single stat */
static void dppline_free_stat(dppline_stats_t * s)
{
    uint32_t i;
    if (NULL != s) {
        switch (s->type) {
            case DPP_T_NEIGHBOR:
                FREE(s->u.neighbor.list);
                break;
            case DPP_T_CLIENT:
                for (i=0; i<s->u.client.qty; i++) {
                    FREE(s->u.client.list[i].rx);
                    FREE(s->u.client.list[i].tx);
                    FREE(s->u.client.list[i].tid);
                }
                FREE(s->u.client.list);
                break;
            case DPP_T_DEVICE:
                break;
            default:;
        }
        FREE(s);
    }
}

/* copy stats to internal buffer */
static bool dppline_copysts(dppline_stats_t * dst, void * sts)
{
    int size = 0;
    switch(dst->type)
    {
		case DPP_T_NEIGHBOR:
            {
                dpp_neighbor_report_data_t *report_data = sts;
                dpp_neighbor_record_list_t *result = NULL;
                dpp_neighbor_record_t      *result_entry = NULL;
                ds_dlist_iter_t             result_iter;

                /* Loop through linked list of results and copy them to dppline buffer */
                dst->u.neighbor.qty = 0;
                dst->u.neighbor.radio_type = report_data->radio_type;
                dst->u.neighbor.report_type = report_data->report_type;
                dst->u.neighbor.scan_type = report_data->scan_type;
                dst->u.neighbor.timestamp_ms = report_data->timestamp_ms;
                for (   result = ds_dlist_ifirst(&result_iter, &report_data->list);
                        result != NULL;
                        result = ds_dlist_inext(&result_iter))
                {
                    result_entry = &result->entry;

                    size = (dst->u.neighbor.qty + 1) * sizeof(dpp_neighbor_record_t);
                    if (!dst->u.neighbor.qty) {
                        dst->u.neighbor.list = CALLOC(1, size);
                    }
                    else {
                        dst->u.neighbor.list = REALLOC(dst->u.neighbor.list, size);
                        memset(&dst->u.neighbor.list[dst->u.neighbor.qty],
                               0,
                               sizeof(dpp_neighbor_record_t));
                    }
                    memcpy(&dst->u.neighbor.list[dst->u.neighbor.qty++],
                            result_entry,
                            sizeof(dpp_neighbor_record_t));
                }
            }
            break;
        case DPP_T_CLIENT:
            {
                dpp_client_report_data_t       *report_data = sts;
                dpp_client_record_t            *result_entry = NULL;
                ds_dlist_iter_t                 result_iter;

                dpp_client_stats_rx_t          *rx = NULL;
                ds_dlist_iter_t                 rx_iter;
                dpp_client_stats_tx_t          *tx = NULL;
                ds_dlist_iter_t                 tx_iter;
                dpp_client_tid_record_list_t   *tid = NULL;
                ds_dlist_iter_t                 tid_iter;

                /* Loop through linked list of results and copy them to dppline buffer */
                dst->u.client.qty = 0;
                dst->u.client.radio_type = report_data->radio_type;
                dst->u.client.channel = report_data->channel;
                dst->u.client.timestamp_ms = report_data->timestamp_ms;
                dst->u.client.uplink_type = strdup(report_data->uplink_type);
                dst->u.client.uplink_changed = report_data->uplink_changed;
                for (   result_entry = ds_dlist_ifirst(&result_iter, &report_data->list);
                        result_entry != NULL;
                        result_entry = ds_dlist_inext(&result_iter))
                {
                    size = (dst->u.client.qty + 1) * sizeof(dppline_client_rec_t);
                    if (!dst->u.client.qty) {
                        dst->u.client.list = CALLOC(1, size);
                    }
                    else {
                        dst->u.client.list = REALLOC(dst->u.client.list, size);
                        memset(&dst->u.client.list[dst->u.client.qty],
                               0,
                               sizeof(dppline_client_rec_t));
                    }
                    memcpy(&dst->u.client.list[dst->u.client.qty].rec,
                            result_entry,
                            sizeof(dpp_client_record_t));

                    /* Add RX stats records */
                    for (   rx = ds_dlist_ifirst(&rx_iter, &result_entry->stats_rx);
                            rx != NULL;
                            rx = ds_dlist_inext(&rx_iter))
                    {
                        size = (dst->u.client.list[dst->u.client.qty].rx_qty + 1) * sizeof(dpp_client_stats_rx_t);
                        if (!dst->u.client.list[dst->u.client.qty].rx_qty) {
                            dst->u.client.list[dst->u.client.qty].rx = CALLOC(1, size);
                        }
                        else {
                            dst->u.client.list[dst->u.client.qty].rx =
                                REALLOC(dst->u.client.list[dst->u.client.qty].rx, size);
                            memset(&dst->u.client.list[dst->u.client.qty].rx[dst->u.client.list[dst->u.client.qty].rx_qty],
                                    0,
                                    sizeof(dpp_client_stats_rx_t));
                        }
                        memcpy(&dst->u.client.list[dst->u.client.qty].rx[dst->u.client.list[dst->u.client.qty].rx_qty],
                                rx,
                                sizeof(dpp_client_stats_rx_t));

                        dst->u.client.list[dst->u.client.qty].rx_qty++;
                    }

                    /* Add TX stats records */
                    for (   tx = ds_dlist_ifirst(&tx_iter, &result_entry->stats_tx);
                            tx != NULL;
                            tx = ds_dlist_inext(&tx_iter))
                    {
                        size = (dst->u.client.list[dst->u.client.qty].tx_qty + 1) * sizeof(dpp_client_stats_tx_t);
                        if (!dst->u.client.list[dst->u.client.qty].tx_qty) {
                            dst->u.client.list[dst->u.client.qty].tx = CALLOC(1, size);
                        }
                        else {
                            dst->u.client.list[dst->u.client.qty].tx =
                                REALLOC(dst->u.client.list[dst->u.client.qty].tx, size);
                            memset(&dst->u.client.list[dst->u.client.qty].tx[dst->u.client.list[dst->u.client.qty].tx_qty],
                                    0,
                                    sizeof(dpp_client_stats_tx_t));
                        }
                        memcpy(&dst->u.client.list[dst->u.client.qty].tx[dst->u.client.list[dst->u.client.qty].tx_qty],
                                tx,
                                sizeof(dpp_client_stats_tx_t));

                        dst->u.client.list[dst->u.client.qty].tx_qty++;
                    }

                    /* Add TID records */
                    for (   tid = ds_dlist_ifirst(&tid_iter, &result_entry->tid_record_list);
                            tid != NULL;
                            tid = ds_dlist_inext(&tid_iter))
                    {
                        size = (dst->u.client.list[dst->u.client.qty].tid_qty + 1) * sizeof(dpp_client_tid_record_list_t);
                        if (!dst->u.client.list[dst->u.client.qty].tid_qty) {
                            dst->u.client.list[dst->u.client.qty].tid = CALLOC(1, size);
                        }
                        else {
                            dst->u.client.list[dst->u.client.qty].tid =
                                REALLOC(dst->u.client.list[dst->u.client.qty].tid, size);
                            memset(&dst->u.client.list[dst->u.client.qty].tid[dst->u.client.list[dst->u.client.qty].tid_qty],
                                    0,
                                    sizeof(dpp_client_tid_record_list_t));
                        }
                        memcpy(&dst->u.client.list[dst->u.client.qty].tid[dst->u.client.list[dst->u.client.qty].tid_qty],
                                tid,
                                sizeof(dpp_client_tid_record_list_t));

                        dst->u.client.list[dst->u.client.qty].tid_qty++;
                    }
                    dst->u.client.qty++;
                }
            }
            break;
		case DPP_T_DEVICE: {
			    dpp_device_report_data_t        *report_data = sts;

				memcpy(&dst->u.device.record, &report_data->record, sizeof(dpp_device_record_t));
				dst->u.device.timestamp_ms = report_data->timestamp_ms;
			} break;
		
		case DPP_T_VIF: {
			    dpp_vif_report_data_t        *report_data = sts;

				memcpy(&dst->u.vif.record, &report_data->record, sizeof(dpp_vif_record_t));
				dst->u.vif.timestamp_ms = report_data->timestamp_ms;
			} break;
        default:
            LOG(ERR, "Failed to copy %d stats", dst->type);
            /* do nothing */
            return false;
    }
    dst->size = size;
    return true;
}

static char * getNodeid()
{
    char * buff = NULL;

    buff = MALLOC(TARGET_ID_SZ);

    if (!osp_unit_id_get(buff, TARGET_ID_SZ))
    {
        LOG(ERR, "Error acquiring node id.");
        FREE(buff);
        return NULL;
    }

    return buff;
}


Sts__RadioBandType dppline_to_proto_radio(radio_type_t radio_type)
{
    switch (radio_type)
    {
        case RADIO_TYPE_2G:
            return STS__RADIO_BAND_TYPE__BAND2G;

        case RADIO_TYPE_5G:
            return STS__RADIO_BAND_TYPE__BAND5G;

        case RADIO_TYPE_5GL:
            return STS__RADIO_BAND_TYPE__BAND5GL;

        case RADIO_TYPE_5GU:
            return STS__RADIO_BAND_TYPE__BAND5GU;

        case RADIO_TYPE_6G:
            return STS__RADIO_BAND_TYPE__BAND6G;

        default:
            assert(0);
    }
    return 0;
}

Sts__SurveyType dppline_to_proto_survey_type(radio_scan_type_t scan_type)
{
    switch (scan_type)
    {
        case RADIO_SCAN_TYPE_ONCHAN:
            return STS__SURVEY_TYPE__ON_CHANNEL;

        case RADIO_SCAN_TYPE_OFFCHAN:
            return STS__SURVEY_TYPE__OFF_CHANNEL;

        case RADIO_SCAN_TYPE_FULL:
            return STS__SURVEY_TYPE__FULL;

        default:
            assert(0);
    }
    return 0;
}

Sts__ReportType dppline_to_proto_report_type(report_type_t report_type)
{
    switch (report_type)
    {
        case REPORT_TYPE_RAW:
            return STS__REPORT_TYPE__RAW;

        case REPORT_TYPE_AVERAGE:
            return STS__REPORT_TYPE__AVERAGE;

        case REPORT_TYPE_HISTOGRAM:
            return STS__REPORT_TYPE__HISTOGRAM;

        case REPORT_TYPE_PERCENTILE:
            return STS__REPORT_TYPE__PERCENTILE;

        case REPORT_TYPE_DIFF:
            return STS__REPORT_TYPE__DIFF;

        default:
            assert(0);
    }
    return 0;
}

void dpp_mac_to_str(uint8_t *mac, char *str)
{
    // slow
    //sprintf(str, MAC_ADDRESS_FORMAT, MAC_ADDRESS_PRINT(rec->mac));

    // optimized
    int i;
    uint8_t nib;
    for (i=0; i<6; i++)
    {
        nib = *mac >> 4;
        *str++ = nib < 10 ? '0' + nib : 'A' + nib - 10;
        nib = *mac & 0xF;
        *str++ = nib < 10 ? '0' + nib : 'A' + nib - 10;
        if (i < 5) *str++ = ':';
        mac++;
    }
    *str = 0;
}

char* dpp_mac_str_tmp(uint8_t *mac)
{
    static mac_address_str_t str;
    dpp_mac_to_str(mac, str);
    return str;
}

Sts__WmmAc dppline_to_proto_wmm_ac_type(radio_queue_type_t ac_type)
{
    switch (ac_type)
    {
        case RADIO_QUEUE_TYPE_VI:
            return STS__WMM_AC__WMM_AC_VI;
        case RADIO_QUEUE_TYPE_VO:
            return STS__WMM_AC__WMM_AC_VO;
        case RADIO_QUEUE_TYPE_BE:
            return STS__WMM_AC__WMM_AC_BE;
        case RADIO_QUEUE_TYPE_BK:
            return STS__WMM_AC__WMM_AC_BK;

        default:
            assert(0);
    }

    return -1;
}

Sts__NeighborType dppline_to_proto_neighbor_scan_type(radio_scan_type_t scan_type)
{
    switch (scan_type)
    {
        case RADIO_SCAN_TYPE_FULL:
            return STS__NEIGHBOR_TYPE__FULL_SCAN;

        case RADIO_SCAN_TYPE_ONCHAN:
            return STS__NEIGHBOR_TYPE__ONCHAN_SCAN;

        case RADIO_SCAN_TYPE_OFFCHAN:
            return STS__NEIGHBOR_TYPE__OFFCHAN_SCAN;

        default:
            assert(0);
    }
    return 0;
}


static void dppline_add_stat_neighbor(Sts__Report *r, dppline_stats_t *s)
{
    Sts__Neighbor *sr = NULL;
    uint32_t i;
    int size = 0;
    dppline_neighbor_stats_t *neighbor = &s->u.neighbor;

    // increase the number of neighbors
    r->n_neighbors++;

    // allocate or extend the size of neighbors
    r->neighbors = REALLOC(r->neighbors,
            r->n_neighbors * sizeof(Sts__Neighbor*));
    size += sizeof(Sts__Neighbor*);

    // allocate new buffer Sts__Neighbor
    sr = MALLOC(sizeof(Sts__Neighbor));
    size += sizeof(Sts__Neighbor);
    r->neighbors[r->n_neighbors - 1] = sr;

    sts__neighbor__init(sr);
    sr->band = dppline_to_proto_radio(neighbor->radio_type);
    sr->scan_type = dppline_to_proto_neighbor_scan_type(neighbor->scan_type);
    sr->report_type = dppline_to_proto_report_type(neighbor->report_type);
    sr->has_report_type = true;
    sr->timestamp_ms = neighbor->timestamp_ms;
    sr->has_timestamp_ms = true;
    sr->bss_list = MALLOC(neighbor->qty * sizeof(*sr->bss_list));
    size += neighbor->qty * sizeof(*sr->bss_list);
    sr->n_bss_list = neighbor->qty;
    for (i = 0; i < neighbor->qty; i++)
    {
        dpp_neighbor_record_t *rec = &neighbor->list[i];
        Sts__Neighbor__NeighborBss *dr; // dest rec
        dr = sr->bss_list[i] = MALLOC(sizeof(**sr->bss_list));
        size += sizeof(**sr->bss_list);
        sts__neighbor__neighbor_bss__init(dr);

        dr->bssid = strdup(rec->bssid);
        size += strlen(rec->bssid) + 1;
        dr->ssid = strdup(rec->ssid);
        size += strlen(rec->ssid) + 1;
        if (rec->sig) {
            dr->rssi = rec->sig;
            dr->has_rssi = true;
        }
        if (rec->tsf) {
            dr->tsf = rec->tsf;
            dr->has_tsf = true;
        }
        dr->chan_width = (Sts__ChanWidth)rec->chanwidth;
        dr->has_chan_width = true;
        dr->channel = rec->chan;

        if (REPORT_TYPE_DIFF == neighbor->report_type) {
            if (rec->lastseen) {
                dr->status = STS__DIFF_TYPE__ADDED;
            }
            else {
                dr->status = STS__DIFF_TYPE__REMOVED;
            }
            dr->has_status = true;
        }

    }
    LOGT("%s: ============= size raw: %zu alloc: %d proto struct: %d", __func__,
         sizeof(s->u.neighbor), s->size, size);
}


static void dppline_add_stat_client(Sts__Report *r, dppline_stats_t *s)
{
    Sts__ClientReport *sr = NULL;
    Sts__Client *dr; // dest rec
    uint32_t i = 0;
    int j, j1;
    int n = 0;
    int size = 0;
    dppline_client_stats_t *client = &s->u.client;

    // increase the number of clients
    r->n_clients++;

    // allocate or extend the size of clients
    r->clients = REALLOC(r->clients,
            r->n_clients * sizeof(Sts__ClientReport*));

    // allocate new buffer
    sr = MALLOC(sizeof(Sts__ClientReport));
    size += sizeof(Sts__ClientReport);
    r->clients[r->n_clients - 1] = sr;

    sts__client_report__init(sr);
    sr->band = dppline_to_proto_radio(client->radio_type);
    sr->timestamp_ms = client->timestamp_ms;
    sr->has_timestamp_ms = true;
    sr->channel = client->channel;
    if (client->uplink_changed) {
        sr->has_uplink_changed = true;
        sr->uplink_changed = client->uplink_changed;
    }
    sr->uplink_type = strdup(client->uplink_type);

    sr->client_list = MALLOC(client->qty * sizeof(*sr->client_list));
    size += client->qty * sizeof(*sr->client_list);
    sr->n_client_list = client->qty;
    for (i = 0; i < client->qty; i++)
    {
        dpp_client_record_t *rec = &client->list[i].rec;
        int network_id_len;
        dr = sr->client_list[i] = MALLOC(sizeof(**sr->client_list));
        size += sizeof(**sr->client_list);
        sts__client__init(dr);

        dr->mac_address = MALLOC(MACADDR_STR_LEN);
        dpp_mac_to_str(rec->info.mac, dr->mac_address);
        size += MACADDR_STR_LEN;

        dr->ip_address = strdup(rec->info.ip);
        size += strlen(rec->info.ip) + 1;

        dr->hostname = strdup(rec->info.hostname);
        size += strlen(rec->info.hostname) + 1;

        dr->ssid = strdup(rec->info.essid);
        size += strlen(rec->info.essid) + 1;

        network_id_len = strlen(rec->info.networkid);
        if (network_id_len) {
            dr->network_id = strdup(rec->info.networkid);
            size += network_id_len + 1;
        }

        dr->connected = rec->is_connected;
        dr->connect_count = rec->connected;
        dr->disconnect_count = rec->disconnected;

        if (rec->connect_ts) {
            dr->connect_offset_ms = client->timestamp_ms - rec->connect_ts;
            dr->has_connect_offset_ms = true;
        }

        if (rec->disconnect_ts) {
            dr->disconnect_offset_ms = client->timestamp_ms - rec->disconnect_ts;
            dr->has_disconnect_offset_ms = true;
        }

        if (rec->uapsd) {
            dr->uapsd = rec->uapsd;
            dr->has_uapsd = true;
        }

        dr->duration_ms = rec->duration_ms;

        dr->has_connected = true;
        dr->has_connect_count = true;
        dr->has_disconnect_count = true;
        dr->has_duration_ms = true;

        dr->stats = MALLOC(sizeof(*dr->stats));
        size += sizeof(*dr->stats);
        sts__client__stats__init(dr->stats);

        if (rec->stats.bytes_rx) {
            dr->stats->rx_bytes = rec->stats.bytes_rx;
            dr->stats->has_rx_bytes = true;
        }
        if (rec->stats.bytes_tx) {
            dr->stats->tx_bytes = rec->stats.bytes_tx;
            dr->stats->has_tx_bytes = true;
        }
        if (rec->stats.frames_rx) {
            dr->stats->rx_frames = rec->stats.frames_rx;
            dr->stats->has_rx_frames = true;
        }
        if (rec->stats.frames_tx) {
            dr->stats->tx_frames = rec->stats.frames_tx;
            dr->stats->has_tx_frames = true;
        }
        if (rec->stats.retries_rx) {
            dr->stats->rx_retries = rec->stats.retries_rx;
            dr->stats->has_rx_retries = true;
        }
        if (rec->stats.retries_rx) {
            dr->stats->tx_retries = rec->stats.retries_tx;
            dr->stats->has_tx_retries = true;
        }
        if (rec->stats.errors_rx) {
            dr->stats->rx_errors = rec->stats.errors_rx;
            dr->stats->has_rx_errors = true;
        }
        if (rec->stats.errors_tx) {
            dr->stats->tx_errors = rec->stats.errors_tx;
            dr->stats->has_tx_errors = true;
        }
        if (rec->stats.rate_rx) {
            dr->stats->rx_rate = rec->stats.rate_rx;
            dr->stats->has_rx_rate = true;
        }
        if (rec->stats.rate_tx) {
            dr->stats->tx_rate = rec->stats.rate_tx;
            dr->stats->has_tx_rate = true;
        }
        if (rec->stats.rssi) {
            dr->stats->rssi = rec->stats.rssi;
            dr->stats->has_rssi = true;
        }
        if (rec->stats.rate_rx_perceived) {
            dr->stats->rx_rate_perceived = rec->stats.rate_rx_perceived;
            dr->stats->has_rx_rate_perceived = true;
        }
        if (rec->stats.rate_tx_perceived) {
            dr->stats->tx_rate_perceived = rec->stats.rate_tx_perceived;
            dr->stats->has_tx_rate_perceived = true;
        }

        dr->rx_stats = MALLOC(client->list[i].rx_qty * sizeof(*dr->rx_stats));
        size += client->list[i].rx_qty * sizeof(*dr->rx_stats);
        dr->n_rx_stats = client->list[i].rx_qty;
        for (j = 0; j < client->list[i].rx_qty; j++)
        {
            Sts__Client__RxStats   *drx;
            dpp_client_stats_rx_t  *srx = &client->list[i].rx[j];

            drx = dr->rx_stats[j] = MALLOC(sizeof(**dr->rx_stats));
            sts__client__rx_stats__init(drx);

            drx->mcs        = srx->mcs;
            drx->nss        = srx->nss;
            drx->bw         = srx->bw;

            if (srx->bytes) {
                drx->bytes = srx->bytes;
                drx->has_bytes = true;
            }
            if (srx->msdu) {
                drx->msdus = srx->msdu;
                drx->has_msdus = true;
            }
            if (srx->mpdu) {
                drx->mpdus = srx->mpdu;
                drx->has_mpdus = true;
            }
            if (srx->ppdu) {
                drx->ppdus = srx->ppdu;
                drx->has_ppdus = true;
            }
            if (srx->retries) {
                drx->retries = srx->retries;
                drx->has_retries = true;
            }
            if (srx->errors) {
                drx->errors = srx->errors;
                drx->has_errors = true;
            }
            if (srx->rssi) {
                drx->rssi = srx->rssi;
                drx->has_rssi = true;
            }
        }

        dr->tx_stats = MALLOC(client->list[i].tx_qty * sizeof(*dr->tx_stats));
        size += client->list[i].tx_qty * sizeof(*dr->tx_stats);
        dr->n_tx_stats = client->list[i].tx_qty;
        for (j = 0; j < client->list[i].tx_qty; j++)
        {
            Sts__Client__TxStats *dtx;
            dpp_client_stats_tx_t *stx = &client->list[i].tx[j];

            dtx = dr->tx_stats[j] = MALLOC(sizeof(**dr->tx_stats));
            sts__client__tx_stats__init(dtx);

            dtx->mcs     = stx->mcs;
            dtx->nss     = stx->nss;
            dtx->bw      = stx->bw;

            if (stx->bytes) {
                dtx->bytes = stx->bytes;
                dtx->has_bytes = true;
            }
            if (stx->msdu) {
                dtx->msdus = stx->msdu;
                dtx->has_msdus = true;
            }
            if (stx->mpdu) {
                dtx->mpdus = stx->mpdu;
                dtx->has_mpdus = true;
            }
            if (stx->ppdu) {
                dtx->ppdus = stx->ppdu;
                dtx->has_ppdus = true;
            }
            if (stx->retries) {
                dtx->retries = stx->retries;
                dtx->has_retries = true;
            }
            if (stx->errors) {
                dtx->errors = stx->errors;
                dtx->has_errors = true;
            }
        }

        dr->tid_stats = MALLOC(client->list[i].tid_qty * sizeof(*dr->tid_stats));
        size += client->list[i].tid_qty * sizeof(*dr->tid_stats);
        dr->n_tid_stats = client->list[i].tid_qty;
        for (j = 0; j < client->list[i].tid_qty; j++)
        {
            Sts__Client__TidStats *dtid;
            dpp_client_tid_record_list_t *stid = &client->list[i].tid[j];
            dtid = dr->tid_stats[j] = MALLOC(sizeof(**dr->tid_stats));
            sts__client__tid_stats__init(dtid);

            dtid->offset_ms =
                sr->timestamp_ms - stid->timestamp_ms;
            dtid->has_offset_ms = true;

            dtid->sojourn = MALLOC(CLIENT_MAX_TID_RECORDS * sizeof(*dtid->sojourn));
            for (n = 0, j1 = 0; j1 < CLIENT_MAX_TID_RECORDS; j1++)
            {
                Sts__Client__TidStats__Sojourn *drr;
                dpp_client_stats_tid_t *srr = &stid->entry[n];
                if (!(srr->num_msdus)) continue;
                drr = dtid->sojourn[n] = MALLOC(sizeof(**dtid->sojourn));
                sts__client__tid_stats__sojourn__init(drr);
                drr->ac = dppline_to_proto_wmm_ac_type(srr->ac);
                drr->tid = srr->tid;

                if (srr->ewma_time_ms) {
                    drr->ewma_time_ms = srr->ewma_time_ms;
                    drr->has_ewma_time_ms = true;
                }
                if (srr->sum_time_ms) {
                    drr->sum_time_ms = srr->sum_time_ms;
                    drr->has_sum_time_ms = true;
                }
                if (srr->num_msdus) {
                    drr->num_msdus = srr->num_msdus;
                    drr->has_num_msdus = true;
                }
                n++;
            }
            dtid->n_sojourn = n;
            dtid->sojourn = REALLOC(dtid->sojourn, n * sizeof(*dtid->sojourn));
            size += n * sizeof(*dtid->sojourn);
        }
    }
}

static void dppline_add_stat_device(Sts__Report *r, dppline_stats_t *s)
{
    Sts__Device *sr = NULL;
    uint32_t i;
    dppline_device_stats_t *device = &s->u.device;

    // increase the number of devices
    r->n_device++;

    // allocate or extend the size of devices
    r->device = REALLOC(r->device, r->n_device * sizeof(Sts__Device*));

    // allocate new buffer Sts__Device
    sr = MALLOC(sizeof(Sts__Device));
    r->device[r->n_device - 1] = sr;

    sts__device__init(sr);
    sr->timestamp_ms = device->timestamp_ms;
    sr->has_timestamp_ms = true;

    sr->load = MALLOC(sizeof(*sr->load));
    sts__device__load_avg__init(sr->load);
    sr->load->one = device->record.load[DPP_DEVICE_LOAD_AVG_ONE];
    sr->load->has_one = true;
    sr->load->five = device->record.load[DPP_DEVICE_LOAD_AVG_FIVE];
    sr->load->has_five = true;
    sr->load->fifteen = device->record.load[DPP_DEVICE_LOAD_AVG_FIFTEEN];
    sr->load->has_fifteen = true;

    sr->uptime = device->record.uptime;
    sr->has_uptime = true;

    sr->mem_util = MALLOC(sizeof(*sr->mem_util));
    sts__device__mem_util__init(sr->mem_util);
    sr->mem_util->mem_total = device->record.mem_util.mem_total;
    sr->mem_util->mem_used = device->record.mem_util.mem_used;
    sr->mem_util->swap_total = device->record.mem_util.swap_total;
    sr->mem_util->has_swap_total = true;
    sr->mem_util->swap_used = device->record.mem_util.swap_used;
    sr->mem_util->has_swap_used = true;

    sr->fs_util = MALLOC(DPP_DEVICE_FS_TYPE_QTY * sizeof(*sr->fs_util));
    sr->n_fs_util = DPP_DEVICE_FS_TYPE_QTY;
    for (i = 0; i < sr->n_fs_util; i++)
    {
        sr->fs_util[i] = MALLOC(sizeof(**sr->fs_util));
        sts__device__fs_util__init(sr->fs_util[i]);

        sr->fs_util[i]->fs_total = device->record.fs_util[i].fs_total;
        sr->fs_util[i]->fs_used = device->record.fs_util[i].fs_used;
        sr->fs_util[i]->fs_type = (Sts__FsType)device->record.fs_util[i].fs_type;
    }

    sr->cpuutil = MALLOC(sizeof(*sr->cpuutil));
    sts__device__cpu_util__init(sr->cpuutil);
    sr->cpuutil->cpu_util = device->record.cpu_util.cpu_util;
    sr->cpuutil->has_cpu_util = true;

    sr->n_ps_cpu_util = 0;
    sr->n_ps_cpu_util = device->record.n_top_cpu;

    if (sr->n_ps_cpu_util > 0) {
        sr->ps_cpu_util = MALLOC(sr->n_ps_cpu_util * sizeof(*sr->ps_cpu_util));
        for (i = 0; i < sr->n_ps_cpu_util; i++) {
            sr->ps_cpu_util[i] = MALLOC(sizeof(**sr->ps_cpu_util));
            sts__device__per_process_util__init(sr->ps_cpu_util[i]);
            sr->ps_cpu_util[i]->pid = device->record.top_cpu[i].pid;
            sr->ps_cpu_util[i]->cmd = strdup(device->record.top_cpu[i].cmd);
            sr->ps_cpu_util[i]->util = device->record.top_cpu[i].util;
        }
    }

    sr->n_ps_mem_util = 0;
    sr->n_ps_mem_util = device->record.n_top_mem;

    if (sr->n_ps_mem_util > 0) {
        sr->ps_mem_util = MALLOC(sr->n_ps_mem_util * sizeof(*sr->ps_mem_util));
        for (i = 0; i < sr->n_ps_mem_util; i++) {
            sr->ps_mem_util[i] = MALLOC(sizeof(**sr->ps_mem_util));
            sts__device__per_process_util__init(sr->ps_mem_util[i]);
            sr->ps_mem_util[i]->pid = device->record.top_mem[i].pid;
            sr->ps_mem_util[i]->cmd = strdup(device->record.top_mem[i].cmd);
            sr->ps_mem_util[i]->util = device->record.top_mem[i].util;
        }
    }

    sr->powerinfo = MALLOC(sizeof(*sr->powerinfo));
    sts__device__power_info__init(sr->powerinfo);
    if (device->record.power_info.ps_type) {
        sr->powerinfo->ps_type = device->record.power_info.ps_type;
        sr->powerinfo->has_ps_type = true;
    }

    if (device->record.power_info.p_consumption) {
        sr->powerinfo->p_consumption = device->record.power_info.p_consumption;
        sr->powerinfo->has_p_consumption = true;
    }

    if (device->record.power_info.batt_level) {
        sr->powerinfo->batt_level = device->record.power_info.batt_level;
        sr->powerinfo->has_batt_level = true;
    }
}

static void dppline_add_stat_vif(Sts__Report *r, dppline_stats_t *s)
{
	//TO ADD VIF STATS
	Sts__VifStatReport *sr = NULL;
	Sts__Vif *dr;
	Sts__Radio *rr;

	uint32_t i = 0;
    int j, j1;
    int n = 0;
    int size = 0;
    dppline_vif_stats_t *vif = &s->u.vif;

    // increase the number of radio
    r->n_vif++;

    // allocate or extend the size of radio
    r->vif = REALLOC(r->vif, r->n_vif * sizeof(Sts__VifStatReport*));

    // allocate new buffer Sts__Radio
    sr = MALLOC(sizeof(Sts__VifStatReport));
    r->vif[r->n_vif - 1] = sr;

    sts__vif_stat_report__init(sr);

	sr->timestamp_ms = vif->timestamp_ms;
    sr->has_timestamp_ms = true;

    sr->vif_list = MALLOC(vif->record.n_vif * sizeof(*sr->vif_list));
    size += vif->record.n_vif * sizeof(*sr->vif_list);
    sr->n_vif_list = vif->record.n_vif;
    for (i = 0; i < vif->record.n_vif; i++)
    {
        dr = sr->vif_list[i] = MALLOC(sizeof(**sr->vif_list));
        size += sizeof(**sr->vif_list);
        sts__vif__init(dr);

		if (strlen(vif->record.vif[i].radio) > 0) {
            dr->radio = strdup(vif->record.vif[i].radio);
        }
        if (strlen(vif->record.vif[i].ssid) > 0) {
            dr->stat_ssid = strdup(vif->record.vif[i].ssid);
        }
        
		dr->has_stat_num_sta = true;
		dr->stat_num_sta = vif->record.vif[i].num_sta;
		
		if(vif->record.vif[i].uplink_mb) {
			dr->has_stat_uplink_mb = true;
			dr->stat_uplink_mb = vif->record.vif[i].uplink_mb;
		}

		if(vif->record.vif[i].downlink_mb) {
			dr->has_stat_downlink_mb = true;
			dr->stat_downlink_mb = vif->record.vif[i].downlink_mb;
		}
	}


    sr->radio_list = MALLOC(vif->record.n_radio * sizeof(*sr->radio_list));
    size += vif->record.n_radio * sizeof(*sr->radio_list);
    sr->n_radio_list = vif->record.n_radio;
    for (i = 0; i < vif->record.n_radio; i++)
    {
        rr = sr->radio_list[i] = MALLOC(sizeof(**sr->radio_list));
        size += sizeof(**sr->radio_list);
		sts__radio__init(rr);

		if (strlen(vif->record.radio[i].band) > 0) {
                    rr->band = strdup(vif->record.radio[i].band);
                }
		
		if(vif->record.radio[i].channel) {
			rr->has_channel = true;
			rr->channel = vif->record.radio[i].channel;
		}

		if(vif->record.radio[i].txpower) {
			rr->has_txpower = true;
			rr->txpower = vif->record.radio[i].txpower;
		}

		if(vif->record.radio[i].channel_utilization) {
			rr->has_channel_utilization = true;
			rr->channel_utilization = vif->record.radio[i].channel_utilization;
		}
	}
}


static void dppline_add_stat(Sts__Report * r, dppline_stats_t * s)
{
    switch(s->type)
    {
		case DPP_T_NEIGHBOR:
            dppline_add_stat_neighbor(r, s);
            break;
        case DPP_T_CLIENT:
            dppline_add_stat_client(r, s);
            break;
		case DPP_T_DEVICE:
            dppline_add_stat_device(r, s);
            break;
		case DPP_T_VIF:
            dppline_add_stat_vif(r, s);
            break;
        default:
            LOG(ERR, "Failed to add %d to stats report", s->type);
            /* do nothing       */
            break;
    }

}


/*
 * Genetic function for removing a single stat from queue head
 */
bool dppline_remove_head()
{
    dppline_stats_t * s = NULL;

    /* get head if now queue node given     */
    s = ds_dlist_head(&g_dppline_list);

    /* remove head element                  */
    ds_dlist_remove_head(&g_dppline_list);

    /* reduce queue depth                   */
    queue_depth--;
    queue_size -= s->size;

    /* free allocated memory                */
    dppline_free_stat(s);

    return true;
}

void dppline_log_queue()
{
    LOGT( "Q len: %d size: %d\n", queue_depth, queue_size );
}

/*
 * Genetic function for adding new stats to internal queue
 */
static bool dppline_put(DPP_STS_TYPE type, void * rpt)
{
    dppline_stats_t *s = NULL;

    /* allocate buffer          */
    s = dpp_alloc_stat();
    if (!s)
    {
        LOG(ERR, "Failed add %d to stats queue", type);
        return false;
    }

    /* set stats buffer type    */
    s->type = type;

    /* copy stats               */
    if (!dppline_copysts(s, rpt))
    {
        dppline_free_stat(s);
        return false;
    }

    /* insert new element into stats queue  */
    ds_dlist_insert_tail(&g_dppline_list, s);

    // update counters
    queue_depth++;
    queue_size += s->size;

    // drop old entries if queue too long
    if (queue_depth > DPP_MAX_QUEUE_DEPTH
            || queue_size > DPP_MAX_QUEUE_SIZE_BYTES)
    {
        LOG(WARN, "Queue size exceeded %d > %d || %d > %d",
                queue_depth, DPP_MAX_QUEUE_DEPTH,
                queue_size, DPP_MAX_QUEUE_SIZE_BYTES);
        dppline_remove_head();
    }

    dppline_log_queue();

    return true;
}

/* Initialize library     */
bool dpp_init()
{
    LOG(INFO,
        "Initializing DPP library.\n");

    ds_dlist_init(&g_dppline_list, struct dpp_stats, dnode);

    /* reset the queue depth counter    */
    queue_depth = 0;

    return true;
}

/*
 * Put client stats to internal queue
 */
bool dpp_put_device(dpp_device_report_data_t * rpt)
{
    return dppline_put(DPP_T_DEVICE, rpt);
}


/*
 * Put vif stats to internal queue
 */
bool dpp_put_vif(dpp_vif_report_data_t * rpt)
{
    return dppline_put(DPP_T_VIF, rpt);
}

/*
 * Put client stats to internal queue
 */
bool dpp_put_client(dpp_client_report_data_t *rpt)
{
    return dppline_put(DPP_T_CLIENT, rpt);
}

/*
 * Put neighbor stats to internal queue
 */
bool dpp_put_neighbor(dpp_neighbor_report_data_t *rpt)
{
    return dppline_put(DPP_T_NEIGHBOR, rpt);
}


/*
 * Put client stats to internal queue
 */
bool dpp_put_rssi(dpp_rssi_report_data_t * rpt)
{
    return dppline_put(DPP_T_RSSI, rpt);
}


/*
 * Create the protobuf buff and copy it to given buffer
 */
bool dpp_get_report(uint8_t * buff, size_t sz, uint32_t * packed_sz)
{

    ds_dlist_iter_t iter;
    dppline_stats_t *s;
	char param[32];
    bool ret = false;
    size_t tmp_packed_size; /* packed size of current report */

    /* prevent sending empty reports */
    if (dpp_get_queue_elements() == 0)
    {
        LOG(DEBUG, "get_report: queue depth is zero");
        return false;
    }

    /* stop any further actions in case improper buffer submitted */
    if (NULL == buff || sz == 0)
    {
        LOG(DEBUG, "get_report: invalid buffer or size");
        return false;
    }

    /* initialize report structure. Note - it has to be on heap,
     * otherwise __free_unpacked function fails
     */
    Sts__Report * report = MALLOC(sizeof(Sts__Report));
    sts__report__init(report);
    report->mac_addr = getNodeid();
    report->serial_num = getNodeid();

    for (s = ds_dlist_ifirst(&iter, &g_dppline_list); s != NULL; s = ds_dlist_inext(&iter))
    {
        /* try to add new stats data to protobuf report */
        dppline_add_stat(report, s);

        tmp_packed_size = sts__report__get_packed_size(report);

        /* check the size, if size too small break the process */
        if (sz < tmp_packed_size)
        {
            LOG(WARNING, "Packed size: %5zd, buffer size: %5zd ",
                tmp_packed_size,
                sz);

            /* break if size exceeded */
            break; /* for loop   */;
        }
        else
        {
            /* pack current report to return buffer */
            *packed_sz = sts__report__pack(report, buff);

            /* remove item from the list and free memory */
            s = ds_dlist_iremove(&iter);

            /* decrease queue depth */
            if (0 == queue_depth)
            {
                LOG(ERR, "Queue depth zero but dpp is keep adding");
                break;
            }

            queue_size -= s->size;
            queue_depth--;

            /* at least one stat report is in protobuf, good
             * reason to announce success
             */
            ret = true;

            /* free internal stats structure */
            dppline_free_stat(s);
        }
    }

    /* in any case,
     * free memory used for report using system allocator
     */
    sts__report__free_unpacked(report, NULL);
    dppline_log_queue();

    return ret;
}

/*
 * Count the number of stats in queue
 */
int dpp_get_queue_elements()
{
    dppline_stats_t * s = NULL;
    ds_dlist_iter_t iter;
    uint32_t queue = 0;

    /* iterate the queue and count the number of elements */
    for (s = ds_dlist_ifirst(&iter, &g_dppline_list); s != NULL; s = ds_dlist_inext(&iter))
    {
        queue++;
    }

    if (queue != queue_depth)
    {
        LOG(ERR, "Queue depth mismatch %d != %d", queue, queue_depth);
    }

    return queue;
}

// alloc and init a dpp_client_record_t
dpp_client_record_t* dpp_client_record_alloc()
{
    dpp_client_record_t *record = NULL;

    record = MALLOC(sizeof(dpp_client_record_t));
    memset(record, 0, sizeof(dpp_client_record_t));

    // init stats_rx dlist
    ds_dlist_init(&record->stats_rx, dpp_client_stats_rx_t, node);

    // init stats_tx dlist
    ds_dlist_init(&record->stats_tx, dpp_client_stats_tx_t, node);

    // init tid_record_list dlist
    ds_dlist_init(&record->tid_record_list, dpp_client_tid_record_list_t, node);

    return record;
}
