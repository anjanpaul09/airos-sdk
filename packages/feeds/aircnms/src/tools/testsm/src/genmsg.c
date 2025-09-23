#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>

#include "nl80211_client.h"
#include "sm.h"
#include "testsm.h"
#include "memutil.h"

#define MAX_CLIENTS 4

static struct ev_timer  genmsg_timer;

bool client_update_list_cb(ds_dlist_t *client_list, void *ctx, int client_status);
sm_client_ctx_t *sm_client_ctx_get(radio_entry_t *radio_cfg);
void testqm_init_dpp_client_stats();
uint64_t get_current_timestamp_ms() 
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t milliseconds = (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
    return milliseconds;
}

void dpp_dummy_get_client_report_data(dpp_client_report_data_t *report_data)
{
    dpp_client_record_t            *report_entry = NULL;
    ds_dlist_t                     *report_list = &report_data->list;
    report_data->radio_type = 2;  
    //report_data->radio_type = rand() % 6;  
    report_data->channel = rand() % 165 + 1;  
    ///report_data->timestamp_ms = rand() % 1000000000;  
    report_data->timestamp_ms = get_current_timestamp_ms(); 
    //report_data->uplink_type = rand() % 4;  // Random uplink type
    //report_data->uplink_changed = rand() % 2;  // Random boolean

    ds_dlist_init(&report_data->list, dpp_client_record_t, node);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        report_entry = dpp_client_record_alloc();
        if (report_entry == NULL) {
            perror("Failed to allocate memory for new client record");
            break;
        }

        dpp_dummy_get_client_record(report_entry, i);
        ds_dlist_insert_tail(report_list, report_entry);
    }
}

#if 0
static
bool dpp_client_stats_rx_records_clear(ds_dlist_t *stats_rx_list)
{
    dpp_client_stats_rx_t          *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (   record = ds_dlist_ifirst(&record_iter, stats_rx_list);
            record != NULL;
            record = ds_dlist_inext(&record_iter))
    {
        ds_dlist_iremove(&record_iter);
        dpp_client_stats_rx_record_free(record);
        record = NULL;
    }

    return true;
}

static
bool dpp_client_tid_records_clear(ds_dlist_t *tid_record_list)
{
    dpp_client_tid_record_list_t   *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (   record = ds_dlist_ifirst(&record_iter, tid_record_list);
            record != NULL;
            record = ds_dlist_inext(&record_iter))
    {
        ds_dlist_iremove(&record_iter);
        dpp_client_tid_record_free(record);
        record = NULL;
    }

    return true;
}


static
bool dpp_client_stats_tx_records_clear(ds_dlist_t *stats_tx_list)
{
    dpp_client_stats_tx_t          *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (   record = ds_dlist_ifirst(&record_iter, stats_tx_list);
            record != NULL;
            record = ds_dlist_inext(&record_iter))
   {
        ds_dlist_iremove(&record_iter);
        dpp_client_stats_tx_record_free(record);
        record = NULL;
    }

    return true;
}



void dpp_free_dummy_client_report_data(dpp_client_report_data_t *report_data)
{
    ds_dlist_t                     *record_list = &report_data->list;
    dpp_client_record_t            *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (record = ds_dlist_ifirst(&record_iter, record_list); record != NULL; record = ds_dlist_inext(&record_iter)) {
        dpp_client_stats_rx_records_clear(&record->stats_rx);
        dpp_client_stats_tx_records_clear(&record->stats_tx);
        dpp_client_tid_records_clear(&record->tid_record_list);
        ds_dlist_iremove(&record_iter);
        dpp_client_record_free(record);
        record = NULL;
    }

}
#endif

void put_client_to_dpp()
{
    testqm_init_dpp_client_stats();
#if 0
    dpp_client_report_data_t report_ctx;
    dpp_dummy_get_client_report_data(&report_ctx);

    dpp_put_client(&report_ctx);

    dpp_free_dummy_client_report_data(&report_ctx);
#endif
}

void put_device_to_dpp()
{
    dpp_device_report_data_t report_data;

    report_data.timestamp_ms = get_current_timestamp_ms();
    dpp_dummy_get_device_report_data(&report_data);
    //dpp_put_device(&report_data);
}


void put_vif_to_dpp()
{
    dpp_vif_report_data_t report_data;

    report_data.timestamp_ms = get_current_timestamp_ms();
    //dpp_dummy_get_vif_report_data(&report_data.record);
    target_stats_vif_get(&report_data);
    printf("Ankit: vif - %d \n", report_data.record.n_vif);

    //dpp_put_vif(&report_data);
}

void client_genmsg_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    //put_device_to_dpp();
    //put_client_to_dpp();
    //put_vif_to_dpp();

}

bool gemmsg_qm_init(void)
{
    ev_timer_init(&genmsg_timer, client_genmsg_timer_handler, 1.0, 0.5);

    genmsg_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &genmsg_timer);

    return true;
}

