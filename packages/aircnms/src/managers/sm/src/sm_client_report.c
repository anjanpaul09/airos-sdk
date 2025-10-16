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

#include "sm.h"
#include "memutil.h"

bool target_stats_clients_get(client_report_data_t *client_list);

#define MODULE_ID LOG_MODULE_ID_MAIN

#define sm_client_report_stat_percent_get(v1, v2) \
    ((v2 > 0 && v1 < v2) ? (v1*100/v2) : 0)

#define sm_client_report_stat_delta(n, o) ((n) - (o))


typedef struct
{
    bool                            initialized;
    radio_entry_t                   radio_cfg;
    ev_timer                        report_timer;
    ev_signal                       ev_sig;
    sm_stats_request_t              request;
    client_report_data_t            report;
    client_report_data_t            cache;
    client_report_data_t            result;
    uint64_t                        report_ts;
} sm_client_ctx_t;

static sm_client_ctx_t              g_sm_client_ctx;

static bool sm_client_timer_set(ev_timer *timer, bool enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    } else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}

static void update_client_cache(sm_client_ctx_t *client_ctx)
{
    client_report_data_t *report_ctx = &client_ctx->report;
    client_report_data_t *cache_ctx = &client_ctx->cache;

    // Mark all cached clients as disconnected initially
    for (int i = 0; i < cache_ctx->n_client; i++) {
        cache_ctx->record[i].is_connected = 0;
    }

    // Update cache with new report data
    for (int i = 0; i < report_ctx->n_client; i++) {
        client_record_t *new_client = &report_ctx->record[i];

        bool found = false;
        for (int j = 0; j < cache_ctx->n_client; j++) {
            client_record_t *cached_client = &cache_ctx->record[j];

            if (memcmp(cached_client->macaddr, new_client->macaddr, 6) == 0) {
                // Client found in cache, update details
                *cached_client = *new_client;
                cached_client->is_connected = 1;
                found = true;
                break;
            }
        }

        if (!found && cache_ctx->n_client < MAX_CLIENTS) {
            // Add new client to cache
            cache_ctx->record[cache_ctx->n_client++] = *new_client;
        }
    }
}

static void prepare_client_result(sm_client_ctx_t *client_ctx)
{
    sm_stats_request_t *request_ctx = &client_ctx->request;
    client_report_data_t *report_ctx = &client_ctx->report;
    client_report_data_t *cache_ctx = &client_ctx->cache;
    client_report_data_t *result_ctx = &client_ctx->result;
    client_report_data_t temp_cache;

    result_ctx->n_client = 0;
    temp_cache.n_client = 0;
    
    result_ctx->timestamp_ms = request_ctx->reporting_timestamp - client_ctx->report_ts + get_timestamp();

    for (int i = 0; i < cache_ctx->n_client; i++) {
        if (result_ctx->n_client < MAX_CLIENTS) {
            // Add both connected and disconnected clients to the result
            result_ctx->record[result_ctx->n_client++] = cache_ctx->record[i];
        }

        if (cache_ctx->record[i].is_connected) {
            // Keep only connected clients in the cache
            temp_cache.record[temp_cache.n_client++] = cache_ctx->record[i];
        }
    }

    // Update cache to remove disconnected clients
    *cache_ctx = temp_cache;
    
    SM_SANITY_CHECK_TIME(result_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &client_ctx->report_ts);
}

/* Main Function */
static void sm_client_report_stats(sm_client_ctx_t *client_ctx)
{
    bool status;
    sm_stats_request_t *request_ctx = &client_ctx->request;
    client_report_data_t *report_ctx = &client_ctx->report;
    client_report_data_t *result_ctx = &client_ctx->result;

    // Fetch current connected clients
    status = target_stats_clients_get(report_ctx);

    // Update timestamp
    report_ctx->timestamp_ms = request_ctx->reporting_timestamp - client_ctx->report_ts + get_timestamp();

    if (!status) {
        fprintf(stderr, "Failed to fetch client stats\n");
        return;
    }

    // Update the cache
    update_client_cache(client_ctx);

    // Prepare the final result (including disconnected clients) and clean up cache
    prepare_client_result(client_ctx);

    result_ctx->timestamp_ms = request_ctx->reporting_timestamp - client_ctx->report_ts + get_timestamp();
    // Send final report
    if (client_ctx->result.n_client > 0) {
        sm_put_client(&client_ctx->result);
        LOG(INFO,
            "Sending client report at '%s' n-client '%d'",
            sm_timestamp_ms_to_date(result_ctx->timestamp_ms),
            result_ctx->n_client);
    }
}

static void sm_client_report(EV_P_ ev_timer *w, int revents)
{
    sm_client_report_stats(w->data);
}

static void
sm_nlev_client_handle_signal(struct ev_loop *loop, ev_signal *w, int revents)
{
    sm_client_ctx_t *client_ctx = (sm_client_ctx_t *)w->data;
    ev_timer        *report_timer = &client_ctx->report_timer;

    LOG(INFO, "SM: STA SIGNAL\n");
    
    usleep(1000000);
    ev_feed_event(loop, report_timer, EV_TIMEOUT);
}

bool sm_client_report_request(radio_entry_t *radiocfg, sm_stats_request_t *request)
{
    sm_client_ctx_t             *client_ctx = NULL;
    client_ctx = &g_sm_client_ctx;
    sm_stats_request_t          *request_ctx = &client_ctx->request;
    client_report_data_t        *report_ctx = &client_ctx->report;
    radio_entry_t               *radio_cfg  = &client_ctx->radio_cfg;
    ev_timer                    *report_timer = &client_ctx->report_timer;
    ev_signal                   *ev_sigusr = &client_ctx->ev_sig;

    if (NULL == request) {
        LOG(ERR, "Initializing client reporting ""(Invalid request config)");
        return false;
    }

    radio_cfg->type = request->radio_type;

    /* Initialize global stats only once */
    if (!client_ctx->initialized) {
        memset(request_ctx, 0, sizeof(*request_ctx));
        memset(report_ctx, 0, sizeof(*report_ctx));

        LOG(INFO, "Initializing client reporting");

        ev_init(report_timer, sm_client_report);
        report_timer->data = client_ctx;

        ev_signal_init(ev_sigusr, sm_nlev_client_handle_signal, SIGUSR1);
        ev_sigusr->data = client_ctx;
        ev_signal_start(EV_DEFAULT, ev_sigusr);

        client_ctx->initialized = true;
    }

    REQUEST_VAL_UPDATE("client", reporting_count, "%d");
    REQUEST_VAL_UPDATE("client", reporting_interval, "%d");
    REQUEST_VAL_UPDATE("client", reporting_timestamp, "%"PRIu64"");

    sm_client_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        client_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        sm_client_timer_set(report_timer, true);
        LOG(INFO, "Started client reporting");
    }
    else {
        LOG(INFO, "Stopped client reporting");
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}

