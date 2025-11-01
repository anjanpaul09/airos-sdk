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

#include "netstats.h"
#include "memutil.h"
#include "log.h"

bool target_stats_clients_get(client_report_data_t *client_list);

#define MODULE_ID LOG_MODULE_ID_MAIN

#define netstats_client_report_stat_percent_get(v1, v2) \
    ((v2 > 0 && v1 < v2) ? (v1*100/v2) : 0)

#define netstats_client_report_stat_delta(n, o) ((n) - (o))

typedef struct
{
    bool                            initialized;
    ev_timer                        report_timer;
    ev_signal                       ev_sig;
    netstats_request_t        request;
    client_report_data_t            cache;      // Only cache persists between calls
    uint64_t                        report_ts;
} netstats_client_ctx_t;

static netstats_client_ctx_t g_netstats_client_ctx;

/* Dynamic allocation helper functions */
static client_report_data_t* alloc_report_data(int initial_capacity)
{
    client_report_data_t *data = (client_report_data_t *)calloc(1, sizeof(client_report_data_t));
    if (!data) {
        LOG(ERR, "Failed to allocate client_report_data_t");
        return NULL;
    }
    
    data->record = (client_record_t *)calloc(initial_capacity, sizeof(client_record_t));
    if (!data->record) {
        LOG(ERR, "Failed to allocate memory for client records");
        free(data);
        return NULL;
    }
    
    data->capacity = initial_capacity;
    data->n_client = 0;
    data->timestamp_ms = 0;
    
    return data;
}

static void free_report_data(client_report_data_t *data)
{
    if (data) {
        if (data->record) {
            free(data->record);
        }
        free(data);
    }
}

static bool ensure_capacity(client_report_data_t *data, int required)
{
    
    if (required <= data->capacity) {
        return true;
    }
    
    int new_capacity = data->capacity * 2;
    if (new_capacity < required) {
        new_capacity = required;
    }
    
    client_record_t *new_record = (client_record_t *)realloc(data->record, 
                                                              new_capacity * sizeof(client_record_t));
    if (!new_record) {
        LOG(ERR, "Failed to reallocate memory for client records");
        return false;
    }
    
    int old_capacity = data->capacity;
    data->record = new_record;
    data->capacity = new_capacity;
    
    LOG(DEBUG, "Expanded client capacity from %d to %d", old_capacity, new_capacity);
    return true;
}

static void init_cache_if_needed(client_report_data_t *cache, int initial_capacity)
{
    if (cache->record == NULL) {
        LOG(DEBUG, "Initializing cache with capacity %d", initial_capacity);
        cache->record = (client_record_t *)calloc(initial_capacity, sizeof(client_record_t));
        if (cache->record) {
            cache->capacity = initial_capacity;
            cache->n_client = 0;
            LOG(INFO, "Cache initialized successfully");
        } else {
            LOG(ERR, "Failed to initialize cache");
        }
    } else {
        LOG(DEBUG, "init_cache_if_needed: Cache already initialized");
    }
}

static void free_cache(client_report_data_t *cache)
{
    if (cache->record) {
        free(cache->record);
        cache->record = NULL;
    }
    cache->capacity = 0;
    cache->n_client = 0;
}

static bool netstats_client_timer_set(ev_timer *timer, bool enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    } else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}

static bool update_client_cache(client_report_data_t *cache_ctx,
                                  client_report_data_t *report_ctx)
{
    // Validate pointers
    if (!cache_ctx || !report_ctx) {
        LOG(ERR, "update_client_cache: NULL pointer detected");
        return false;
    }
    
    if (!cache_ctx->record) {
        LOG(ERR, "update_client_cache: cache_ctx->record is NULL");
        return false;
    }
    
    if (!report_ctx->record) {
        return false;
    }

    // Ensure cache has enough capacity for potential new clients
    int required_capacity = cache_ctx->n_client + report_ctx->n_client;
    
    if (!ensure_capacity(cache_ctx, required_capacity)) {
        LOG(ERR, "Failed to ensure cache capacity");
        return false;
    }
    
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
                // Client found in cache, update details using memcpy
                memcpy(cached_client, new_client, sizeof(client_record_t));
                cached_client->is_connected = 1;
                found = true;
                break;
            }
        }

        if (!found) {
            
            // Verify we're not writing out of bounds
            if (cache_ctx->n_client >= cache_ctx->capacity) {
                return false;
            }
            
            // Add new client to cache using memcpy
            memcpy(&cache_ctx->record[cache_ctx->n_client], new_client, sizeof(client_record_t));
            cache_ctx->record[cache_ctx->n_client].is_connected = 1;
            cache_ctx->n_client++;
        }
    }

    return true;
}


static client_report_data_t* prepare_client_result(netstats_client_ctx_t *client_ctx)
{
    netstats_request_t *request_ctx = &client_ctx->request;
    client_report_data_t *cache_ctx = &client_ctx->cache;
    
    // Allocate result on the fly
    client_report_data_t *result_ctx = alloc_report_data(cache_ctx->n_client);
    if (!result_ctx) {
        LOG(ERR, "Failed to allocate result");
        return NULL;
    }

    result_ctx->timestamp_ms = request_ctx->reporting_timestamp - 
                               client_ctx->report_ts + get_timestamp();

    // Temporary storage for connected clients count
    int connected_count = 0;
    
    // First pass: add all clients to result and count connected ones
    for (int i = 0; i < cache_ctx->n_client; i++) {
        // Add to result (both connected and disconnected)
        result_ctx->record[result_ctx->n_client++] = cache_ctx->record[i];
        
        if (cache_ctx->record[i].is_connected) {
            connected_count++;
        }
    }

    // Second pass: compact cache to keep only connected clients
    int write_idx = 0;
    for (int i = 0; i < cache_ctx->n_client; i++) {
        if (cache_ctx->record[i].is_connected) {
            if (write_idx != i) {
                cache_ctx->record[write_idx] = cache_ctx->record[i];
            }
            write_idx++;
        }
    }
    cache_ctx->n_client = connected_count;
    
    NETSTATS_SANITY_CHECK_TIME(result_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &client_ctx->report_ts);
    
    return result_ctx;
}

/* Main Function */
static void netstats_client_report_stats(netstats_client_ctx_t *client_ctx)
{
    bool status;
    netstats_request_t *request_ctx = &client_ctx->request;
    client_report_data_t *cache_ctx = &client_ctx->cache;
   
    // Allocate report on the fly
    client_report_data_t *report_ctx = alloc_report_data(16); // Start with reasonable size
    
    if (!report_ctx) {
        LOG(ERR, "Failed to allocate report");
        return;
    }
    
    status = target_stats_clients_get(report_ctx);
    
    // Update timestamp
    report_ctx->timestamp_ms = request_ctx->reporting_timestamp - 
                               client_ctx->report_ts + get_timestamp();

    if (!status) {
        LOG(ERR, "Failed to fetch client stats");
        free_report_data(report_ctx);
        return;
    }

    LOG(DEBUG, "Updating cache with %d clients", report_ctx->n_client);

    // Update the cache
    if (!update_client_cache(cache_ctx, report_ctx)) {
        free_report_data(report_ctx);
        return;
    }
    
    LOG(DEBUG, "Cache updated, freeing report");
    
    // Free report immediately after updating cache
    free_report_data(report_ctx);
    report_ctx = NULL;

    LOG(DEBUG, "Preparing client result");

    // Prepare the final result (including disconnected clients)
    client_report_data_t *result_ctx = prepare_client_result(client_ctx);
    if (!result_ctx) {
        return;
    }

    // Send final report
    if (result_ctx->n_client > 0) {
        netstats_put_client(result_ctx);
    
        LOG(INFO,
            "Sending client report at '%s' n-client '%d'",
            netstats_timestamp_ms_to_date(result_ctx->timestamp_ms),
            result_ctx->n_client);
    }

    // Free result immediately after sending
    free_report_data(result_ctx);
}

static void netstats_client_report(EV_P_ ev_timer *w, int revents)
{
    netstats_client_report_stats(w->data);
}

static void
netstats_nlev_client_handle_signal(struct ev_loop *loop, ev_signal *w, int revents)
{
    netstats_client_ctx_t *client_ctx = (netstats_client_ctx_t *)w->data;
    ev_timer *report_timer = &client_ctx->report_timer;

    LOG(INFO, "NETSTATS: STA SIGNAL");
    
    usleep(1000000);
    ev_feed_event(loop, report_timer, EV_TIMEOUT);
}

bool netstats_client_report_request(netstats_request_t *request)
{
    netstats_client_ctx_t *client_ctx = NULL;
    client_ctx = &g_netstats_client_ctx;
    netstats_request_t *request_ctx = &client_ctx->request;
    ev_timer *report_timer = &client_ctx->report_timer;
    ev_signal *ev_sigusr = &client_ctx->ev_sig;

    if (NULL == request) {
        LOG(ERR, "netstats_client_report_request: NULL request");
        LOG(ERR, "Initializing client reporting (Invalid request config)");
        return false;
    }

    /* Initialize global stats only once */
    if (!client_ctx->initialized) {
        memset(request_ctx, 0, sizeof(*request_ctx));
        memset(&client_ctx->cache, 0, sizeof(client_ctx->cache));

        LOG(INFO, "Initializing client reporting");

        ev_init(report_timer, netstats_client_report);
        report_timer->data = client_ctx;

        ev_signal_init(ev_sigusr, netstats_nlev_client_handle_signal, SIGUSR1);
        ev_sigusr->data = client_ctx;
        ev_signal_start(EV_DEFAULT, ev_sigusr);

        client_ctx->initialized = true;
    }

    REQUEST_VAL_UPDATE("client", reporting_count, "%d");
    REQUEST_VAL_UPDATE("client", reporting_interval, "%d");
    REQUEST_VAL_UPDATE("client", reporting_timestamp, "%"PRIu64"");

    netstats_client_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        client_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        // Initialize cache lazily on first use
        init_cache_if_needed(&client_ctx->cache, 16);

        netstats_client_timer_set(report_timer, true);
        LOG(INFO, "Started client reporting");
    }
    else {
        LOG(INFO, "Stopped client reporting");
        
        // Clean up cache when stopping
        free_cache(&client_ctx->cache);
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}
