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
bool target_stats_neighbor_get(neighbor_report_data_t *report);

#define MODULE_ID LOG_MODULE_ID_MAIN

typedef struct
{
    bool                            initialized;
    radio_entry_t                   radio_cfg;
    ev_timer                        report_timer;
    ev_signal                       ev_sig;
    sm_stats_request_t              request;
    neighbor_report_data_t            report;
    uint64_t                        report_ts;
} sm_neighbor_ctx_t;

static sm_neighbor_ctx_t              g_sm_neighbor_ctx;

static bool sm_neighbor_timer_set(ev_timer *timer, bool enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    } else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}


static
bool sm_neighbor_report_timer_restart(
        ev_timer                   *timer)
{
    sm_neighbor_ctx_t                   *neighbor_ctx;
    sm_stats_request_t                  *request_ctx;

    if (NULL == timer->data)
        return false;

    neighbor_ctx =
        (sm_neighbor_ctx_t *) timer->data;

    request_ctx = &neighbor_ctx->request;

    if (request_ctx->reporting_count) {
        request_ctx->reporting_count--;

        LOG(DEBUG,
            "Neighbor reporting count=%d",
            request_ctx->reporting_count);

        /* If reporting_count becomes zero, then stop reporting */
        if (0 == request_ctx->reporting_count) {
            sm_neighbor_timer_set(timer, false);

            LOG(DEBUG,
                "Stopped neighbor reporting (count expired)");
            return true;
        }
    }

    return true;
}

static void sm_neighbor_report_stats(sm_neighbor_ctx_t *neighbor_ctx)
{
    bool                            status;
    sm_stats_request_t               *request_ctx = &neighbor_ctx->request;
    neighbor_report_data_t           *report_ctx = &neighbor_ctx->report;
    ev_timer                       *report_timer =
        &neighbor_ctx->report_timer;

    sm_neighbor_report_timer_restart(report_timer);

    status = target_stats_neighbor_get(report_ctx);

    /* Report_timestamp is base-timestamp + relative start time offset */
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - neighbor_ctx->report_ts +
        get_timestamp();

    LOG(INFO,
        "Sending neighbor report at '%s'",
        sm_timestamp_ms_to_date(report_ctx->timestamp_ms));
    if (status && report_ctx->n_entry > 0) {
        sm_put_neighbor(report_ctx);
    } 
    
    return;    
}


static void sm_neighbor_report(EV_P_ ev_timer *w, int revents)
{
    sm_neighbor_report_stats(w->data);
    //ev_timer_stop(EV_A_ w); // Stops the timer
}

static void
sm_nlev_neighbor_handle_signal(struct ev_loop *loop, ev_signal *w, int revents)
{
    sm_neighbor_ctx_t *neighbor_ctx = (sm_neighbor_ctx_t *)w->data;
    ev_timer        *report_timer = &neighbor_ctx->report_timer;

    printf("Anjan: signal received...\n");

    ev_feed_event(loop, report_timer, EV_TIMEOUT);
}

bool sm_neighbor_report_request(sm_stats_request_t *request)
{
    sm_neighbor_ctx_t             *neighbor_ctx = NULL;
    neighbor_ctx = &g_sm_neighbor_ctx;
    sm_stats_request_t          *request_ctx = &neighbor_ctx->request;
    neighbor_report_data_t        *report_ctx = &neighbor_ctx->report;
    ev_timer                    *report_timer = &neighbor_ctx->report_timer;
    ev_signal                   *ev_sigusr = &neighbor_ctx->ev_sig;

    if (NULL == request) {
        LOG(ERR, "Initializing neighbor reporting ""(Invalid request config)");
        return false;
    }

    /* Initialize global stats only once */
    if (!neighbor_ctx->initialized) {
        memset(request_ctx, 0, sizeof(*request_ctx));
        memset(report_ctx, 0, sizeof(*report_ctx));

        LOG(INFO, "Initializing neighbor reporting");

        ev_init(report_timer, sm_neighbor_report);
        report_timer->data = neighbor_ctx;

        ev_signal_init(ev_sigusr, sm_nlev_neighbor_handle_signal, SIGUSR2);
        ev_sigusr->data = neighbor_ctx;
        ev_signal_start(EV_DEFAULT, ev_sigusr);

        neighbor_ctx->initialized = true;
    }

    REQUEST_VAL_UPDATE("neighbor", reporting_count, "%d");
    REQUEST_VAL_UPDATE("neighbor", reporting_interval, "%d");
    REQUEST_VAL_UPDATE("neighbor", reporting_timestamp, "%"PRIu64"");

    sm_neighbor_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        neighbor_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        sm_neighbor_timer_set(report_timer, true);
        LOG(INFO, "Started neighbor reporting");
    }
    else {
        LOG(INFO, "Stopped neighbor reporting");
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}

