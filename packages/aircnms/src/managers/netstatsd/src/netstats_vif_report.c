#include <unistd.h>
#include <time.h>
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
bool target_stats_vif_get(vif_record_t *record);

#define MODULE_ID LOG_MODULE_ID_MAIN


/* new part VIF */
typedef struct
{
    bool                            initialized;

    /* Internal structure used to lower layer radio selection */
    ev_timer                        report_timer;

    netstats_request_t              request;

    /* Reporting start timestamp used for reporting timestamp calculation */
    uint64_t                        report_ts;
} netstats_vif_ctx_t;

static netstats_vif_ctx_t              g_netstats_vif_ctx;

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/


static
bool netstats_vif_report_timer_set(
        ev_timer                   *timer,
        bool                        enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    }
    else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}


static
bool netstats_vif_report_timer_restart(
        ev_timer                   *timer)
{
    netstats_vif_ctx_t                   *vif_ctx;
    netstats_request_t             *request_ctx;

    if (NULL == timer->data)
        return false;

    vif_ctx =
        (netstats_vif_ctx_t *) timer->data;

    request_ctx = &vif_ctx->request;

    if (request_ctx->reporting_count) {
        request_ctx->reporting_count--;

        LOG(DEBUG,
            "Vif reporting count=%d",
            request_ctx->reporting_count);

        /* If reporting_count becomes zero, then stop reporting */
        if (0 == request_ctx->reporting_count) {
            netstats_vif_report_timer_set(timer, false);

            LOG(DEBUG,
                "Stopped vif reporting (count expired)");
            return true;
        }
    }

    return true;
}


static
void netstats_vif_report(EV_P_ ev_timer *w, int revents)
{
    bool                           rc;

    netstats_vif_ctx_t                *vif_ctx =
        (netstats_vif_ctx_t *) w->data;
    netstats_request_t             *request_ctx =
        &vif_ctx->request;
    ev_timer                       *report_timer =
        &vif_ctx->report_timer;

    netstats_vif_report_timer_restart(report_timer);

    vif_report_data_t *report_ctx = calloc(1, sizeof(*report_ctx));
    if (!report_ctx) {
        LOG(ERR, "Failed to allocate vif_report_data_t");
        return;
    }

    /* Get vif stats */
    rc = target_stats_vif_get(&report_ctx->record);
    //rc = dummy_get_vif_report_data(&report_ctx->record);
    if (true != rc) {
        free(report_ctx);
        return;
    }

    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - vif_ctx->report_ts +
        get_timestamp();
    
    NETSTATS_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &vif_ctx->report_ts);

    /* Report_timestamp is base-timestamp + relative start time offset */
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - vif_ctx->report_ts +
        get_timestamp();

    LOG(INFO,
        "Sending vif report at '%s' n-vif '%d' n-radio '%d'",
        netstats_timestamp_ms_to_date(report_ctx->timestamp_ms), report_ctx->record.n_vif, 
        report_ctx->record.n_radio);

    netstats_put_vif(report_ctx);
    
    NETSTATS_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &vif_ctx->report_ts);

    free(report_ctx);
}

/******************************************************************************
 *  PUBLIC API definitions
 *****************************************************************************/

bool netstats_vif_report_request(
        netstats_request_t         *request)
{
    netstats_vif_ctx_t                   *vif_ctx =
        &g_netstats_vif_ctx;
    netstats_request_t             *request_ctx =
        &vif_ctx->request;
    ev_timer                       *report_timer =
        &vif_ctx->report_timer;


    if (NULL == request) {
        LOG(ERR,
            "Initializing vif reporting "
            "(Invalid request config)");
        return false;
    }

    /* Initialize global stats only once */
    if (!vif_ctx->initialized) {
        memset(request_ctx, 0, sizeof(*request_ctx));

        LOG(INFO,
            "Initializing vif reporting");

        /* Initialize event lib timers and pass the global
           internal cache
         */
        ev_init(report_timer, netstats_vif_report);
        report_timer->data = vif_ctx;
        
        vif_ctx->initialized = true;
    }

    /* Store and compare every request parameter ...
       memcpy would be easier but we want some debug info
     */
    REQUEST_VAL_UPDATE("vif", reporting_count, "%d");
    REQUEST_VAL_UPDATE("vif", reporting_interval, "%d");
    REQUEST_VAL_UPDATE("vif", reporting_timestamp, "%"PRIu64"");

    /* Restart timers with new parameters */
    netstats_vif_report_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        vif_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        netstats_vif_report_timer_set(report_timer, true);
        LOG(INFO, "Started vif reporting");
    }
    else {
        LOG(INFO, "Stopped vif reporting");
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}
