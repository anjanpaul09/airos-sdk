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

#include "sm.h"
//#include "../../../libs/datapipeline/inc/dpp_vif_stats.h"
bool target_stats_vif_get(vif_record_t *record);

#define MODULE_ID LOG_MODULE_ID_MAIN


/* new part VIF */
typedef struct
{
    bool                            initialized;

    /* Internal structure used to lower layer radio selection */
    ev_timer                        report_timer;

    /* Structure containing cloud request timer params */
    sm_stats_request_t              request;
    /* Structure pointing to upper layer device storage */
    vif_report_data_t               report;

    /* Reporting start timestamp used for reporting timestamp calculation */
    uint64_t                        report_ts;
} sm_vif_ctx_t;

static sm_vif_ctx_t              g_sm_vif_ctx;

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/


static
bool sm_vif_report_timer_set(
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
bool sm_vif_report_timer_restart(
        ev_timer                   *timer)
{
    sm_vif_ctx_t                   *vif_ctx;
    sm_stats_request_t             *request_ctx;
    //vif_entry_t                    *vif_cfg_ctx;

    if (NULL == timer->data)
        return false;

    vif_ctx =
        (sm_vif_ctx_t *) timer->data;

    request_ctx = &vif_ctx->request;

    if (request_ctx->reporting_count) {
        request_ctx->reporting_count--;

        LOG(DEBUG,
            "Vif reporting count=%d",
            request_ctx->reporting_count);

        /* If reporting_count becomes zero, then stop reporting */
        if (0 == request_ctx->reporting_count) {
            sm_vif_report_timer_set(timer, false);

            LOG(DEBUG,
                "Stopped vif reporting (count expired)");
            return true;
        }
    }

    return true;
}


static
void sm_vif_report(EV_P_ ev_timer *w, int revents)
{
    bool                           rc;

    sm_vif_ctx_t                *vif_ctx =
        (sm_vif_ctx_t *) w->data;
    vif_report_data_t           *report_ctx =
        &vif_ctx->report;
    sm_stats_request_t             *request_ctx =
        &vif_ctx->request;
    ev_timer                       *report_timer =
        &vif_ctx->report_timer;

    sm_vif_report_timer_restart(report_timer);

    /* Get vif stats */
    rc = target_stats_vif_get(&report_ctx->record);
    //rc = dummy_get_vif_report_data(&report_ctx->record);
    if (true != rc) {
        return;
    }

    /* Report_timestamp is base-timestamp + relative start time offset */
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - vif_ctx->report_ts +
        get_timestamp();
    
    SM_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &vif_ctx->report_ts);

    /* Report_timestamp is base-timestamp + relative start time offset */
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - vif_ctx->report_ts +
        get_timestamp();

    LOG(INFO,
        "Sending vif report at '%s' n-vif '%d' n-radio '%d'",
        sm_timestamp_ms_to_date(report_ctx->timestamp_ms), report_ctx->record.n_vif, 
        report_ctx->record.n_radio);

    sm_put_vif(report_ctx);

clean:
    SM_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &vif_ctx->report_ts);
}

/******************************************************************************
 *  PUBLIC API definitions
 *****************************************************************************/

bool sm_vif_report_request(
        sm_stats_request_t         *request)
{
    sm_vif_ctx_t                   *vif_ctx =
        &g_sm_vif_ctx;
    sm_stats_request_t             *request_ctx =
        &vif_ctx->request;
    vif_report_data_t              *report_ctx =
        &vif_ctx->report;
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
        memset(report_ctx, 0, sizeof(*report_ctx));

        LOG(INFO,
            "Initializing vif reporting");

        /* Initialize event lib timers and pass the global
           internal cache
         */
        ev_init(report_timer, sm_vif_report);
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
    sm_vif_report_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        vif_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        sm_vif_report_timer_set(report_timer, true);
        LOG(INFO, "Started vif reporting");
    }
    else {
        LOG(INFO, "Stopped vif reporting");
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}
