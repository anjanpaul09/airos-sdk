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

int target_stats_device_get(device_record_t *device_entry);
#define MODULE_ID LOG_MODULE_ID_MAIN

#define DEVICE_THERMAL_TIMER_SEC                60

/* new part */
typedef struct
{
    bool                            initialized;
    ev_timer                        report_timer;
    netstats_request_t        request;
    uint64_t                        report_ts;
} netstats_device_ctx_t;

static netstats_device_ctx_t              g_netstats_device_ctx;

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/
static
bool netstats_device_report_timer_set(
        ev_timer                   *timer,
        bool                        enable)
{
    if (enable) {
        ev_timer_again(EV_DEFAULT, timer);
    } else {
        ev_timer_stop(EV_DEFAULT, timer);
    }

    return true;
}


static
bool netstats_device_report_timer_restart(
        ev_timer                   *timer)
{
    netstats_device_ctx_t                *device_ctx =
        (netstats_device_ctx_t *) timer->data;
    netstats_request_t             *request_ctx =
        &device_ctx->request;

    if (request_ctx->reporting_count) {
        request_ctx->reporting_count--;

        LOG(DEBUG,
            "Updated device reporting count=%d",
            request_ctx->reporting_count);

        /* If reporting_count becomes zero, then stop reporting */
        if (0 == request_ctx->reporting_count) {
            netstats_device_report_timer_set(timer, false);

            LOG(DEBUG,
                "Stopped device reporting (count expired)");
            return true;
        }
    }

    return true;
}


int fill_dummy_device_report(device_report_data_t *report) 
{
    if (!report) return false;

    memset(report, 0, sizeof(device_report_data_t));

    // Fill timestamp
    //struct timespec ts;
    //clock_gettime(CLOCK_REALTIME, &ts);
    //report->timestamp_ms = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;

    // Dummy Load averages
    report->record.load[0] = 0.5;
    report->record.load[1] = 1.2;
    report->record.load[2] = 2.3;

    // Dummy Uptime
    report->record.uptime = 123456; // Example uptime in seconds

    // Dummy Memory utilization
    report->record.mem_util.mem_total = 2048000; // 2 GB
    report->record.mem_util.mem_used = 1024000; // 1 GB
    report->record.mem_util.swap_total = 102400; // 100 MB
    report->record.mem_util.swap_used = 51200;  // 50 MB

    // Dummy CPU utilization
    report->record.cpu_util.cpu_util = 25; // 25%

    // Dummy Filesystem utilization
    report->record.fs_util[0].fs_type = 0; // Root FS
    report->record.fs_util[0].fs_total = 512000; // 500 MB
    report->record.fs_util[0].fs_used = 256000; // 250 MB

    report->record.fs_util[1].fs_type = 1; // Temp FS
    report->record.fs_util[1].fs_total = 102400; // 100 MB
    report->record.fs_util[1].fs_used = 51200;  // 50 MB
    
    return true;
}


static
void netstats_device_report(EV_P_ ev_timer *w, int revents)
{
    bool                           rc;

    netstats_device_ctx_t                *device_ctx = (netstats_device_ctx_t *) w->data;
    netstats_request_t             *request_ctx = &device_ctx->request;
    ev_timer                       *report_timer = &device_ctx->report_timer;

    netstats_device_report_timer_restart(report_timer);

    device_report_data_t *report_ctx = calloc(1, sizeof(*report_ctx));
    if (!report_ctx) {
        LOG(ERR, "Failed to allocate device_report_data_t");
        return;
    }

    /* Get device stats */
    rc = target_stats_device_get(&report_ctx->record);
    if (true != rc) {
        free(report_ctx);
        return;
    }

    LOG(DEBUG,
        "Sending device stats load %0.2f %0.2f %0.2f\n",
        report_ctx->record.load[DEVICE_LOAD_AVG_ONE],
        report_ctx->record.load[DEVICE_LOAD_AVG_FIVE],
        report_ctx->record.load[DEVICE_LOAD_AVG_FIFTEEN]);

    /* Report_timestamp is base-timestamp + relative start time offset */
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - device_ctx->report_ts +
        get_timestamp();
    
    NETSTATS_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &device_ctx->report_ts);

    LOG(INFO,
        "uptime=%u, mem=%u/%u, cpu=%u",
        report_ctx->record.uptime,
        report_ctx->record.mem_util.mem_used,
        report_ctx->record.mem_util.mem_total,
        report_ctx->record.cpu_util.cpu_util);
    
    report_ctx->timestamp_ms =
        request_ctx->reporting_timestamp - device_ctx->report_ts +
        get_timestamp();

    LOG(INFO,
        "Sending device report at '%s'",
        netstats_timestamp_ms_to_date(report_ctx->timestamp_ms));

    netstats_put_device(report_ctx);

    NETSTATS_SANITY_CHECK_TIME(report_ctx->timestamp_ms,
                         &request_ctx->reporting_timestamp,
                         &device_ctx->report_ts);

    free(report_ctx);
}


/******************************************************************************
 *  PUBLIC API definitions
 *****************************************************************************/
bool netstats_device_report_request(netstats_request_t *request)
{
    netstats_device_ctx_t                *device_ctx = &g_netstats_device_ctx;
    netstats_request_t             *request_ctx = &device_ctx->request;
    ev_timer                       *report_timer = &device_ctx->report_timer;

    if (NULL == request) {
        LOG(ERR, "Initializing device reporting " "(Invalid request config)");
        return false;
    }

    if (!device_ctx->initialized) {
        memset(request_ctx, 0, sizeof(*request_ctx));

        LOG(INFO, "Initializing device reporting");

        ev_init(report_timer, netstats_device_report);
        report_timer->data = device_ctx;
        
        device_ctx->initialized = true;
    }

    REQUEST_VAL_UPDATE("device", reporting_count, "%d");
    REQUEST_VAL_UPDATE("device", reporting_interval, "%d");
    REQUEST_VAL_UPDATE("device", reporting_timestamp, "%"PRIu64"");

    /* Restart timers with new parameters */
    netstats_device_report_timer_set(report_timer, false);

    if (request_ctx->reporting_interval) {
        device_ctx->report_ts = get_timestamp();
        report_timer->repeat = request_ctx->reporting_interval == -1 ? 1 : request_ctx->reporting_interval;

        netstats_device_report_timer_set(report_timer, true);
        LOG(INFO, "Started device reporting");
    }
    else {
        LOG(INFO, "Stopped device reporting");
        memset(request_ctx, 0, sizeof(*request_ctx));
    }

    return true;
}
