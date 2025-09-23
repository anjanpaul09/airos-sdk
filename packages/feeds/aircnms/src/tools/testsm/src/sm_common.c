#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "sm.h"
#include "os_time.h"
#include "log.h"


#define DIFF(a, b)    ((b >= a) ? (b - a) : (a - b))
#define MAX_DRIFT     (2000)  /* milliseconds */


void sm_sanity_check_report_timestamp(
        const char *log_prefix,
        uint64_t   timestamp_ms,  /* Report's timestamp (real time) to check. */
        uint64_t   *reporting_timestamp,  /* Base timestamp (real time) */
        uint64_t   *report_ts   /* Base timestamp (monotonic time) */
)
{
    uint64_t real_ms;
    uint64_t mono_ms;
    uint64_t diff_real_ms;

    real_ms = clock_real_ms();
    mono_ms = clock_mono_ms();

    diff_real_ms = DIFF(real_ms, timestamp_ms);
    if (diff_real_ms > MAX_DRIFT)
    {
        LOG(WARN, "%s: Report timestamp %"PRIu64" ms drifting for %"PRIu64" ms "
                  "from system wall clock. (Exceeding max drift %u ms). "
                  "Adjusting reporting's base timestamps. Effective with next report.",
                  log_prefix, timestamp_ms, diff_real_ms, MAX_DRIFT);

        *reporting_timestamp = real_ms;
        *report_ts = mono_ms;
    }
}

