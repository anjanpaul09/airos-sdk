#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

#include "os.h"
#include "log.h"
#include "memutil.h"

#include "netstats.h"
#include "target.h"
#include "MT7621.h"

int reporting_interval = 30; 

void netstats_check_aircnms_interval()
{
    FILE *fp = popen("uci get aircnms.@aircnms[0].interval 2>/dev/null", "r");
    if (fp) {
        char buffer[16];

        if (fgets(buffer, sizeof(buffer), fp)) {
            // Remove newline character if present
            buffer[strcspn(buffer, "\n")] = '\0';

            // Check if the command returned an error message
            if (strncmp(buffer, "uci:", 4) != 0) {
                int parsed_interval = atoi(buffer);
                if (parsed_interval > 0) {
                    reporting_interval = parsed_interval;
                }
            }
        }
        int pclose_ret = pclose(fp);
        if (pclose_ret != 0) {
            LOG(ERR, "pclose failed with exit code %d", pclose_ret);
        }
    }
    return;
}

bool netstats_init_neighbor_stats()
{
    struct timespec                 ts;
    netstats_request_t              req;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&req, 0, sizeof(netstats_request_t));

    req.reporting_interval = SM_NEIGHBOR_REPORTING_INTERVAL;
    req.reporting_count = SM_NEIGHBOR_REPORTING_COUNT;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    netstats_neighbor_report_request(&req);    
    return true;
}


bool netstats_init_wifi_stats()
{
    struct timespec                 ts;
    netstats_request_t              req;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&req, 0, sizeof(netstats_request_t));

    req.reporting_interval = reporting_interval;
    req.reporting_count = 0;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    netstats_client_report_request(&req);
    
    return true;
}

bool netstats_initiate_stats()
{  
    struct timespec         ts;
    netstats_check_aircnms_interval();
    netstats_request_t req;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;
    memset(&req, 0, sizeof(req));

    req.reporting_interval = reporting_interval;
    req.reporting_count = 0;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    netstats_device_report_request(&req);
    netstats_vif_report_request(&req);
    netstats_init_wifi_stats();

    return true;
}

bool netstats_init_device_stats_send()
{
    device_report_data_t report_data;
    struct timespec                 ts;
    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&report_data, 0, sizeof(report_data));
    report_data.timestamp_ms = timespec_to_timestamp(&ts);
    target_stats_device_get(&report_data.record);

    netstats_put_device(&report_data);
    return true;
}
