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

#include "sm.h"
#include "MT7621.h"

int reporting_interval = 30; 

char *sm_report_type_str[STS_REPORT_MAX] =
{
    "neighbor",
    "client",
    "device",
    "vif",
};

void sm_check_aircnms_interval()
{
    FILE *fp = popen("uci get aircnms.@aircnms[0].interval 2>/dev/null", "r");
    if (fp) {
        char buffer[16];

        if (fgets(buffer, sizeof(buffer), fp)) {
            // Remove newline character if present
            buffer[strcspn(buffer, "\n")] = '\0';

            // Check if the command returned an error message
            if (strncmp(buffer, "uci:", 4) != 0) {
                reporting_interval = atoi(buffer);  // Convert string to integer
            }
        }
        pclose(fp);
    }
    return;
}

bool sm_init_neighbor_stats_config()
{
    struct timespec                 ts;
    sm_stats_request_t              req;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&req, 0, sizeof(sm_stats_request_t));

    req.reporting_interval = SM_NEIGHBOR_REPORTING_INTERVAL;
    req.reporting_count = SM_NEIGHBOR_REPORTING_COUNT;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    sm_neighbor_report_request(&req);    
    return true;
}


bool sm_init_wifi_stats_config()
{
    struct timespec                 ts;
    sm_stats_request_t              req;
    radio_entry_t                   config;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&req, 0, sizeof(sm_stats_request_t));
    memset(&config, 0, sizeof(radio_entry_t));

    strcpy(config.if_name, "ra0");   // not needed as client stats are radio independent
    strcpy(config.phy_name, "ra0");  // not needed as client stats are radio independent
    config.type = RADIO_TYPE_2G;     // not needed as client stats are radio independent
    req.radio_type = RADIO_TYPE_2G;  // not needed as client stats are radio independent
    //req.reporting_interval = SM_DEVICE_REPORTING_INTERVAL;
    req.reporting_interval = reporting_interval;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    sm_client_report_request(&config, &req);
    
    return true;
}

bool sm_setup_monitor()
{  
    struct timespec         ts;
    sm_check_aircnms_interval();
    sm_stats_request_t req;

    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;
    memset(&req, 0, sizeof(req));

    //req.reporting_interval = SM_DEVICE_REPORTING_INTERVAL;
    req.reporting_interval = reporting_interval;
    req.reporting_count = 0;
    req.reporting_timestamp = timespec_to_timestamp(&ts);

    sm_device_report_request(&req);
    sm_vif_report_request(&req);
    sm_init_wifi_stats_config();

    return true;
}

bool sm_init_device_stats_send()
{
    device_report_data_t report_data;
    struct timespec                 ts;
    memset (&ts, 0, sizeof (ts));
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return false;

    memset(&report_data, 0, sizeof(report_data));
    report_data.timestamp_ms = timespec_to_timestamp(&ts);
    target_stats_device_get(&report_data.record);

    sm_put_device(&report_data);
    return true;
}
