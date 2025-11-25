#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <ev.h>
#include <syslog.h>
#include <getopt.h>

#include "log.h"
#include "os.h"
#include "netstats.h"
#include "target.h"

// Forward declarations from target library
extern bool target_init(target_init_opt_t opt, struct ev_loop *loop);
extern void target_close(target_init_opt_t opt, struct ev_loop *loop);
extern int target_stats_device_get(device_record_t *device_entry);

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    bool rc;
    (void)loop;

    log_open("NETSTATS",0);

    rc = target_init(TARGET_INIT_MGR_SM, loop);
    if (true != rc) {
        LOG(ERR, "Initializing NETSTATS ""(Failed to init target library)");
        return -1;
    }

    netstats_queue_init();

    if (!netstats_initiate_stats()) {
        LOG(ERR, "Initializing NETSTATS ""(Failed to init STATS)");
        return -1;
    }
    
    if (!netstats_ubus_service_init()) {
        LOG(ERR, "Initializing NETSTATS ""(Failed to start ubus service)");
        return -1;
    }

#if 0 
    if (!netstats_nl_event_monitor()) {
        LOG(ERR, "Initializing NETSTATS""(Failed to nl event)");
        return -1;
    }
#endif

    if (!netstats_dequeue_timer_init()) {
        return -1;
    }
    if (!netstats_init_device_stats_send()) {  //to show device online readily
        LOG(ERR, "Initializing SM ""(Failed to start stats monitor)");
        return -1;
    }
    ev_run(EV_DEFAULT, 0);

    ev_default_destroy();
    netstats_ubus_service_cleanup();
    target_close(TARGET_INIT_MGR_SM, loop);

    LOGN("Exiting NETSTATS");

    return 0;
}
