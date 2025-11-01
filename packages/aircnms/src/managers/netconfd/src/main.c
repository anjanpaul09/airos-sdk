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

#include "ds_tree.h"
#include "log.h"
#include "os.h"
#include "os_socket.h"
#include "os_backtrace.h"
#include "netconf.h"
#include "target.h"

// Forward declarations
extern bool target_init(target_init_opt_t opt, struct ev_loop *loop);
extern void target_close(target_init_opt_t opt, struct ev_loop *loop);

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    target_init(TARGET_INIT_MGR_SM, loop);

    log_open("NETCONF",0);

    set_intf_reset_progress_indication(NETCONF_INTF_RESET_STOP);

    netconf_ubus_service_init();
    // Initialize unixcomm server for async message handling
    if (!netconf_unixcomm_server_init()) {
        LOG(ERR, "NETCONF: Failed to initialize unixcomm server");
        return -1;
    }

    netconf_queue_init();

    netconf_dequeue_timer_init();

    ev_run(loop, 0);
        
    target_close(TARGET_INIT_MGR_SM, loop);
    netconf_unixcomm_server_cleanup();
    netconf_ubus_service_cleanup();

}
