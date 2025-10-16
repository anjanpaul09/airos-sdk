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
#include "cm.h"
#include "target.h"

int main()
{
    int rc;
    struct ev_loop *loop = EV_DEFAULT;
    rc = target_init(TARGET_INIT_MGR_SM, loop);

    log_open("CM",0);

    set_intf_reset_progress_indication(CM_INTF_RESET_STOP);

    // Initialize unixcomm server for async message handling
    if (!cm_unixcomm_server_init()) {
        LOG(ERR, "CM: Failed to initialize unixcomm server");
        return -1;
    }

    cm_event_init();

    cm_dequeue_timer_init();

    ev_run(loop, 0);
        
    target_close(TARGET_INIT_MGR_SM, loop);
    cm_unixcomm_server_cleanup();

}
