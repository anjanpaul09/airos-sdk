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

    //read_setjson_and_process();

    cm_event_init();

    cm_dequeue_timer_init();

    ev_run(loop, 0);
        
    target_close(TARGET_INIT_MGR_SM, loop);

}
