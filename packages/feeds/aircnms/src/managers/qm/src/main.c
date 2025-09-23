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
#include "qm.h"

bool qm_set_aircnms_param();
bool qm_check_valid_device_id();
bool qm_set_online_status();
bool qm_device_discovery_request();

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    
    log_open("QM",0);
   
    qm_set_aircnms_param();

    if (!qm_check_valid_device_id()) {
        if (!qm_device_discovery_request()) {
            LOG(ERR, "Cloud Registration Failed..");
            return -1;
        }
    } else {
        qm_set_online_status();
    }

    qm_mqtt_init();

    qm_event_init();

    ev_run(loop, 0);

    qm_mqtt_stop();
}
