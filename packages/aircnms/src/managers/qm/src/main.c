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
#include "qm_device_state.h"

bool qm_set_aircnms_param();
bool qm_check_valid_device_id();
bool qm_set_online_status();
bool qm_device_discovery_request();

int main(void)
{
    struct ev_loop *loop = EV_DEFAULT;

    log_open("QM", 0);
    qm_set_aircnms_param();

    // Initialize the global device state system
    device_state_init();

    // Start the event loop (libev handles async events)
    ev_run(loop, 0);

    // Cleanup before exit
    ws_cleanup();
    qm_unixcomm_server_cleanup();
    qm_mqtt_stop_worker();
    qm_mqtt_stop();
    device_state_deinit();

    return 0;
}
