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
#include <signal.h>
#include "cgw.h"
#include "cgw_state_mgr.h"
#include "log.h"

static ev_signal signal_watcher;
static struct ev_loop *g_loop = NULL;

static void sigterm_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    LOG(INFO, "Received SIGTERM, shutting down...");

    air_set_online_status(0);
    ev_break(loop, EVBREAK_ALL);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    (void)argc;
    (void)argv;
    
    g_loop = EV_DEFAULT;

    ev_signal_init(&signal_watcher, sigterm_cb, SIGTERM);
    ev_signal_start(g_loop, &signal_watcher);

    log_open("CGWD", 0);
    air_set_online_status(0);

    if (!cgw_params_init()) {
        LOG(ERR, "Failed to initialize gateway parameters");
        ret = -1;
        goto cleanup;
    }

    if (!cgw_ubus_rx_service_init()) {
        LOG(ERR, "Failed to initialize UBUS RX service");
        ret = -1;
        goto cleanup_params;
    }

    if (!cgw_ubus_service_init()) {
        LOG(ERR, "Failed to initialize UBUS service");
        ret = -1;
        goto cleanup_ubus_rx;
    }

    if (!device_state_init()) {
        LOG(ERR, "Failed to initialize device state");
        ret = -1;
        goto cleanup_ubus;
    }

    ev_run(g_loop, 0);
    
cleanup_ubus:
    cgw_ubus_service_cleanup();
cleanup_ubus_rx:
    cgw_ubus_rx_service_cleanup();
cleanup_params:
    // No cleanup needed for cgw_params_init
cleanup:
    ws_cleanup();
    cgw_mqtt_stop_worker();
    cgw_mqtt_stop();
    LOG(INFO, "CGWD shutting down");
    return ret;
}
