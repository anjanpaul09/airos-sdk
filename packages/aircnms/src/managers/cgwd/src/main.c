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

static volatile sig_atomic_t g_running = 1;
static struct ev_loop *g_loop = NULL;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_loop) {
        ev_break(g_loop, EVBREAK_ALL);
    }
}

int main(int argc, char *argv[])
{
    int ret = 0;
    (void)argc;
    (void)argv;

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to prevent crashes
    
    g_loop = EV_DEFAULT;
    log_open("CGWD", 0);

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

#if 0
    printf("Ankit:1 \n");
    if (!cgw_mqtt_init()) {
        LOG(ERR, "Failed to initialize MQTT");
        ret = -1;
        goto cleanup_device_state;
    }
    printf("Ankit:2 \n");

    cgw_queue_init();
    printf("Ankit:3 \n");
    
    if (!cgw_mqtt_start_worker()) {
        LOG(ERR, "Failed to start MQTT worker");
        ret = -1;
        goto cleanup_mqtt;
    }
    printf("Ankit:4 \n");
#endif
    
    ev_run(g_loop, 0);
    
//cleanup_mqtt:
  //  cgw_mqtt_stop_worker();
  //  cgw_mqtt_stop();
//cleanup_device_state:
  //  device_state_deinit();
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
