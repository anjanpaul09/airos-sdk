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
#include "sm.h"

#include "target.h"

bool sm_setup_monitor();
bool sm_init_device_stats_send();
bool sm_mqtt_init(void);
bool sm_check_wifi_config(void); 
bool sm_nl_event_monitor(void);
bool sm_rx_event_init();
bool sm_dequeue_timer_init();

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    bool rc;
    (void)loop;

    log_open("SM",0);

    rc = target_init(TARGET_INIT_MGR_SM, loop);
    if (true != rc) {
        LOG(ERR, "Initializing SM ""(Failed to init target library)");
        return -1;
    }


    if (!sm_mqtt_init()) {
        LOG(ERR, "Initializing SM ""(Failed to start MQTT)");
        return -1;
    }
    
#ifdef CONFIG_PLATFORM_MTK_JEDI
    if (!sm_check_wifi_config()) {
        LOG(ERR, "Initializing SM ""(Failed to check wifi config)");
        return -1;
    }
#endif 

    if (!sm_init_device_stats_send()) {
        LOG(ERR, "Initializing SM ""(Failed to start stats monitor)");
        return -1;
    }
    
    if (!sm_setup_monitor()) {
        LOG(ERR, "Initializing SM ""(Failed to start stats monitor)");
        return -1;
    }

    if (!sm_nl_event_monitor()) {
        LOG(ERR, "Initializing SM ""(Failed to nl event)");
        return -1;
    }
   
    if (!sm_rx_event_init()) {
        return -1;
    }

    if (!sm_dequeue_timer_init()) {
        return -1;
    }

    ev_run(EV_DEFAULT, 0);
    ev_default_destroy();

    target_close(TARGET_INIT_MGR_SM, loop);

    LOGN("Exiting SM");

    return 0;
}
