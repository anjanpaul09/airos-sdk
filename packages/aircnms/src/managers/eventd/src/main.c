#include <stdio.h>
#include <ev.h>
#include <unistd.h>
#include "eventd.h"
#include "log.h"

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    log_open("EVENTD",0);

    // Initialize unixcomm server for async message handling
    if (eventd_lib_init() != 0) {
        LOG(ERR, "EVENTD: Failed to initialize libeventd ubus");
        return -1;
    }

    //usleep(8000000); // 8 seconds
    //check_and_send_reboot_alarm();
    
    if (ubus_alarm_init(loop) < 0) {
        LOG(ERR, "Initializing EVENTD ""(Failed to start UBUS ALARM)");
        return -1;
    }

    printf("Ankit: eventd running \n");
    ev_run(loop, 0);

    ubus_alarm_cleanup(loop);
    ev_default_destroy();
    eventd_lib_cleanup();
    
    return 0;
}

