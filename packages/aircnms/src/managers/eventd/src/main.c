#include <stdio.h>
#include <ev.h>
#include "eventd.h"
#include "log.h"

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    log_open("EVENTD",0);

    // Initialize unixcomm server for async message handling
    if (!eventd_ubus_tx_service_init()) {
        LOG(ERR, "EVENTD: Failed to initialize ubus server");
        return -1;
    }
    
    if (ubus_alarm_init(loop) < 0) {
        LOG(ERR, "Initializing EVENTD ""(Failed to start UBUS ALARM)");
        return -1;
    }

    printf("Ankit: eventd running \n");
    ev_run(loop, 0);

    ubus_alarm_cleanup(loop);
    ev_default_destroy();
    eventd_ubus_tx_service_cleanup();
    
    return 0;
}

