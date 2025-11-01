#include <stdio.h>
#include <netev.h>
#include "log.h"

int main()
{
    // Initialize unixcomm server for async message handling
    if (!netev_ubus_tx_service_init()) {
        LOG(ERR, "CMDEXEC: Failed to initialize ubus server");
        return -1;
    }
    
    if (!netev_monitor_init()) {
        LOG(ERR, "Initializing DM ""(Failed to start MQTT)");
        return -1;
    }

    printf("Ankit: netev running \n");
    ev_run(EV_DEFAULT, 0);

    ev_default_destroy();
    netev_ubus_tx_service_cleanup();
    return 0;
}

