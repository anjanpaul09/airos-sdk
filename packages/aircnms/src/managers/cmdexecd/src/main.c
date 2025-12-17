#include <stdio.h>
#include <cmdexec.h>
#include "log.h"

int main()
{
    // Initialize unixcomm server for async message handling
    if (!cmdexec_ubus_tx_service_init()) {
        LOG(ERR, "CMDEXEC: Failed to initialize ubus server");
        return -1;
    }

    if (check_fw_upgrade_status()) {
        LOG(INFO, "%s: CMDEXEC fw upgrade status sending", __func__);
        cmdexec_send_event_to_cloud(UPGRADE, UPGRADED, NULL, NULL);
        set_fw_upgrade_status_to_aircnms(UPGRADED);
    }
    
    if (!cmdexec_ubus_rx_service_init()) {
        LOG(ERR, "CMDEXEC: Failed to initialize ubus server");
        return -1;
    }
    
    cmdexec_queue_init();

    cmdexec_dequeue_timer_init();

    printf("Ankit: cmdexec running \n");
    ev_run(EV_DEFAULT, 0);

    ev_default_destroy();
    cmdexec_ubus_tx_service_cleanup();
    cmdexec_ubus_rx_service_cleanup();
    return 0;
}

