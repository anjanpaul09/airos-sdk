#include <stdio.h>
#include "cmdexec.h"
#include "log.h"

int main()
{
    log_open("CMDEXECD",0);
    // Initialize unixcomm server for async message handling
    if (!cmdexec_ubus_tx_service_init()) {
        LOG(ERR, "CMDEXEC: Failed to initialize ubus server");
        return -1;
    }

    int ret = check_and_send_fw_upgrade_status();
    if (ret != 0) {
        LOG(ERR, "Upgrade status reporting failed: %d", ret);
        return -1;
    }

    if (!cmdexec_ubus_rx_service_init()) {
        LOG(ERR, "CMDEXEC: Failed to initialize ubus server");
        return -1;
    }
    
    cmdexec_queue_init();

    cmdexec_dequeue_timer_init();

    LOG(INFO, "CMDEXEC: running");
    ev_run(EV_DEFAULT, 0);

    ev_default_destroy();
    cmdexec_ubus_tx_service_cleanup();
    cmdexec_ubus_rx_service_cleanup();
    return 0;
}

