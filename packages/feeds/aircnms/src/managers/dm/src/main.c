#include <stdio.h>
#include <dm.h>
#include "log.h"

int main()
{
    if (check_fw_upgrade_status()) {
        LOG(INFO, "%s: DM fw upgrade status sending", __func__);
        dm_send_event_to_cloud(UPGRADE, UPGRADED, NULL, NULL);
        set_fw_upgrade_status_to_aircnms(UPGRADED);
    }
    
    if (!dm_mqtt_init()) {
        LOG(ERR, "Initializing DM ""(Failed to start MQTT)");
        return -1;
    }
    
    dm_event_init();

    dm_dequeue_timer_init();

    ev_run(EV_DEFAULT, 0);

    ev_default_destroy();
    return 0;
}

