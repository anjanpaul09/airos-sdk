#include <stdio.h>
#include <ev.h>
#include "stamonitord_history.h"
#include "stamonitord.h"
#include "stamonitord_ubus_tx.h"
#include "stamonitord_vif_info.h"
#include "stamonitord_device_info.h"
#include "stamonitord_nl80211.h"
#include "log.h"
#include "dhcp_fp.h"

int wireless_monitor_init(void);
void wireless_monitor_stop(void);

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    (void)loop;
    int ret = -1;
    log_open("STAMONITORD",0);

    /* Initialize ubus TX service for sending info events to cgwd */
    if (!stamonitord_ubus_tx_service_init()) {
        LOG(ERR, "Failed to initialize ubus TX service");
    	return -1;
    }

    if (!stamonitord_monitor_device_info()) {
        LOG(ERR, "Initializing DM ""(Failed to start MQTT)");
        goto cleanup;
    }
    
    if (wireless_monitor_init() != 0) {
        return -1;
    }

    /* Send VIF info event on startup */
	stamonitord_send_vif_info();
    
    /* Start nl80211 generic netlink listener for station connect/disconnect events */
    if (stamonitord_nl80211_start(loop) < 0) {
        LOG(WARN, "nl80211 listener not started (may not be available)");
    }
    
    if (stamonitord_history_start(loop) < 0) {
        fprintf(stderr, "failed to start ap history\n");
        goto cleanup;
    }

    ev_run(EV_DEFAULT, 0);


cleanup:
	/* Cleanup */
    stamonitord_cleanup_vif_timer();
    stamonitord_history_stop();
    stamonitord_nl80211_stop();
    wireless_monitor_stop();
	stamonitord_ubus_tx_service_cleanup();
	
	return ret;
}

