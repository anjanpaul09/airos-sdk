#include <stdio.h>
#include "netev.h"
#include "netev_ubus_tx.h"
#include "netev_vif_info.h"
#include "netev_device_info.h"
#include "log.h"
#include "dhcp_fp.h"

int nl80211_init(void);
void nl80211_cleanup(void);
void hostapd_events_stop(void);

int main()
{
    struct ev_loop *loop = EV_DEFAULT;
    (void)loop;
    int ret = -1;
    log_open("NETEVD",0);
        
    /* Initialize ubus TX service for sending info events to cgwd */
    if (!netev_ubus_tx_service_init()) {
        LOG(ERR, "Failed to initialize ubus TX service");
	return -1;
    }

    if (!netev_monitor_device_info()) {
        LOG(ERR, "Initializing DM ""(Failed to start MQTT)");
        return -1;
    }
	
    /* Send VIF info event on startup */
	netev_send_vif_info();
 
    ret = nl80211_init();
    if (ret) {
        LOG(ERR, "Failed to initialize nl80211: %d", ret);
        goto cleanup;
    }

	/* start hostapd event listener (non-fatal if not present) */
	hostapd_events_start(NULL);

    ev_run(EV_DEFAULT, 0);

    hostapd_events_stop();

cleanup:
	/* Cleanup */
        nl80211_cleanup();
	netev_ubus_tx_service_cleanup();
	
	return ret;
}

