#include <stdio.h>
#include <netev.h>
#include "netev_ubus_tx.h"
#include "netev_vif_info.h"
#include "log.h"
#include "dhcp_fp.h"

int nl80211_init(struct nl80211_state *state);
int listen_events(struct nl80211_state *state, const int n_waits, const __u32 *waits);

int main()
{
	struct nl80211_state nlstate;
	int ret = -1;
        
        //dhcp_fp_init();
	/* Initialize ubus TX service for sending info events to cgwd */
	if (!netev_ubus_tx_service_init()) {
		LOG(ERR, "Failed to initialize ubus TX service");
		return -1;
	}

	/* Send VIF info event on startup */
	netev_send_vif_info();

	/* start hostapd event listener (non-fatal if not present) */
	hostapd_events_start(NULL);

	ret = nl80211_init(&nlstate);

	listen_events(&nlstate, 0, 0);
	
	/* Cleanup */
	netev_ubus_tx_service_cleanup();
	
	return ret;
}

