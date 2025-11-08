#ifndef NETEVD_NETEV_H
#define NETEVD_NETEV_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

int nl80211_init(struct nl80211_state *state);
int listen_events(struct nl80211_state *state, const int n_waits, const __u32 *waits);

/* hostapd event listener */
int hostapd_events_start(const char *ctrl_dir);
void hostapd_events_stop(void);

#endif /* NETEVD_NETEV_H */

