#include <stdio.h>
#include <netev.h>

int nl80211_init(struct nl80211_state *state);
int listen_events(struct nl80211_state *state, const int n_waits, const __u32 *waits);

int main()
{
	struct nl80211_state nlstate;
	int ret = -1;

	/* start hostapd event listener (non-fatal if not present) */
	hostapd_events_start(NULL);

	ret = nl80211_init(&nlstate);

	listen_events(&nlstate, 0, 0);
	return ret;
}

