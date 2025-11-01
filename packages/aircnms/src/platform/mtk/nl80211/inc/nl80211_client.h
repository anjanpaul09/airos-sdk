#ifndef NL80211_CLIENT_H_INCLUDED
#define NL80211_CLIENT_H_INCLUDED

#include <stats_report.h>

bool nl80211_stats_clients_get(
        client_report_data_t *client_list
);

#endif /* NL80211_CLIENT_H_INCLUDED */
