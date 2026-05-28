#ifndef STAMONITORD_CLIENT_CAP_H
#define STAMONITORD_CLIENT_CAP_H

#include "stamonitord_info_events.h"   // where client_info_event_t is defined

int get_client_capability(const char *ifname, client_info_event_t *client_info);

#endif

