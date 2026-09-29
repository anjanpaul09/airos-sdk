#ifndef NETCONF_SNAPSHOT_H
#define NETCONF_SNAPSHOT_H

#include <stdbool.h>

bool netconf_snapshot_create(const char *job_id);
bool netconf_snapshot_restore(const char *job_id);

#endif
