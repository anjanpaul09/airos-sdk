#ifndef CGW_UCI_H_INCLUDED
#define CGW_UCI_H_INCLUDED
#include <stdbool.h>
#include "cgw.h"
typedef struct {
 const char *device_id, *network_id, *org_id, *username, *password, *broker, *port;
 const cgw_mqtt_topic_list *topics;
 const stats_topic_t *stats;
} cgw_enrollment_uci_t;
bool cgw_uci_commit_enrollment(const cgw_enrollment_uci_t *values);
#endif
