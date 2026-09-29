#ifndef CGW_TOPIC_ROUTE_H
#define CGW_TOPIC_ROUTE_H

#include <stdbool.h>
#include <stddef.h>

#define CGW_ROUTE_TOPIC_LEN 264

typedef enum {
    CGW_ROUTE_REJECT = 0,
    CGW_ROUTE_CONFIG,
    CGW_ROUTE_COMMAND,
    CGW_ROUTE_ACL,
    CGW_ROUTE_RATE_LIMIT
} cgw_topic_route_t;

cgw_topic_route_t cgw_topic_route(const char topics[][CGW_ROUTE_TOPIC_LEN],
                                  int topic_count, const char *topic);
bool cgw_payload_is_rf_scan(const void *payload, size_t payload_len);
const char *cgw_topic_route_string(cgw_topic_route_t route);

#endif
