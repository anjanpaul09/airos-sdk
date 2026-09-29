#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "cgw_topic_route.h"

int main(void)
{
    char topics[16][CGW_ROUTE_TOPIC_LEN] = {{0}};
    int topic_count = 6;
    const char *rf = "{\"cmd\":\"rf_scan\"}";
    const char *not_rf = "{\"description\":\"cmd rf_scan\",\"cmd\":\"reboot\"}";

    strcpy(topics[0], "cloud/to/device/1/S/config");
    strcpy(topics[1], "cloud/to/device/1/S/cmd");
    strcpy(topics[2], "cloud/to/device/1/S/bw_list");
    strcpy(topics[3], "cloud/to/device/1/S/rate_limit");
    strcpy(topics[4], "cloud/to/device/broadcast");
    strcpy(topics[5], "cloud/to/device/org/net/config");

    assert(cgw_topic_route(topics, topic_count, topics[0]) == CGW_ROUTE_CONFIG);
    assert(cgw_topic_route(topics, topic_count, topics[1]) == CGW_ROUTE_COMMAND);
    assert(cgw_topic_route(topics, topic_count, topics[2]) == CGW_ROUTE_ACL);
    assert(cgw_topic_route(topics, topic_count, topics[3]) == CGW_ROUTE_RATE_LIMIT);
    assert(cgw_topic_route(topics, topic_count, topics[5]) == CGW_ROUTE_CONFIG);
    assert(cgw_topic_route(topics, topic_count, topics[4]) == CGW_ROUTE_REJECT);
    assert(cgw_topic_route(topics, topic_count, "cloud/to/device/1/S/config-evil") == CGW_ROUTE_REJECT);
    assert(cgw_topic_route(topics, topic_count, "evil/config") == CGW_ROUTE_REJECT);
    assert(cgw_payload_is_rf_scan(rf, strlen(rf)));
    assert(!cgw_payload_is_rf_scan(not_rf, strlen(not_rf)));
    assert(!cgw_payload_is_rf_scan("{\"cmd\":\"rf_scan\",\"cmd\":\"reboot\"}", strlen("{\"cmd\":\"rf_scan\",\"cmd\":\"reboot\"}")));
    assert(!cgw_payload_is_rf_scan("not-json", 8));
    puts("topic route: PASS");
    return 0;
}
