#ifndef CGW_TYPES_H
#define CGW_TYPES_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_TOPICS 16
#define MAX_TOPIC_LEN 256

typedef struct {
    char topic[MAX_TOPICS][MAX_TOPIC_LEN];
    int n_topic;
} cgw_mqtt_topic_list;

typedef struct {
    char device[64];
    char vif[64];
    char client[64];
    char neighbor[64];
    char config[64];
    char cmdr[64];
} stats_topic_t;

#endif
