#ifndef STAMONITORD_HISTORY_TYPES_H
#define STAMONITORD_HISTORY_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ds_tree.h"

typedef enum {
    TRAFFIC_OTHER = 0,
    TRAFFIC_DNS,
    TRAFFIC_HTTP,
    TRAFFIC_HTTPS,
    TRAFFIC_QUIC
} traffic_type_t;

typedef struct history_domain {
    ds_tree_node_t node;

    char domain[128];
    char service[64];
    char ndpi_protocol[64];

    traffic_type_t type;

    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t visits;
    uint64_t connections;

    uint64_t uploaded_reported;
    uint64_t downloaded_reported;
    uint64_t visits_reported;
    uint64_t connections_reported;

    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint64_t last_reported_ms;

    bool active;
} history_domain_t;

typedef struct history_state {
    uint64_t uploaded;
    uint64_t downloaded;

    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint64_t last_reported_ms;

    size_t domain_count;

    ds_tree_t domains;
} history_state_t;

static inline int history_domain_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

#endif
