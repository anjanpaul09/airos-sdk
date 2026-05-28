#ifndef STAMONITORD_CLIENT_EVENTS_H
#define STAMONITORD_CLIENT_EVENTS_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <ev.h>

#include "ds_tree.h"
#include "stamonitord_history_types.h"
#include "stamonitord_info_events.h"

typedef struct client_state {
    ds_tree_node_t node;

    uint8_t mac[6];

    bool connected;
    uint64_t disconnected_ms;

    char ifname[IFNAMSIZ];

    client_info_event_t info;

    bool metadata_complete;

    int metadata_retry_count;

    ev_timer metadata_timer;

    history_state_t history;
} client_state_t;

extern ds_tree_t g_client_tree;

client_state_t *stamonitord_client_lookup(const uint8_t *macaddr);
void stamonitord_client_history_free(client_state_t *client);

/* Handle client connect event */
void stamonitord_handle_client_connect(const uint8_t *macaddr, const char *ifname);

/* Handle client disconnect event */
void stamonitord_handle_client_disconnect(const uint8_t *macaddr, const char *ifname);

#endif // STAMONITORD_CLIENT_EVENTS_H
