#include <stdio.h>
#include <string.h>
#include "ds_dlist.h"

typedef struct
{
    int                event;
    uint8_t            mac[6];
    char               ifname[16];
    ds_dlist_node_t    node;
} sm_ext_event_t;

extern ds_dlist_t g_ext_event_list;

void nl_ext_event_enqueue(int event, unsigned char *mac, char *ifname);
