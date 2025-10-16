#include "ext_event.h"

void nl_ext_event_enqueue(int event, unsigned char *mac, char *ifname)
{
    sm_ext_event_t *nl = malloc(sizeof(sm_ext_event_t));
    if (!nl) {
    return;
    }

    nl->event = event;
    if (mac) {
    for (int i = 0; i < 6; i++) {
        nl->mac[i] = mac[i];
    }
    }

    if (ifname) {
        strncpy(nl->ifname, ifname, sizeof(nl->ifname) - 1);
        nl->ifname[sizeof(nl->ifname) - 1] = '\0'; // ensure null-termination
    }
    ds_dlist_insert_tail(&g_ext_event_list, nl);

    return;
}
