#include "stamonitord_history_internal.h"

/* paste Flow table section */

/* ------------------------------------------------------------------------- */
/* Flow table                                                                */
/* ------------------------------------------------------------------------- */

void flow_key_set_ip4(uint8_t out[16], uint32_t ip) {
    memset(out, 0, 16);
    memcpy(out + 12, &ip, 4);
}

void flow_key_set_ip6(uint8_t out[16], const uint8_t ip6[16]) {
    memcpy(out, ip6, 16);
}

int ip16_cmp(const uint8_t a[16], const uint8_t b[16]) {
    return memcmp(a, b, 16);
}

void normalize_flow_key(flow_key_t *k) {
    bool swap = false;

    int c = ip16_cmp(k->a_ip, k->b_ip);

    if (c > 0) {
        swap = true;
    } else if (c == 0 && ntohs(k->a_port) > ntohs(k->b_port)) {
        swap = true;
    }

    if (swap) {
        uint8_t ip[16];

        memcpy(ip, k->a_ip, 16);
        memcpy(k->a_ip, k->b_ip, 16);
        memcpy(k->b_ip, ip, 16);

        uint16_t port = k->a_port;
        k->a_port = k->b_port;
        k->b_port = port;
    }
}

void flow_free(flow_t *f) {
    if (!f)
        return;

    free(f);
}

bool traffic_type_needs_ndpi(traffic_type_t type) {
    return type == TRAFFIC_HTTPS ||
           type == TRAFFIC_QUIC;
}

flow_t *flow_get_or_create(app_t *app,
                           const parsed_pkt_t *pp,
                           mac_addr_t station_mac,
                           uint32_t station_ip,
                           const char *domain,
                           traffic_type_t type,
                           bool *is_new)
{
    flow_key_t key;

    memset(&key, 0, sizeof(key));

    key.ip_version = pp->ip_version;
    key.proto = pp->proto;
    key.a_port = pp->sport;
    key.b_port = pp->dport;

    if (pp->ip_version == 4) {

        flow_key_set_ip4(key.a_ip, pp->ip_src);
        flow_key_set_ip4(key.b_ip, pp->ip_dst);

    } else if (pp->ip_version == 6) {

        flow_key_set_ip6(key.a_ip, pp->ip6_src);
        flow_key_set_ip6(key.b_ip, pp->ip6_dst);

    } else {
        return NULL;
    }

    /*
     * IMPORTANT:
     *
     * Do NOT normalize flow key.
     *
     * We must preserve direction:
     *
     *   upload   STA -> SERVER
     *   download SERVER -> STA
     *
     * Hybrid bridge/AP capture requires directional flow ownership.
     */

    uint32_t h =
        hash_bytes(&key, sizeof(key)) % FLOW_BUCKETS;

    uint64_t t = now_ms();

    for (flow_t *f = app->flows[h];
         f;
         f = f->next)
    {
        /*
         * Forward-direction match.
         */
        bool forward =
            (f->key.ip_version == key.ip_version &&
             f->key.proto == key.proto &&
             !memcmp(f->key.a_ip, key.a_ip, 16) &&
             !memcmp(f->key.b_ip, key.b_ip, 16) &&
             f->key.a_port == key.a_port &&
             f->key.b_port == key.b_port);

        /*
         * Reverse-direction match.
         */
        bool reverse =
            (f->key.ip_version == key.ip_version &&
             f->key.proto == key.proto &&
             !memcmp(f->key.a_ip, key.b_ip, 16) &&
             !memcmp(f->key.b_ip, key.a_ip, 16) &&
             f->key.a_port == key.b_port &&
             f->key.b_port == key.a_port);

        if (!forward && !reverse)
            continue;

        f->last_seen_ms = t;

        /*
         * Preserve first useful domain learned.
         */
        if (domain &&
            valid_domain_for_history(domain) &&
            (!f->domain[0] ||
             !strcmp(f->domain, "unknown")))
        {
            snprintf(f->domain,
                     sizeof(f->domain),
                     "%s",
                     domain);
        }

        /*
         * Upgrade traffic classification.
         */
        if (f->type == TRAFFIC_OTHER &&
            type != TRAFFIC_OTHER)
        {
            f->type = type;
        }

        /*
         * Preserve station ownership.
         */
        if (mac_is_zero(f->station_mac) &&
            !mac_is_zero(station_mac))
        {
            f->station_mac = station_mac;
        }

        if (f->station_ip == 0 &&
            station_ip != 0)
        {
            f->station_ip = station_ip;
        }

        if (is_new)
            *is_new = false;

        return f;
    }

    /*
     * Create new flow.
     */
    flow_t *f = calloc(1, sizeof(*f));
    if (!f)
        return NULL;

    f->key = key;

    f->station_mac = station_mac;
    f->station_ip = station_ip;

    f->type = type;

    f->first_seen_ms = t;
    f->last_seen_ms = t;

    if (domain &&
        domain[0])
    {
        snprintf(f->domain,
                 sizeof(f->domain),
                 "%s",
                 domain);
    }

    f->next = app->flows[h];

    app->flows[h] = f;
    app->active_flows++;

    if (is_new)
        *is_new = true;

    return f;
}
