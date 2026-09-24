#include "stamonitord_history_internal.h"

/* paste Station/domain tables section */

/* ------------------------------------------------------------------------- */
/* Station/domain tables                                                     */
/* ------------------------------------------------------------------------- */

station_t *station_get_or_create(app_t *app,
                                        mac_addr_t mac,
                                        uint32_t ip,
                                        zone_t zone,
                                        uint8_t ip_version) {
    if (mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return NULL;

    if (is_ap_own_oui(mac))
        return NULL;

    if (local_mac_contains(app, mac))
        return NULL;

    if (ip_version == 4 && ip == 0)
        return NULL;

    if (ip_version == 4 && is_common_gateway_ip(ip))
        return NULL;

    uint32_t h = hash_bytes(mac.b, sizeof(mac.b)) % STATION_BUCKETS;
    uint64_t t = now_ms();

    for (station_t *s = app->stations[h]; s; s = s->next) {
        if (mac_equal(s->mac, mac)) {
            if (ip != 0)
                s->ip = ip;

            if (zone != ZONE_UNKNOWN)
                s->zone = zone;

            s->last_seen_ms = t;
            return s;
        }
    }

    station_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    s->mac = mac;
    s->ip = ip;
    s->zone = zone;
    s->first_seen_ms = t;
    s->last_seen_ms = t;

    s->next = app->stations[h];
    app->stations[h] = s;

    return s;
}

domain_stat_t *domain_get_or_create(station_t *s,
                                           const char *domain,
                                           traffic_type_t type) {
    if (!domain || !domain[0])
        domain = "unknown";

    if (strcmp(domain, "unknown") &&
        strcmp(domain, "dns") &&
        !valid_domain_for_history(domain)) {
        domain = "unknown";
    }

    uint32_t h = hash_bytes(domain, strlen(domain)) % DOMAIN_BUCKETS;
    uint64_t t = now_ms();

    for (domain_stat_t *d = s->domains[h]; d; d = d->next) {
        if (!strcmp(d->domain, domain)) {
            d->last_seen_ms = t;
            d->active = true;
            if (d->type == TRAFFIC_OTHER && type != TRAFFIC_OTHER)
                d->type = type;
            return d;
        }
    }

    if (s->domain_count >= MAX_DOMAINS_PER_STATION)
        return NULL;

    domain_stat_t *d = calloc(1, sizeof(*d));
    if (!d)
        return NULL;

    snprintf(d->domain, sizeof(d->domain), "%s", domain);
    snprintf(d->service, sizeof(d->service), "%s", service_from_domain(domain));
    d->ndpi_protocol[0] = '\0';

    d->type = type;
    d->first_seen_ms = t;
    d->last_seen_ms = t;
    d->active = true;

    d->next = s->domains[h];
    s->domains[h] = d;
    s->domain_count++;

    return d;
}
