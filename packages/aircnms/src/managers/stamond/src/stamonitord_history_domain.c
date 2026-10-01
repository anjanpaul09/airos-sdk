#include "stamonitord_history_internal.h"

history_domain_t *
history_domain_get_or_create(
    history_state_t *history,
    const char *domain,
    traffic_type_t type)
{
    history_domain_t *d;
    uint64_t t = now_ms();

    if (!history)
        return NULL;

    if (!domain || !domain[0])
        domain = "unknown";

    d = ds_tree_find(
        &history->domains,
        domain);

    if (d) {
        d->last_seen_ms = t;
        d->active = true;

        if (d->type == TRAFFIC_OTHER && type != TRAFFIC_OTHER)
            d->type = type;

        return d;
    }

    if (history->domain_count >= MAX_DOMAINS_PER_STATION)
        return NULL;

    d = calloc(1, sizeof(*d));
    if (!d)
        return NULL;

    snprintf(
        d->domain,
        sizeof(d->domain),
        "%s",
        domain);

    snprintf(
        d->service,
        sizeof(d->service),
        "%s",
        service_from_domain(domain));

    d->type = type;
    d->first_seen_ms = t;
    d->last_seen_ms = t;
    d->active = true;

    ds_tree_insert(
        &history->domains,
        d,
        d->domain);

    history->domain_count++;

    return d;
}
