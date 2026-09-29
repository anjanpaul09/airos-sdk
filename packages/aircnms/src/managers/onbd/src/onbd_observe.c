#include "onbd.h"

#include <libubus.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <uci.h>

static bool object_exists(struct ubus_context *ctx, const char *name)
{
    uint32_t id;
    return ctx && ubus_lookup_id(ctx, name, &id) == 0;
}

static void read_legacy_uci(onbd_state_t *state)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *element;
    if (!ctx || uci_load(ctx, "aircnms", &pkg) != UCI_OK)
        goto out;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *device_id, *online;
        if (strcmp(section->type, "aircnms")) continue;
        device_id = uci_lookup_option_string(ctx, section, "device_id");
        online = uci_lookup_option_string(ctx, section, "online");
        state->stored_identity_valid = onbd_valid_device_id(device_id);
        state->legacy_online = online && !strcmp(online, "1");
        break;
    }
out:
    if (pkg) uci_unload(ctx, pkg);
    if (ctx) uci_free_context(ctx);
}

void onbd_observe(struct ubus_context *ctx, onbd_state_t *state)
{
    struct timespec now;
    if (!state) return;
    state->ubus_available = ctx != NULL;
    state->network_available = object_exists(ctx, "network.interface");
    state->cgwd_available = object_exists(ctx, "cgwd");
    state->netconfd_available = object_exists(ctx, "netconfd");
    read_legacy_uci(state);
    onbd_probe_network(state);
    onbd_derive_shadow_state(state);
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        state->updated_monotonic_ms = (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}
