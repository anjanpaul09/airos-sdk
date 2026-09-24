#include <string.h>

#include "log.h"
#include "os.h"
#include "portal_db.h"
#include "portal_utils.h"

static portal_entry_t g_portals[PORTAL_MAX_ENTRIES];
static portal_vif_ref_t g_vif_refs[PORTAL_MAX_VIFS];

void portal_db_init(void)
{
    memset(g_portals, 0, sizeof(g_portals));
    memset(g_vif_refs, 0, sizeof(g_vif_refs));
}

portal_entry_t *portal_db_get(const char *portal_id)
{
    int i;

    if (!portal_id || portal_id[0] == '\0')
        return NULL;

    for (i = 0; i < PORTAL_MAX_ENTRIES; i++) {
        if (!strcmp(g_portals[i].portal_id, portal_id))
            return &g_portals[i];
    }

    return NULL;
}

portal_entry_t *portal_db_add(const char *portal_id)
{
    int i;
    portal_entry_t *entry;

    if (!portal_id_valid(portal_id))
        return NULL;

    entry = portal_db_get(portal_id);
    if (entry)
        return entry;

    for (i = 0; i < PORTAL_MAX_ENTRIES; i++) {
        if (g_portals[i].portal_id[0] != '\0')
            continue;

        entry = &g_portals[i];
        memset(entry, 0, sizeof(*entry));
        strlcpy(entry->portal_id, portal_id, sizeof(entry->portal_id));
        portal_make_network_name(portal_id, entry->network, sizeof(entry->network));
        portal_make_bridge_name(entry->network, entry->bridge, sizeof(entry->bridge));
        portal_make_tun_name(entry->network, entry->tun, sizeof(entry->tun));
        strlcpy(entry->interface, entry->bridge, sizeof(entry->interface));
        snprintf(entry->metadata_path, sizeof(entry->metadata_path),
                 "%s/%s/metadata.json", PORTAL_INSTANCE_DIR, portal_id);
        return entry;
    }

    LOG(ERR, "portal_db: no free entries for portal_id=%s", portal_id);
    return NULL;
}

void portal_db_remove(const char *portal_id)
{
    portal_entry_t *entry = portal_db_get(portal_id);

    if (entry)
        memset(entry, 0, sizeof(*entry));
}

int portal_db_count(void)
{
    int i;
    int count = 0;

    for (i = 0; i < PORTAL_MAX_ENTRIES; i++) {
        if (g_portals[i].portal_id[0] != '\0')
            count++;
    }

    return count;
}

portal_entry_t *portal_db_at(int idx)
{
    if (idx < 0 || idx >= PORTAL_MAX_ENTRIES)
        return NULL;

    if (g_portals[idx].portal_id[0] == '\0')
        return NULL;

    return &g_portals[idx];
}

const char *portal_db_get_vif_portal(const char *vif_name)
{
    int i;

    if (!vif_name || vif_name[0] == '\0')
        return NULL;

    for (i = 0; i < PORTAL_MAX_VIFS; i++) {
        if (!strcmp(g_vif_refs[i].vif_name, vif_name))
            return g_vif_refs[i].portal_id;
    }

    return NULL;
}

void portal_db_set_vif_portal(const char *vif_name, const char *portal_id)
{
    int i;
    int free_idx = -1;

    if (!vif_name || !portal_id || vif_name[0] == '\0' || portal_id[0] == '\0')
        return;

    for (i = 0; i < PORTAL_MAX_VIFS; i++) {
        if (!strcmp(g_vif_refs[i].vif_name, vif_name)) {
            strlcpy(g_vif_refs[i].portal_id, portal_id,
                    sizeof(g_vif_refs[i].portal_id));
            return;
        }
        if (free_idx < 0 && g_vif_refs[i].vif_name[0] == '\0')
            free_idx = i;
    }

    if (free_idx < 0) {
        LOG(ERR, "portal_db: no free vif refs for vif=%s", vif_name);
        return;
    }

    strlcpy(g_vif_refs[free_idx].vif_name, vif_name,
            sizeof(g_vif_refs[free_idx].vif_name));
    strlcpy(g_vif_refs[free_idx].portal_id, portal_id,
            sizeof(g_vif_refs[free_idx].portal_id));
}

void portal_db_clear_vif_portal(const char *vif_name)
{
    int i;

    if (!vif_name || vif_name[0] == '\0')
        return;

    for (i = 0; i < PORTAL_MAX_VIFS; i++) {
        if (!strcmp(g_vif_refs[i].vif_name, vif_name)) {
            memset(&g_vif_refs[i], 0, sizeof(g_vif_refs[i]));
            return;
        }
    }
}
