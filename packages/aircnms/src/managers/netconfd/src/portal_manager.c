#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "os.h"
#include "portal_chilli.h"
#include "portal_db.h"
#include "portal_manager.h"
#include "portal_network.h"
#include "portal_template.h"
#include "portal_utils.h"

static char g_portal_ipaddr[32];
static char g_portal_netmask[32];

static bool portal_manager_vif_config_valid(const struct airpro_mgr_wlan_vap_params *vif)
{
    if (!vif)
        return false;

    if ((vif->net_segment_ip[0] == '\0' && g_portal_ipaddr[0] == '\0') ||
        (vif->net_mask_ip[0] == '\0' && g_portal_netmask[0] == '\0')) {
        LOG(ERR, "portal_manager: missing natConfig ip/netmask portal=%s vif=%s",
            vif->portal_id, vif->record_id);
        return false;
    }

    if (vif->server_ip[0] == '\0' || vif->secret_key[0] == '\0') {
        LOG(ERR, "portal_manager: missing radius server/secret portal=%s vif=%s",
            vif->portal_id, vif->record_id);
        return false;
    }

    if (vif->auth_url[0] == '\0') {
        LOG(ERR, "portal_manager: missing authUrl portal=%s vif=%s",
            vif->portal_id, vif->record_id);
        return false;
    }

    return true;
}

void portal_manager_set_network_config(const char *ipaddr, const char *netmask)
{
    if (ipaddr && ipaddr[0] != '\0')
        strlcpy(g_portal_ipaddr, ipaddr, sizeof(g_portal_ipaddr));

    if (netmask && netmask[0] != '\0')
        strlcpy(g_portal_netmask, netmask, sizeof(g_portal_netmask));
}

static int portal_manager_create(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif)
{
    if (!entry || !portal_manager_vif_config_valid(vif))
        return -1;

    if (portal_network_create(entry) != 0)
        return -1;
    if (portal_template_render_instance(entry, vif) != 0)
        return -1;

    return 0;
}

static int portal_manager_destroy(portal_entry_t *entry)
{
    char instance_dir[PORTAL_PATH_LEN];

    if (!entry)
        return -1;

    portal_chilli_stop(entry);
    portal_network_delete(entry);

    snprintf(instance_dir, sizeof(instance_dir), "%s/%s", PORTAL_INSTANCE_DIR,
             entry->portal_id);
    portal_remove_tree(instance_dir);
    portal_db_remove(entry->portal_id);
    return 0;
}

static bool portal_manager_update_network_config(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif)
{
    char ipaddr[32] = {0};
    char netmask[32] = {0};
    bool changed = false;

    if (!entry || !vif)
        return false;

    strlcpy(ipaddr, vif->net_segment_ip[0] ? vif->net_segment_ip : g_portal_ipaddr,
            sizeof(ipaddr));
    strlcpy(netmask, vif->net_mask_ip[0] ? vif->net_mask_ip : g_portal_netmask,
            sizeof(netmask));

    if (ipaddr[0] != '\0' && strcmp(entry->ipaddr, ipaddr)) {
        strlcpy(entry->ipaddr, ipaddr, sizeof(entry->ipaddr));
        changed = true;
    }

    if (netmask[0] != '\0' && strcmp(entry->netmask, netmask)) {
        strlcpy(entry->netmask, netmask, sizeof(entry->netmask));
        changed = true;
    }

    return changed;
}

static int portal_manager_restore_vif_refs(portal_entry_t *entry)
{
    FILE *fp;
    char line[256];
    int count = 0;

    if (!entry)
        return 0;

    fp = popen("uci show wireless 2>/dev/null", "r");
    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *section;
        char *opt;
        char *value;
        char *end;

        if (strncmp(line, "wireless.", 9))
            continue;

        section = line + 9;
        opt = strchr(section, '.');
        if (!opt)
            continue;
        *opt++ = '\0';

        value = strchr(opt, '=');
        if (!value)
            continue;
        *value++ = '\0';

        if (strcmp(opt, "network"))
            continue;

        while (*value == '\'' || *value == '"')
            value++;
        end = value + strlen(value);
        while (end > value &&
               (end[-1] == '\n' || end[-1] == '\r' ||
                end[-1] == '\'' || end[-1] == '"')) {
            *--end = '\0';
        }

        if (strcmp(value, entry->network))
            continue;

        portal_db_set_vif_portal(section, entry->portal_id);
        count++;
    }

    pclose(fp);
    return count;
}

static void portal_manager_restore_instances(void)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir(PORTAL_INSTANCE_DIR);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        portal_entry_t *entry;

        if (de->d_name[0] == '.')
            continue;
        if (!portal_id_valid(de->d_name))
            continue;

        entry = portal_db_add(de->d_name);
        if (!entry)
            continue;

        if (portal_template_load_metadata(de->d_name, entry) != 0) {
            portal_db_remove(de->d_name);
            continue;
        }

        {
            int vif_count = portal_manager_restore_vif_refs(entry);
            if (vif_count > 0)
                entry->ref_count = vif_count;
            else if (entry->ref_count <= 0)
                entry->ref_count = 1;
        }

        if (entry->ipaddr[0] == '\0' || entry->netmask[0] == '\0') {
            LOG(ERR, "portal_manager: remove stale portal restore portal=%s missing ip/netmask",
                entry->portal_id);
            portal_manager_destroy(entry);
            continue;
        }

        if (portal_network_create(entry) == 0)
            portal_chilli_start(entry);
        LOG(INFO, "portal_manager: restored portal=%s network=%s ref_count=%d",
            entry->portal_id, entry->network, entry->ref_count);
    }

    closedir(dir);
}

int portal_manager_init(void)
{
    portal_db_init();

    if (portal_template_init_defaults() != 0) {
        LOG(ERR, "portal_manager: failed to initialize template directories");
        return -1;
    }

    portal_manager_restore_instances();
    return 0;
}

int portal_manager_assign(const struct airpro_mgr_wlan_vap_params *vif,
        char *network_name, size_t len)
{
    portal_entry_t *entry;
    const char *old_portal;

    if (!vif || !network_name || len == 0)
        return -1;

    if (!vif->is_auth || vif->portal_id[0] == '\0') {
        int vlan = atoi(vif->vlan_id);

        if (!strcmp(vif->forward_type, "NAT")) {
            strlcpy(network_name, "nat_network", len);
            return 0;
        }

        if (vlan > 0)
            strlcpy(network_name, vif->vlan_id, len);
        else
            strlcpy(network_name, "lan", len);

        return 0;
    }

    if (!portal_id_valid(vif->portal_id)) {
        LOG(ERR, "portal_manager: invalid portal_id=%s vif=%s", vif->portal_id,
            vif->record_id);
        return -1;
    }

    if (!portal_manager_vif_config_valid(vif))
        return -1;

    old_portal = portal_db_get_vif_portal(vif->record_id);
    if (old_portal && strcmp(old_portal, vif->portal_id))
        portal_manager_release(vif->record_id, old_portal);

    entry = portal_db_get(vif->portal_id);
    if (!entry) {
        entry = portal_db_add(vif->portal_id);
        if (!entry)
            return -1;

        portal_manager_update_network_config(entry, vif);

        entry->ref_count = 1;
        if (portal_manager_create(entry, vif) != 0) {
            LOG(ERR, "portal_manager: portal create incomplete portal=%s, keeping configs for diagnostics",
                entry->portal_id);
            return -1;
        }
    } else if (!old_portal || strcmp(old_portal, vif->portal_id)) {
        entry->ref_count++;
        portal_manager_update_network_config(entry, vif);
        portal_chilli_stop(entry);
        if (portal_network_create(entry) != 0)
            return -1;
        if (portal_template_render_instance(entry, vif) != 0)
            return -1;
    } else {
        portal_manager_update_network_config(entry, vif);
        portal_chilli_stop(entry);
        if (portal_network_create(entry) != 0)
            return -1;
        if (portal_template_render_instance(entry, vif) != 0)
            return -1;
    }

    portal_db_set_vif_portal(vif->record_id, vif->portal_id);
    strlcpy(network_name, entry->network, len);
    LOG(INFO, "portal_manager: prepared vif=%s portal=%s network=%s ref_count=%d",
        vif->record_id, entry->portal_id, entry->network, entry->ref_count);
    return 0;
}

int portal_manager_start(const char *portal_id)
{
    portal_entry_t *entry;

    if (!portal_id || portal_id[0] == '\0')
        return 0;

    entry = portal_db_get(portal_id);
    if (!entry) {
        LOG(ERR, "portal_manager: start requested for unknown portal=%s",
            portal_id);
        return -1;
    }

    if (portal_chilli_start(entry) != 0) {
        LOG(ERR, "portal_manager: chilli start failed portal=%s",
            portal_id);
        return -1;
    }

    LOG(INFO, "portal_manager: started portal=%s network=%s",
        entry->portal_id, entry->network);
    return 0;
}

int portal_manager_release(const char *vif_name, const char *portal_id)
{
    const char *resolved_id = portal_id;
    portal_entry_t *entry;

    if (!resolved_id || resolved_id[0] == '\0')
        resolved_id = portal_db_get_vif_portal(vif_name);

    if (!resolved_id || resolved_id[0] == '\0')
        return 0;

    entry = portal_db_get(resolved_id);
    portal_db_clear_vif_portal(vif_name);
    if (!entry)
        return 0;

    if (entry->ref_count > 0)
        entry->ref_count--;

    LOG(INFO, "portal_manager: released vif=%s portal=%s ref_count=%d",
        vif_name ? vif_name : "", entry->portal_id, entry->ref_count);

    if (entry->ref_count > 0)
        return 0;

    return portal_manager_destroy(entry);
}

void netconf_handle_captive_portal(char *vap_name,
        struct airpro_mgr_wlan_vap_params *vap_params)
{
    char network[PORTAL_NAME_LEN];

    if (!vap_name || !vap_params)
        return;

    if (portal_manager_assign(vap_params, network, sizeof(network)) == 0)
        strlcpy(vap_params->network, network, sizeof(vap_params->network));
}
