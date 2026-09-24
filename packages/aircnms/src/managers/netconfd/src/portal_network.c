#include <stdio.h>
#include <string.h>

#include "log.h"
#include "portal_network.h"
#include "portal_utils.h"

int portal_network_create(portal_entry_t *entry)
{
    char cmd[256];
    int rc = 0;

    if (!entry)
        return -1;

    snprintf(cmd, sizeof(cmd), "uci set network.dev_%s=device", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.dev_%s.name='%s'", entry->network,
             entry->bridge);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.dev_%s.type='bridge'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.dev_%s.bridge_empty='1'",
             entry->network);
    rc |= portal_cmd(cmd);

    snprintf(cmd, sizeof(cmd), "uci set network.%s=interface", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s.device='%s'", entry->network,
             entry->bridge);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s.proto='none'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.%s.ipaddr", entry->network);
    portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.%s.netmask", entry->network);
    portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s.type='bridge'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s.bridge_empty='1'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun=interface", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun.device='%s'",
             entry->network, entry->tun);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun.proto='none'",
             entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun0=interface", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun0.device='tun0'",
             entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set network.%s_tun0.proto='none'",
             entry->network);
    rc |= portal_cmd(cmd);
    rc |= portal_cmd("uci commit network");

    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s=zone", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s.name='%s'", entry->network,
             entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s.network='%s'", entry->network,
             entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci add_list firewall.z_%s.network='%s_tun'",
             entry->network, entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci add_list firewall.z_%s.network='%s_tun0'",
             entry->network, entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s.input='ACCEPT'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s.output='ACCEPT'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.z_%s.forward='REJECT'", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.f_%s=forwarding", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.f_%s.src='%s'", entry->network,
             entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci set firewall.f_%s.dest='wan'", entry->network);
    rc |= portal_cmd(cmd);
    rc |= portal_cmd("uci commit firewall");

    snprintf(cmd, sizeof(cmd), "ifup %s", entry->network);
    rc |= portal_cmd(cmd);
    rc |= portal_cmd("/etc/init.d/firewall reload");

    if (rc != 0)
        LOG(ERR, "portal_network: create failed for portal=%s network=%s",
            entry->portal_id, entry->network);
    else
        LOG(INFO, "portal_network: created portal=%s network=%s bridge=%s",
            entry->portal_id, entry->network, entry->bridge);

    return rc;
}

int portal_network_delete(portal_entry_t *entry)
{
    char cmd[256];
    int rc = 0;

    if (!entry)
        return -1;

    snprintf(cmd, sizeof(cmd), "ifdown %s", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.%s", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.dev_%s", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.%s_tun", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete network.%s_tun0", entry->network);
    rc |= portal_cmd(cmd);
    rc |= portal_cmd("uci commit network");

    snprintf(cmd, sizeof(cmd), "uci delete firewall.z_%s", entry->network);
    rc |= portal_cmd(cmd);
    snprintf(cmd, sizeof(cmd), "uci delete firewall.f_%s", entry->network);
    rc |= portal_cmd(cmd);
    rc |= portal_cmd("uci commit firewall");
    rc |= portal_cmd("/etc/init.d/firewall reload");

    LOG(INFO, "portal_network: deleted portal=%s network=%s", entry->portal_id,
        entry->network);
    return rc;
}
