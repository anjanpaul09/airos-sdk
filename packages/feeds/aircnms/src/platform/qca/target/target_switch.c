#define _GNU_SOURCE

#include "log.h"
#include "os_random.h"

#include "os_ssdk.h"
#include "ssdk_util.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#ifndef MAX_VLAN_ID
#define MAX_VLAN_ID 4095
#endif

bool target_switch_is_supported(void)
{
    if (os_ssdk_is_available() == false)
        return false;
    return true;
}

bool target_switch_assoc_vlan_to_iface(const char *ifname, const uint16_t vlan_id,  bool tagged)
{
    uint32_t port_num = 0;
    int32_t  port_bmp = 0;

    port_num = ssdk_util_conv_ifname_to_portnum(ifname);
    if (port_num == 0)
        return false;

   /*
    * If VLAN is associated to other ports, avoid creating again.
    * Otherwise, create new VLAN.
    */
    port_bmp = ssdk_get_vlan_membership(vlan_id);
    if (port_bmp < 1)
    {
        if (WARN_ON(ssdk_create_vlan_entry(vlan_id) == false))
            return false;
    }

    if (WARN_ON(ssdk_add_vlan_member_to_port(port_num, vlan_id, tagged) == false))
        return false;
    return true;
}

bool target_switch_disassoc_vlan_from_iface(const char *ifname, const uint16_t vlan_id)
{
    uint32_t port_num = 0;
    int32_t port_bmp = 0;

    port_num = ssdk_util_conv_ifname_to_portnum(ifname);
    if (port_num == 0)
        return false;

    if (WARN_ON(ssdk_rem_port_from_vlan_membership(port_num, vlan_id) == false))
        return false;

   /*
    * If VLAN is associated with other interfaces, then return here.
    * Otherwise, delete the VLAN entry from the switch config.
    */
    port_bmp = ssdk_get_vlan_membership(vlan_id);
    if (port_bmp > 1)
        return true;

    if (WARN_ON(ssdk_delete_vlan_entry(vlan_id) == false))
        return false;

    return true;
}
