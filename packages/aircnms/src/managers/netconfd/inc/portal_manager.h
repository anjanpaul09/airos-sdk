#ifndef PORTAL_MANAGER_H_INCLUDED
#define PORTAL_MANAGER_H_INCLUDED

#include <stddef.h>
#include <radio_vif.h>

int portal_manager_init(void);
void portal_manager_set_network_config(const char *ipaddr, const char *netmask);
int portal_manager_assign(const struct airpro_mgr_wlan_vap_params *vif,
        char *network_name, size_t len);
int portal_manager_start(const char *portal_id);
int portal_manager_release(const char *vif_name, const char *portal_id);

#endif /* PORTAL_MANAGER_H_INCLUDED */
