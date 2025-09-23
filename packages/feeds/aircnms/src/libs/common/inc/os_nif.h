#ifndef OS_NIF_H_INCLUDED
#define OS_NIF_H_INCLUDED

#include <stdbool.h>

#include "os.h"
#include "ds_list.h"
#include "os_types.h"

/**
 * This structure is used as an entry in the return list of os_nif_list_get()
 */
struct os_nif_list_entry
{
    char            le_ifname[64];
    ds_list_node_t  le_node;
};

extern os_ipaddr_t os_ipaddr_any;

extern bool    os_nif_exists(char *ifname, bool *exists);
extern bool    os_nif_ipaddr_get(char* ifname, os_ipaddr_t* addr);
extern bool    os_nif_netmask_get(char* ifname, os_ipaddr_t* addr);
extern bool    os_nif_bcast_get(char* ifname, os_ipaddr_t* addr);
extern bool    os_nif_ipaddr_set(char* ifname, os_ipaddr_t addr);
extern bool    os_nif_netmask_set(char* ifname, os_ipaddr_t addr);
extern bool    os_nif_bcast_set(char* ifname, os_ipaddr_t addr);
extern bool    os_nif_mtu_get(char* ifname, int *mtu);
extern bool    os_nif_mtu_set(char* ifname, int mtu);
extern bool    os_nif_gateway_set(char* ifname, os_ipaddr_t gwaddr);
extern bool    os_nif_gateway_del(char* ifname, os_ipaddr_t gwaddr);
extern bool    os_nif_macaddr(char* ifname, os_macaddr_t *mac);
extern bool    os_nif_macaddr_get(char* ifname, os_macaddr_t *mac);
extern bool    os_nif_macaddr_set(char* ifname, os_macaddr_t mac);
extern bool    os_nif_up(char* ifname, bool ifup);
extern bool    os_nif_is_up(char* ifname, bool *up);
extern bool    os_nif_is_running(char* ifname, bool *running);
extern bool    os_nif_dhcpc_start(char* ifname, bool apply, int dhcp_time);
extern bool    os_nif_dhcpc_stop(char* ifname, bool dryrun);
extern bool    os_nif_dhcpc_refresh_lease(char* ifname);
extern bool    os_nif_softwds_create(
                                char* ifname,
                                char* parent,
                                os_macaddr_t* addr,
                                bool wrap);
extern bool    os_nif_softwds_destroy(char *ifname);
extern bool    os_nif_list_get(ds_list_t *list);
extern void             os_nif_list_free(ds_list_t *list);
extern bool    os_nif_br_add(char* ifname, char* br);
extern bool    os_nif_br_del(char* ifname);
extern bool    os_nif_ipaddr_from_str(os_ipaddr_t *ipaddr, const char* str);
extern bool    os_nif_macaddr_from_str(os_macaddr_t* mac, const char* str);
extern bool    os_nif_macaddr_to_str(const os_macaddr_t *mac, char *str, const char *format);
extern pid_t   os_nif_pppoe_pidof(const char *ifname);
extern bool    os_nif_pppoe_start(const char *ifname, const char *ifparent, const char *username, const char *password);
extern bool    os_nif_pppoe_stop(const char *ifname);
extern bool    os_nif_is_interface_ready(char *if_name);

extern int     os_nif_ioctl(int cmd, void *buf);

#endif /* OS_NIF_H_INCLUDED */
