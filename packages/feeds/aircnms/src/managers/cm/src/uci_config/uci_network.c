#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include "uci_ops.h"
#include <airpro_mgr_msg.h>

int uci_del_network_elem(char *sec_name, char *elem)
{   
    int status;
    char *sec = sec_name;
    const char *pkg = {"network"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += strlen(elem) ? uciDelete(pkg, sec, elem) : 0;
        if (status)
            break;
        else
            status = uciCommit(pkg);

    } while(0);

    uciDestroy();
    return status;
}

int uci_set_network_config(char *sec_name, struct airpro_mgr_network_config *network_config)
{
    int status;
    char *sec = sec_name;
    const char *pkg = {"network"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += strlen(network_config->ifname) ? uciSet(pkg, sec, "ifname", network_config->ifname) : 0;
        status += strlen(network_config->proto) ?  uciSet(pkg, sec, "proto",  network_config->proto) : 0;
        status += strlen(network_config->ipaddr) ? uciSet(pkg, sec, "ipaddr", network_config->ipaddr) : 0;
        status += strlen(network_config->username) ? uciSet(pkg, sec, "username", network_config->username) : 0;
        status += strlen(network_config->password) ? uciSet(pkg, sec, "password", network_config->password) : 0;
        status += strlen(network_config->netmask) ? uciSet(pkg, sec, "netmask", network_config->netmask) : 0;
        status += strlen(network_config->iface_type) ? uciSet(pkg, sec, "type", network_config->iface_type) : 0;
        status += strlen(network_config->gw) ? uciSet(pkg, sec, "gateway", network_config->gw) : 0;
        status += strlen(network_config->dns) ? uciSet(pkg, sec, "dns", network_config->dns) : 0;
        if (status)
            break;
        else
            status = uciCommit(pkg);

    } while(0);

    uciDestroy();
    return status;
}

int uci_get_network_config(char *sec_name, struct airpro_mgr_network_config *network_config)
{
    int status;
    char *sec = sec_name;
    const char *pkg = {"network"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += uciGet(pkg, sec, "ifname",  network_config->ifname);
        status += uciGet(pkg, sec, "proto",  network_config->proto);
        status += uciGet(pkg, sec, "ipaddr",  network_config->ipaddr);
        status += uciGet(pkg, sec, "netmask",  network_config->netmask);
        status += uciGet(pkg, sec, "username",  network_config->username);
        status += uciGet(pkg, sec, "password",  network_config->password);
        status += uciGet(pkg, sec, "gateway",  network_config->gw);
        status += uciGet(pkg, sec, "dns",  network_config->dns);
        if (status)
            break;

    } while(0);

    uciDestroy();
    return status;
}

int uci_add_section_network_config(char *sec_type, char *sec_name)
{
    const char *pkg = {"network"};
    int status;

    status = uciInit();
    if (status != SUCCESS) {
        return status;
    }
    status = uciSectionExist(pkg, sec_type, sec_name);
    if (status != SUCCESS) {
        return status;
    }

    status = uciAddSection(pkg, sec_type, sec_name);
    if (status != SUCCESS) {
        return status;
    }

    status = uciCommit(pkg);
    if (status != SUCCESS) {
        return status;
    }

    status = uciDestroy();
    if (status != SUCCESS) {
        return status;
    }

    return status;
}

int uci_del_section_network_config(char *sec_type, char *sec_name)
{   
    const char *pkg = {"network"};
    int status;
    
    status = uciInit();
    if (status != SUCCESS) {
        return status;
    }
    
    status = uciDeleteSection(pkg, sec_name);
    if (status != SUCCESS) {
        return status;
    }

    status = uciCommit(pkg);
    if (status != SUCCESS) {
        return status;
    }

    status = uciDestroy(); 
    if (status != SUCCESS) {
        return status;
    }

    return status;
}

void uci_network_reload()
{
    system("/etc/init.d/network reload");
}

void uci_network_reset()
{
    system("/etc/init.d/network reset");
}
