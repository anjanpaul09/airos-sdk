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
#include <radio_vif.h>
static struct uci_context *ctx;

int uciGetSectionName(const char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names)
{
    struct uci_element *elm = NULL;
    struct uci_package *p;
    struct uci_ptr ptr;
    int num_entry = 0;

    if (uci_lookup_ptr(ctx, &ptr, (char *)pkg, true) != UCI_OK) {
        return 1;
    }

    elm = ptr.last;
    p = ptr.p;
    uci_foreach_element(&p->sections, elm) {
        struct uci_section *s = uci_to_section(elm);
        if (!strcmp(s->type, sec_type)) {
            strcpy(sec_arr_names->sec_name[num_entry], s->e.name);
            num_entry++;
        }
    }
    sec_arr_names->num_entry = num_entry;

    return SUCCESS;
}

int uci_get_all_section_names(char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names)
{
    int status;

    status = uciInit();
    if (status != SUCCESS) {
        return status;
    }
    status = uciGetSectionName(pkg, sec_type, sec_arr_names);
    if (status != SUCCESS) {
        return status;
    }

    status = uciDestroy();
    if (status != SUCCESS) {
        return status;
    }

    return status;

}

int uci_get_wifi_sec_name_from_radio_vap_id(char *sec_name, int radio_idx, int vap_idx)
{
    int status;
    const char *pkg = {"wireless"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    status = uciGetSectionNameFromRVID(pkg, sec_name, radio_idx, vap_idx);

    uciDestroy();
    return status;
}


int uci_get_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params)
{
    int status;
    char *sec = radio_name;
    const char *pkg = {"wireless"};

    status = uciInit();
    if (status != SUCCESS)
        return status;
    
    do {
        status += uciGet(pkg, sec, "disabled",  radio_params->disabled);
        status += uciGet(pkg, sec, "channel",  radio_params->channel);
        status += uciGet(pkg, sec, "country",  radio_params->country);
        status += uciGet(pkg, sec, "txpower",  radio_params->txpower);
	status += uciGet(pkg, sec, "hwmode",  radio_params->hwmode);
        status += uciGet(pkg, sec, "htmode",  radio_params->htmode);
        status += uciGet(pkg, sec, "max_sta",  radio_params->max_sta);
        if (status)
            break;  

    } while(0);

    uciDestroy();
    return status;
}

int uci_get_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params)
{
    int status;
    char *sec = vap_name;
    const char *pkg = {"wireless"};

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        //status += uciGet(pkg, sec, "opmode", vap_params->opmode);
        status += uciGet(pkg, sec, "ssid", vap_params->ssid);
        status += uciGet(pkg, sec, "network", vap_params->network);
        status += uciGet(pkg, sec, "mode", vap_params->opmode);
        status += uciGet(pkg, sec, "hidden", vap_params->hide_ssid);
        status += uciGet(pkg, sec, "isolate", vap_params->isolate);
        status += uciGet(pkg, sec, "encryption", vap_params->encryption);
        status += uciGet(pkg, sec, "vlan", vap_params->vlan_id);
        status += uciGet(pkg, sec, "key", vap_params->key);
        //status += uciGet(pkg, sec, "uprate", vap_params->uprate);
        //status += uciGet(pkg, sec, "downrate", vap_params->downrate);
        status += uciGet(pkg, sec, "server", vap_params->server_name);
        status += uciGet(pkg, sec, "server_ip", vap_params->server_ip);
        status += uciGet(pkg, sec, "auth_port", vap_params->auth_port);
        status += uciGet(pkg, sec, "acct_port", vap_params->acct_port);
        status += uciGet(pkg, sec, "macfilter", vap_params->macfilter);
        status += uciGetList(pkg, sec, "maclist", vap_params->maclist);
        // status += uciGet(pkg, sec, "ifname", vap_params->ifname);
        status += uciGet(pkg, sec, "device", vap_params->device);
        if (status)
            break; 

    } while(0);

    uciDestroy();
    return status;
}

int uci_set_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params)
{
    int status;
    char *sec = radio_name;
    const char *pkg = {"wireless"};
	
    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += strlen(radio_params->channel) ? uciSet(pkg, sec, "channel", radio_params->channel) : 0;
        status += strlen(radio_params->htmode) ? uciSet(pkg, sec, "htmode", radio_params->htmode) : 0;
        status += strlen(radio_params->disabled) ? uciSet(pkg, sec, "disabled", radio_params->disabled) : 0;
        status += strlen(radio_params->country) ? uciSet(pkg, sec, "country", radio_params->country) : 0;
        status += strlen(radio_params->max_sta) ? uciSet(pkg, sec, "max_sta", radio_params->max_sta) : 0;
        status += strlen(radio_params->txpower) ? uciSet(pkg, sec, "txpower", radio_params->txpower) : 0;
        status += strlen(radio_params->user_limit) ? uciSet(pkg, sec, "user_limit", radio_params->user_limit) : 0;
        if (status)
            break;
        else
            status = uciCommit((char *)pkg);    

    } while(0);

    uciDestroy();
    return status;
}

int uci_get_vap_iface(char *sec, char *iface)
{
    const char *pkg = {"wireless"};
    int status;

    status = uciInit();
    if (status != SUCCESS)
        return status;
    
    status = uciGet(pkg, sec, "ifname", iface);

    uciDestroy();
    return status;
}

int uci_set_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params)
{
    printf("Ankit: vapname - %s, ssid - %s\n", vap_name, vap_params->ssid);
    char *sec = vap_name;
    const char *pkg = {"wireless"};
    int status;

    status = uciInit();
    if (status != SUCCESS)
        return status;

    do {
        status += strlen(vap_params->wifi_device) ? uciSet(pkg, sec, "device", vap_params->wifi_device) : 0;
        status += strlen(vap_params->network) ? uciSet(pkg, sec, "network", vap_params->network) : 0;
        status += strlen(vap_params->opmode) ? uciSet(pkg, sec, "mode", vap_params->opmode) : 0;
        status += strlen(vap_params->ssid) ? uciSet(pkg, sec, "ssid", vap_params->ssid) : 0;
        status += strlen(vap_params->vlan_id) ? uciSet(pkg, sec, "vlan", vap_params->vlan_id) : 0;
        status += strlen(vap_params->hide_ssid) ? uciSet(pkg, sec, "hidden", vap_params->hide_ssid) : 0;
        status += strlen(vap_params->isolate) ? uciSet(pkg, sec, "isolate", vap_params->isolate) : 0;
        status += strlen(vap_params->encryption) ? uciSet(pkg, sec, "encryption", vap_params->encryption) : 0;
        status += strlen(vap_params->key) ? uciSet(pkg, sec, "key", vap_params->key) : 0;
        status += strlen(vap_params->server_ip) ? uciSet(pkg, sec, "auth_server", vap_params->server_ip) : 0;
        status += strlen(vap_params->auth_port) ? uciSet(pkg, sec, "auth_port", vap_params->auth_port) : 0;
        status += strlen(vap_params->server_ip) ? uciSet(pkg, sec, "acct_server", vap_params->server_ip) : 0;
        status += strlen(vap_params->acct_port) ? uciSet(pkg, sec, "acct_port", vap_params->acct_port) : 0;
        status += strlen(vap_params->secret_key) ? uciSet(pkg, sec, "key", vap_params->secret_key) : 0;
        status += strlen(vap_params->disabled) ? uciSet(pkg, sec, "disabled", vap_params->disabled) : 0;
        status += strlen(vap_params->macfilter) ? uciSet(pkg, sec, "macfilter", vap_params->macfilter) : 0;
        if (status != SUCCESS)
            break;
        uciCommit((char *)pkg);        

    } while(0);

    uciDestroy();
    return status;
}



