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

    if (radio_params->channel_width[0] == '\0' && radio_params->htmode[0] != '\0') {
        if (strstr(radio_params->htmode, "160")) strlcpy(radio_params->channel_width, "160", sizeof(radio_params->channel_width));
        else if (strstr(radio_params->htmode, "80")) strlcpy(radio_params->channel_width, "80", sizeof(radio_params->channel_width));
        else if (strstr(radio_params->htmode, "40")) strlcpy(radio_params->channel_width, "40", sizeof(radio_params->channel_width));
        else if (strstr(radio_params->htmode, "20") || strstr(radio_params->htmode, "NOHT")) strlcpy(radio_params->channel_width, "20", sizeof(radio_params->channel_width));
    }

    if (radio_params->hwmode[0] == '\0' && radio_params->htmode[0] != '\0') {
        if (strstr(radio_params->htmode, "HE")) {
            strlcpy(radio_params->hwmode, (!strcmp(radio_name, "wifi0") ? "11NA_11AC_11AX" : "11BGN_11AX"), sizeof(radio_params->hwmode));
        } else if (strstr(radio_params->htmode, "VHT")) {
            strlcpy(radio_params->hwmode, "11AC", sizeof(radio_params->hwmode));
        } else {
            strlcpy(radio_params->hwmode, (!strcmp(radio_name, "wifi0") ? "11NA" : "11BGN"), sizeof(radio_params->hwmode));
        }
    }

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
        status += uciGet(pkg, sec, "forward_type", vap_params->forward_type);
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
        status += strlen(radio_params->hwmode) ? uciSet(pkg, sec, "hwmode", radio_params->hwmode) : 0;
        status += strlen(radio_params->noscan) ? uciSet(pkg, sec, "noscan", radio_params->noscan) : 0;
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

static int is_enterprise_encryption(const char *encryption)
{
    return !strcmp(encryption, "wpa2") || !strcmp(encryption, "wpa3");
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

    /* Ensure section exists if newly added */
    uciAddSection(pkg, "wifi-iface", sec);

    if (!vap_params->opmode[0])
        strlcpy(vap_params->opmode, "ap", sizeof(vap_params->opmode));
    if (!vap_params->network[0])
        strlcpy(vap_params->network, "lan", sizeof(vap_params->network));
    if (!vap_params->wifi_device[0]) {
        if (strstr(vap_params->device, "5G") || strstr(vap_params->device, "wifi0"))
            strlcpy(vap_params->wifi_device, "wifi0", sizeof(vap_params->wifi_device));
        else if (vap_params->device[0])
            strlcpy(vap_params->wifi_device, "wifi1", sizeof(vap_params->wifi_device));
    }

    do {
        status += strlen(vap_params->wifi_device) ? uciSet(pkg, sec, "device", vap_params->wifi_device) : 0;
        status += strlen(vap_params->network) ? uciSet(pkg, sec, "network", vap_params->network) : 0;
        status += strlen(vap_params->forward_type) ? uciSet(pkg, sec, "forward_type", vap_params->forward_type) : 0;
        status += strlen(vap_params->opmode) ? uciSet(pkg, sec, "mode", vap_params->opmode) : 0;
        status += strlen(vap_params->ssid) ? uciSet(pkg, sec, "ssid", vap_params->ssid) : 0;
        status += strlen(vap_params->mobility_id) ? uciSet(pkg, sec, "mobility_domain", vap_params->mobility_id) : 0;
        status += strlen(vap_params->vlan_id) ? uciSet(pkg, sec, "vlan", vap_params->vlan_id) : 0;
        status += strlen(vap_params->hide_ssid) ? uciSet(pkg, sec, "hidden", vap_params->hide_ssid) : 0;
        status += strlen(vap_params->isolate) ? uciSet(pkg, sec, "isolate", vap_params->isolate) : 0;
        status += strlen(vap_params->encryption) ? uciSet(pkg, sec, "encryption", vap_params->encryption) : 0;
        /* 802.11w is mandatory for pure SAE and optional for transition mode.
         * Reset it for other modes so SAE-required state cannot survive an
         * encryption change. */
        if (!strcmp(vap_params->encryption, "sae"))
            status += uciSet(pkg, sec, "ieee80211w", "2");
        else if (!strcmp(vap_params->encryption, "sae-mixed"))
            status += uciSet(pkg, sec, "ieee80211w", "1");
        else if (strlen(vap_params->encryption))
            status += uciSet(pkg, sec, "ieee80211w", "1");
        if (!strcmp(vap_params->encryption, "none"))
            uciDelete(pkg, sec, "key");
        else
            status += strlen(vap_params->key) ? uciSet(pkg, sec, "key", vap_params->key) : 0;
        if (is_enterprise_encryption(vap_params->encryption)) {
            status += strlen(vap_params->server_ip) ? uciSet(pkg, sec, "auth_server", vap_params->server_ip) : 0;
            status += strlen(vap_params->auth_port) ? uciSet(pkg, sec, "auth_port", vap_params->auth_port) : 0;
            status += strlen(vap_params->server_ip) ? uciSet(pkg, sec, "acct_server", vap_params->server_ip) : 0;
            status += strlen(vap_params->acct_port) ? uciSet(pkg, sec, "acct_port", vap_params->acct_port) : 0;
            status += strlen(vap_params->secret_key) ? uciSet(pkg, sec, "key", vap_params->secret_key) : 0;
        } else {
            uciDelete(pkg, sec, "auth_server");
            uciDelete(pkg, sec, "auth_port");
            uciDelete(pkg, sec, "acct_server");
            uciDelete(pkg, sec, "acct_port");
        }
        status += strlen(vap_params->disabled) ? uciSet(pkg, sec, "disabled", vap_params->disabled) : 0;
        status += strlen(vap_params->macfilter) ? uciSet(pkg, sec, "macfilter", vap_params->macfilter) : 0;
        status += strlen(vap_params->ft_psk_generate_local) ? uciSet(pkg, sec, "ft_psk_generate_local", vap_params->ft_psk_generate_local) : 0;
        if (status != SUCCESS)
            break;
        uciCommit((char *)pkg);        

    } while(0);

    uciDestroy();
    return status;
}


