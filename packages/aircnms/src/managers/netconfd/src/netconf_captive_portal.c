#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "netconf.h"

int convert_ifname(const char *in, char *out, size_t len) 
{
    if (!in || !out || len == 0)
        return -1;

    size_t n = strlen(in);
    if (n >= len)   // check buffer size
        return -1;

    for (size_t i = 0; i < n; i++) {
        if (in[i] == '-')
            out[i] = '_';
        else
            out[i] = in[i];
    }
    out[n] = '\0';
    return 0;
}

void ip_to_network(char *ip) {
    char *lastdot = strrchr(ip, '.');
    if (lastdot) {
        strcpy(lastdot + 1, "0");
    }
}

int get_ssid_interface(const char *ssid, const char *wifi, char *ifname, size_t len) {
    char cmd[512];
    int rc;

    // decide opposite phy prefix
    const char *want_prefix = NULL;
    if (strcmp(wifi, "wifi1") == 0) {
        want_prefix = "phy0-";
    } else if (strcmp(wifi, "wifi0") == 0) {
        want_prefix = "phy1-";
    } else {
        return -1; // invalid wifi string
    }

    // one-liner: find iface matching SSID + desired phy prefix
    snprintf(cmd, sizeof(cmd),
             "iw dev | awk -v ssid='%s' -v pref='%s' "
             "'/Interface/ {iface=$2} $0 ~ ssid && iface ~ pref {print iface; exit}'",
             ssid, want_prefix);

    rc = cmd_buf(cmd, ifname, len);
    if (rc != 0) {
        return -1;
    }

    // remove trailing newline
    ifname[strcspn(ifname, "\n")] = '\0';
    return 0;
}


int netconf_enable_captive_portal(char *cp_ifname, struct airpro_mgr_wlan_vap_params *vap_params)
{
    char cmd[512];
    char result[512];
    int ret;

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci set chilli.cp_%s.disabled=0",
             cp_ifname);        
    system(cmd);

    //set tun0 ip
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci get network.nat_network.ipaddr");
    execute_uci_command(cmd, result, sizeof(result));

    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd),
             "uci set chilli.cp_%s.uamlisten=%s",
             cp_ifname, result);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for uamlisten");
        return -1;
    }
    system(cmd);

    ip_to_network(result);
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd),
             "uci set chilli.cp_%s.net=%s",
             cp_ifname, result);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for net");
        return -1;
    }
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd),
             "uci set chilli.cp_%s.uamserver='%s'",
             cp_ifname, vap_params->auth_url);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for uamserver");
        return -1;
    }
    system(cmd);

    system("uci commit chilli");

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci set wireless.%s.network='lan'",
             vap_params->record_id);
    system(cmd);

    system("uci commit wireless");
            
    sprintf(cmd, "wifi reload %s", vap_params->record_id);
    system(cmd);

    return 0;
}

int netconf_disable_captive_portal(char *cp_ifname, struct airpro_mgr_wlan_vap_params *vap_params)
{
    char cmd[256];
    (void)vap_params;  // May be used in future

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci set chilli.cp_%s.disabled=1",
             cp_ifname);        
    system(cmd);

    system("uci commit chilli");
    return 0;
}

int netconf_check_captive_portal_config(char *cp_ifname, struct airpro_mgr_wlan_vap_params *vap_params)
{
    char cmd[512];
    char result[512];

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci get chilli.cp_%s.uamserver", cp_ifname);
    execute_uci_command(cmd, result, sizeof(result));
    result[strcspn(result, "\n")] = '\0';

    if (strcmp(vap_params->auth_url, result) != 0) {
        netconf_enable_captive_portal(cp_ifname, vap_params); 
    }
    
    memset(cmd, 0, sizeof(cmd));
    char uamlisten[24];
    snprintf(cmd, sizeof(cmd),
             "uci get chilli.cp_%s.uamlisten", cp_ifname);
    execute_uci_command(cmd, uamlisten, sizeof(uamlisten));
    uamlisten[strcspn(uamlisten, "\n")] = '\0'; 

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci get network.nat_network.ipaddr");
    execute_uci_command(cmd, result, sizeof(result));
    result[strcspn(result, "\n")] = '\0';

    if (strcmp(uamlisten, result) != 0) {
        netconf_enable_captive_portal(cp_ifname, vap_params); 
    }


    return 0;
}

void netconf_handle_captive_portal(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params)
{
    char ifname[12];
    char cp_ifname[12];
    char cmd[256];
    char result[256];

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci get wireless.%s.device",
             vap_name);

    memset(result, 0, sizeof(result));
    execute_uci_command(cmd, result, sizeof(result));
    result[strcspn(result, "\n")] = '\0';
    if (get_ssid_interface(vap_params->ssid, result, ifname, sizeof(ifname))== 0) {
        printf("Interface: %s\n", ifname);  // → phy0-ap0
    }

    convert_ifname(ifname, cp_ifname, sizeof(cp_ifname));
    cp_ifname[strcspn(cp_ifname, "\n")] = '\0';

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd),
             "uci get chilli.cp_%s.disabled",
             cp_ifname);        

    memset(result, 0, sizeof(result));
    execute_uci_command(cmd, result, sizeof(result));

    //if interface is disabled - check if disabled string equals "1"
    if (strcmp(vap_params->disabled, "1") == 0) {
        netconf_disable_captive_portal(cp_ifname, vap_params);
    }

    int cp_enable = 1 - atoi(result);
    if (cp_enable == vap_params->is_auth) {
        if (vap_params->is_auth == true) {
            //check for proper config
            netconf_check_captive_portal_config(cp_ifname, vap_params);
        } else {
            //disable cp
            netconf_disable_captive_portal(cp_ifname, vap_params);
        }
    } else {
        if (vap_params->is_auth == true) {
            //enable cp
            netconf_enable_captive_portal(cp_ifname, vap_params);
        } else {
            //disable cp
            netconf_disable_captive_portal(cp_ifname, vap_params);
        }
    }

    system("ifdown nat_network");
    system("/etc/init.d/chilli restart");
}
