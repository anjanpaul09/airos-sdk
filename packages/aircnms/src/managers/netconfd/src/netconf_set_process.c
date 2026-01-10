#include "log.h"
#include "netconf.h"
#include "dpp_types.h"
#include <jansson.h>

int current_roaming_status = false;

uint16_t mobility_domain_from_string(const char *s)
{
    uint32_t hash = 5381;
    int c;

    while ((c = *s++))
        hash = ((hash << 5) + hash) + c;   // djb2

    return (uint16_t)(hash & 0xFFFF);
}

void netconf_apply_jedi_conf()
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc = 0;  // Ensure rc is always initialized
    int aircnms_status = 0;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].onboard", buf, (size_t)UCI_BUF_LEN);
    if (rc != 0) {
        LOG(ERR, "%s: Failed to fetch UCI onboard status", __func__);
        return;
    }
    
    buf[UCI_BUF_LEN - 1] = '\0';  // Ensure buffer is always null-terminated
    len = strlen(buf);
    if (len == 0) {
        LOG(ERR,"%s: No UCI entry found", __func__);
        return;
    }

    if (sscanf(buf, "%d", &aircnms_status) != 1) {
        LOG(ERR,"%s: Failed to parse onboard status", __func__);
        return;
    }

    if (aircnms_status == 1) {
        if (is_flag_set(flags, FLAG_NETWORK_CHANGE)) {
            LOG(INFO,"NETWORK CHANGE DETECTED, REBOOTING!");
            if (system("reboot") == -1) {
                LOG(ERR,"%s: Failed to reboot system", __func__);
            }
        }

        if (is_flag_set(flags, FLAG_WIRELESS_CHANGE)) {
            LOG(INFO,"WIFI CHANGE DETECTED, WIFI RELOAD!");
            system("wifi reload");
        }

        rc = netconf_check_wifi_config();
    } else {
        LOG(INFO, "%s: Setting onboard status and rebooting...", __func__);
        system("uci set aircnms.@aircnms[0].onboard=1");
        system("uci commit aircnms");
        system("reboot");
    }
}

bool netconf_process_vif_list(json_t *vif_list)
{
    bool ret;
    int n_vif = 0;
    //char record_id[12];
    int hidden;
    size_t i;
    vif_record_t *record = (vif_record_t *)malloc(sizeof(vif_record_t));
    
    // FIX: Add null check for malloc
    if (!record) {
        LOG(ERR, "Failed to allocate memory for vif_record_t");
        return false;
    }
    
    memset(record, 0, sizeof(vif_record_t));
    json_t *vif;
    json_t *attr_value;
    json_array_foreach(vif_list, i, vif) {
        
        strcpy(record->vif_param[i].record_id, json_string_value(json_object_get(vif, "recordId")));

        hidden = json_boolean_value(json_object_get(vif, "isHidden"));
        sprintf(record->vif_param[i].hide_ssid, "%d", hidden);
               
        strcpy(record->vif_param[i].ssid, json_string_value(json_object_get(vif, "ssid")));

        strcpy(record->vif_param[i].encryption, json_string_value(json_object_get(vif, "encryption")));
        strcpy(record->vif_param[i].forward_type, json_string_value(json_object_get(vif, "forwardType")));
        
        attr_value = json_object_get(vif, "key");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL) {
                strcpy(record->vif_param[i].key, value);
            }
        }
        
        attr_value = json_object_get(vif, "mobilityDomain");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL) {
                uint16_t md = mobility_domain_from_string(value);
                if (md == 0x0000)
                    md = 0x0001;
                snprintf(record->vif_param[i].mobility_id, sizeof(record->vif_param[i].mobility_id), "%04x", md);
            }
        }

        if (strncmp(record->vif_param[i].encryption, "wpa2-enterprise", 15) == 0
                || strncmp(record->vif_param[i].encryption, "wpa3-enterprise", 15) == 0) {
        
            attr_value = json_object_get(vif, "serverName");
            if (attr_value != NULL && json_is_string(attr_value)) {
                const char *value = json_string_value(attr_value);
                if (value != NULL) {
                    strcpy(record->vif_param[i].server_name, value);
                } 
            }
            
            attr_value = json_object_get(vif, "serverIp");
            if (attr_value != NULL && json_is_string(attr_value)) {
                const char *value = json_string_value(attr_value);
                if (value != NULL) {
                    strcpy(record->vif_param[i].server_ip, value);
                } 
            }
   
            attr_value = json_object_get(vif, "authPort");
            if (json_is_integer(attr_value)) {
                snprintf(record->vif_param[i].auth_port,
                         sizeof(record->vif_param[i].auth_port),
                         "%lld",
                         json_integer_value(attr_value));
            }

            attr_value = json_object_get(vif, "accountPort");
            if (json_is_integer(attr_value)) {
                snprintf(record->vif_param[i].acct_port,
                         sizeof(record->vif_param[i].acct_port),
                         "%lld",
                         json_integer_value(attr_value));
            }

            attr_value = json_object_get(vif, "communicateKey");
            if (attr_value != NULL && json_is_string(attr_value)) {
                const char *value = json_string_value(attr_value);
                if (value != NULL) {
                    strcpy(record->vif_param[i].secret_key, value);
                } 
            }
        }

        record->vif_param[i].is_uprate = false;
        attr_value = json_object_get(vif, "uprate");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL && strlen(value) > 0) {
                int uprate = atoi(value);
                if (uprate >= 0) {
                    record->vif_param[i].is_uprate = true;
                    record->vif_param[i].uprate = uprate;
                }
            }
        }

        record->vif_param[i].is_downrate = false;
        attr_value = json_object_get(vif, "downrate");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL && strlen(value) > 0) {
                int downrate = atoi(value);
                if (downrate >= 0) {
                    record->vif_param[i].is_downrate = true;
                    record->vif_param[i].downrate = downrate;
                }
            }
        }

        record->vif_param[i].is_wlan_uprate = false;
        attr_value = json_object_get(vif, "wlanUprate");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL && strlen(value) > 0) {
                int uprate = atoi(value);
                if (uprate >= 0) {
                    record->vif_param[i].is_wlan_uprate = true;
                    record->vif_param[i].wlan_uprate = uprate;
                }
            }
        }

        record->vif_param[i].is_wlan_downrate = false;
        attr_value = json_object_get(vif, "wlanDownrate");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL && strlen(value) > 0) {
                int downrate = atoi(value);
                if (downrate >= 0) {
                    record->vif_param[i].is_wlan_downrate = true;
                    record->vif_param[i].wlan_downrate = downrate;
                }
            }
        }
        
        int auth = json_boolean_value(json_object_get(vif, "isAuth"));
        record->vif_param[i].is_auth = auth;

        attr_value = json_object_get(vif, "authUrl");
        if (attr_value != NULL && json_is_string(attr_value)) {
            const char *value = json_string_value(attr_value);
            if (value != NULL) {
                strcpy(record->vif_param[i].auth_url, value);
            } 
        }

        int enable = json_boolean_value(json_object_get(vif, "enable"));
        sprintf(record->vif_param[i].enable, "%d", enable);

        int vlan_id = json_integer_value(json_object_get(vif, "vlanId"));
        sprintf(record->vif_param[i].vlan_id, "%d", vlan_id);
        
        strcpy(record->vif_param[i].device, json_string_value(json_object_get(vif, "radioType")));

        record->vif_param[i].status = json_integer_value(json_object_get(vif, "status"));

        n_vif++;
    }
    record->n_vif = n_vif;
    
    // Log parameters before setting
    LOG(INFO, "SET_VIF params n_vif=%d", n_vif);
    for (int j = 0; j < n_vif && j < sizeof(record->vif_param)/sizeof(record->vif_param[0]); j++) {
        LOG(INFO, "SET_VIF[%d] recordId=%s ssid=%s encryption=%s status=%d enable=%s vlanId=%s device=%s", 
            j, record->vif_param[j].record_id, record->vif_param[j].ssid, 
            record->vif_param[j].encryption, record->vif_param[j].status,
            record->vif_param[j].enable, record->vif_param[j].vlan_id, 
            record->vif_param[j].device);
    }
    
    ret = target_config_vif_set(record);
    free(record);
    return ret;
}


bool netconf_process_radio_list(json_t *radio_list)
{
    bool ret;
    int n_radio = 0;
    char record_id[12];
    int channel_width;
    int txpower;
    int disabled = 0;
    size_t i;
    radio_record_t *record = (radio_record_t *)malloc(sizeof(radio_record_t));
    
    // FIX: Add null check for malloc
    if (!record) {
        LOG(ERR, "Failed to allocate memory for radio_record_t");
        return false;
    }
    
    json_t *radio;
    json_array_foreach(radio_list, i, radio) {
        
        memset(&record_id, 0, sizeof(record_id));
        if( json_object_get(radio, "radioType") ) {
            strcpy(record->radio_param[i].radio_type, json_string_value(json_object_get(radio, "radioType")));
            if( strcmp(record->radio_param[i].radio_type, "2.4GHz") == 0){
                strcpy(record_id, "wifi1");
            } else if( strcmp(record->radio_param[i].radio_type, "5GHz") == 0 ){
                strcpy(record_id, "wifi0");
            }
            strcpy(record->radio_param[i].record_id, record_id);
        }

        if( json_object_get(radio, "status")) { 
            record->radio_param[i].status = json_integer_value(json_object_get(radio, "status"));
        }


        if (json_object_get(radio, "channel")) {
            const char *ch_str = json_string_value(json_object_get(radio, "channel"));

            if (ch_str && ch_str[0] != '\0') {
                snprintf(record->radio_param[i].channel,
                            sizeof(record->radio_param[i].channel),
                            "%s", ch_str);

                record->radio_param[i].status = RADIO_SETTING_SECONDARY;
            }
        }

        if( json_object_get(radio, "txpower")) {
            json_t *j_txpower = json_object_get(radio, "txpower");
            if (j_txpower && !json_is_null(j_txpower)) {
                txpower = atoi(json_string_value(json_object_get(radio, "txpower")));
                if ( txpower > 0 ) {
                    strcpy(record->radio_param[i].txpower, json_string_value(json_object_get(radio, "txpower")));
                    record->radio_param[i].status = RADIO_SETTING_SECONDARY;
                }
            }
        }
        
        if( json_object_get(radio, "disabled")) { 
            const char *disabled_str = json_string_value(json_object_get(radio, "disabled"));

            if (disabled_str && strcmp(disabled_str, "True") == 0) {
                disabled = 0;  
            } else if (disabled_str && strcmp(disabled_str, "False") == 0) {
                disabled = 1;  
            }
            sprintf(record->radio_param[i].disabled, "%d", disabled);    
        }

        if( json_object_get(radio, "country")) { 
            strcpy(record->radio_param[i].country, json_string_value(json_object_get(radio, "country")));
        }

        if( json_object_get(radio, "channelWidth")) { 
            channel_width = json_integer_value(json_object_get(radio, "channelWidth"));
            sprintf(record->radio_param[i].channel_width, "%d", channel_width);
        }

        if( json_object_get(radio, "userlimit")) { 
            strcpy(record->radio_param[i].user_limit, json_string_value(json_object_get(radio, "userlimit")));
        }

        if( json_object_get(radio, "hwmode")) { 
            strcpy(record->radio_param[i].hwmode, json_string_value(json_object_get(radio, "hwmode")));
        }

        n_radio++;
    }
    record->n_radio = n_radio;
    
    // Log parameters before setting
    LOG(INFO, "SET_RADIO params n_radio=%d", n_radio);
    for (int j = 0; j < n_radio && j < sizeof(record->radio_param)/sizeof(record->radio_param[0]); j++) {
        LOG(INFO, "SET_RADIO[%d] recordId=%s radioType=%s channel=%s txpower=%s disabled=%s country=%s channelWidth=%s", 
            j, record->radio_param[j].record_id, record->radio_param[j].radio_type,
            record->radio_param[j].channel, record->radio_param[j].txpower,
            record->radio_param[j].disabled, record->radio_param[j].country,
            record->radio_param[j].channel_width);
    }
    
    ret = target_config_radio_set(record);
    free(record);
    return ret;
}


bool netconf_process_blacklist(json_t *blackList)
{
    char tmp_mac[32];
    char type[16];
    strlcpy(type, json_string_value(json_object_get(blackList, "type")), sizeof(type));
    json_t *add_list = json_object_get(blackList, "add");
    if (json_is_array(add_list)) {
        printf("MAC addresses to add:\n");
        LOG(INFO, "SET_ACL blacklist add count=%zu type=%s", json_array_size(add_list), type);
        for (size_t i = 0; i < json_array_size(add_list); i++) {
            json_t *mac = json_array_get(add_list, i);
            if (json_is_string(mac)) {
                printf("%s\n", json_string_value(mac));
                memset(tmp_mac, 0, sizeof(tmp_mac));
                strcpy(tmp_mac, json_string_value(mac));
                if (strncmp(type, "ssid", 4) == 0) {
                    char ssid[64];
                    strlcpy(ssid, json_string_value(json_object_get(blackList, "ssid")), sizeof(ssid));
                    LOG(INFO, "SET_ACL blacklist add_ssid mac=%s ssid=%s", tmp_mac, ssid);
                    netconf_handle_add_blacklist_ssid(tmp_mac, ssid);
                } else {
                    LOG(INFO, "SET_ACL blacklist add mac=%s", tmp_mac);
                    netconf_handle_add_blacklist(tmp_mac);
                }
            }
        }
    }

    json_t *remove_list = json_object_get(blackList, "remove");
    if (json_is_array(remove_list)) {
        printf("MAC addresses to remove:\n");
        LOG(INFO, "SET_ACL blacklist remove count=%zu", json_array_size(remove_list));
        for (size_t i = 0; i < json_array_size(remove_list); i++) {
            json_t *mac = json_array_get(remove_list, i);
            if (json_is_string(mac)) {
                printf("%s\n", json_string_value(mac));
                memset(tmp_mac, 0, sizeof(tmp_mac));
                strcpy(tmp_mac, json_string_value(mac));
                LOG(INFO, "SET_ACL blacklist remove mac=%s", tmp_mac);
                netconf_handle_remove_blacklist(tmp_mac);
            }
        }
    }
    return true;
}

int netconf_process_whitelist(json_t *whiteList)
{
    char tmp_mac[32];
    char type[16];
    strlcpy(type, json_string_value(json_object_get(whiteList, "type")), sizeof(type));
    json_t *add_list = json_object_get(whiteList, "add");
    if (json_is_array(add_list)) {
        printf("MAC addresses to add:\n");
        LOG(INFO, "SET_ACL whitelist add count=%zu type=%s", json_array_size(add_list), type);
        for (size_t i = 0; i < json_array_size(add_list); i++) {
            json_t *mac = json_array_get(add_list, i);
            if (json_is_string(mac)) {
                printf("%s\n", json_string_value(mac));
                memset(tmp_mac, 0, sizeof(tmp_mac));
                strcpy(tmp_mac, json_string_value(mac));
                if (strncmp(type, "ssid", 4) == 0) {
                    char ssid[64];
                    strlcpy(ssid, json_string_value(json_object_get(whiteList, "ssid")), sizeof(ssid));
                    LOG(INFO, "SET_ACL whitelist add_ssid mac=%s ssid=%s", tmp_mac, ssid);
                    netconf_handle_add_whitelist_ssid(tmp_mac, ssid);
                } else {
                    LOG(INFO, "SET_ACL whitelist add mac=%s", tmp_mac);
                    netconf_handle_add_whitelist(tmp_mac);
                }
            }
        }
    }

    json_t *remove_list = json_object_get(whiteList, "remove");
    if (json_is_array(remove_list)) {
        printf("MAC addresses to remove:\n");
        LOG(INFO, "SET_ACL whitelist remove count=%zu", json_array_size(remove_list));
        for (size_t i = 0; i < json_array_size(remove_list); i++) {
            json_t *mac = json_array_get(remove_list, i);
            if (json_is_string(mac)) {
                printf("%s\n", json_string_value(mac));
                memset(tmp_mac, 0, sizeof(tmp_mac));
                strcpy(tmp_mac, json_string_value(mac));
                LOG(INFO, "SET_ACL whitelist remove mac=%s", tmp_mac);
                netconf_handle_remove_whitelist(tmp_mac);
            }
        }
    }
    return true;

}

int netconf_process_nat_config(json_t *nat_config)
{
    int ret;
    nat_config_t config;

    json_t *netSegmentIp = json_object_get(nat_config, "netSegmentIp");
    if (!netSegmentIp || json_is_null(netSegmentIp)) {
        printf("netSegmentIp is NULL\n");
        return -1;
    } else if (json_is_string(netSegmentIp)) {
        printf("netSegmentIp: %s\n", json_string_value(netSegmentIp));
        strncpy(config.ipaddr, json_string_value(netSegmentIp), sizeof(config.ipaddr) - 1);
        config.ipaddr[sizeof(config.ipaddr) - 1] = '\0';  // Ensure null termination
    } else {
        printf("Error: 'netSegmentIp' is not a string\n");
    }

    json_t *netMaskIp = json_object_get(nat_config, "netMaskIp");
    if (!netMaskIp || json_is_null(netMaskIp)) {
        printf("netMaskIp is NULL\n");
    } else if (json_is_string(netMaskIp)) {
        printf("netMaskIp: %s\n", json_string_value(netMaskIp));
        strncpy(config.netmask, json_string_value(netMaskIp), sizeof(config.netmask) - 1);
        config.netmask[sizeof(config.netmask) - 1] = '\0';  // Ensure null termination
    } else {
        printf("Error: 'netMaskIp' is not a string\n");
    }

    ret = netconf_handle_nat_config(&config);

    json_t *roaming = json_object_get(nat_config, "l2Roaming");
    if (!roaming || json_is_null(roaming)) {
        printf("l2Roaming is NULL\n");
    } else {

        int new_roaming_status = json_boolean_value(roaming);
        if (new_roaming_status != current_roaming_status) {
            ret = target_set_roaming_status(new_roaming_status);
            current_roaming_status = new_roaming_status;
        }
    }

    return ret;
}

int netconf_process_set_msg(char* buf)
{
    int ret;
    json_error_t error;
    json_t *root = json_loads(buf, 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return false;
    }
 
    json_t *nat_config = json_object_get(root, "natConfig");      
    if (nat_config) {
        ret = netconf_process_nat_config(nat_config);
    }

    json_t *vif_list = json_object_get(json_object_get(root, "vif"), "vifList");      
    if (vif_list && json_is_array(vif_list)) {
        ret = netconf_process_vif_list(vif_list);
    }
    
    json_t *radio_list = json_object_get(json_object_get(root, "radio"), "radioList");
    if (radio_list && json_is_array(radio_list)) {
        ret = netconf_process_radio_list(radio_list);
    }

    json_decref(root);
#ifdef CONFIG_PLATFORM_MTK_JEDI
    netconf_apply_jedi_conf();
#endif
    return ret;
}

int netconf_process_acl_msg(char *buf)
{
    json_error_t error;
    json_t *root = json_loads(buf, 0, &error);

    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return false;
    }
    
    json_t *blackList = json_object_get(root, "blackList");
    if (blackList) {
        netconf_process_blacklist(blackList);
    }

    json_t *whiteList = json_object_get(root, "whiteList");
    if (whiteList) {
        netconf_process_whitelist(whiteList);
    }

    json_decref(root);
    
#ifdef CONFIG_PLATFORM_MTK_JEDI
    netconf_check_wifi_config();
#endif

    return true;
}

int netconf_process_user_rl_msg(char *buf)
{
    int uplink, downlink;
    char tmp_mac[32];
    //mac_address_t    mac;
    os_macaddr_t mac;

    json_error_t error;
    json_t *root = json_loads(buf, 0, &error);

    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return false;
    }

    json_t *rate_limit = json_object_get(root, "rateLimit");
    if (rate_limit) {
        strcpy(tmp_mac, json_string_value(json_object_get(rate_limit, "mac")));
        uplink = atoi(json_string_value(json_object_get(rate_limit, "uplink")));
        downlink = atoi(json_string_value(json_object_get(rate_limit, "downlink")));
    }
    
    os_nif_macaddr_from_str(&mac, tmp_mac); 
    
    // Log parameters before setting
    LOG(INFO, "SET_USER_RL mac=%s uplink=%d downlink=%d", tmp_mac, uplink, downlink);
   
    if (uplink >= 0 || downlink >= 0) {
        air_user_rate_limit(mac.addr,
                       uplink >= 0 ? uplink : 0,
                       downlink >= 0 ? downlink : 0);
    }

    json_decref(root);
    return true;
}
