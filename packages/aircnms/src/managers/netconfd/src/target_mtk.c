#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "uci_ops.h"  
#include "netconf.h"

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"

uint32_t flags = 0;  // Global variable

bool set_intf_reset_progress_indication(netconf_intf_reset_t reset)
{
    FILE *fp = fopen("/tmp/intf_reset_progress_indication", "w");
    if (fp == NULL) {
        perror("fopen");
        return false;
    }

    if (fprintf(fp, "%d", reset ? 1 : 0) < 0) {
        perror("fprintf");
        fclose(fp);
        return false;
    }

    fclose(fp);

    return true;
}


bool target_config_radio_get(radio_record_t *record)
{
    struct airpro_mgr_wlan_radio_params rad_params;
    int rid = 0;
    char radio_name[8] = {0};

    memset(record, 0, sizeof(*record));
    record->n_radio = 2; //set a macro for num radios
    for (rid = 0; rid < 2; rid++) {
        sprintf(radio_name, "radio%d", rid);
        memset(&rad_params, 0, sizeof(struct airpro_mgr_wlan_radio_params));
        uci_get_radio_params(radio_name, &rad_params);
        
        //fill radio params to ctx
        memcpy(&record->radio_param[rid], &rad_params, sizeof(struct airpro_mgr_wlan_radio_params));
        strcpy(record->radio_param[rid].radio_type, radio_name);
    }
    return true;

}

bool target_config_vif_get(vif_record_t *record)
{
    struct airpro_mgr_get_all_uci_section_names sec_arr_names;
    struct airpro_mgr_wlan_vap_params vif_params;
    int vid = 0;
    char *pkg = "wireless";
    char *sec_type = "wifi-iface";
    //char param[20];
    memset(&sec_arr_names, 0, sizeof(struct airpro_mgr_get_all_uci_section_names));
    uci_get_all_section_names(pkg, sec_type, &sec_arr_names);

    record->n_vif = sec_arr_names.num_entry;
    for (vid = 0; vid < record->n_vif; vid++) {

        memset(&vif_params, 0,sizeof(struct airpro_mgr_wlan_vap_params));
        uci_get_vap_params(sec_arr_names.sec_name[vid], &vif_params);
        
        memcpy(&record->vif_param[vid], &vif_params, sizeof(struct airpro_mgr_wlan_vap_params));
        strcpy(record->vif_param[vid].record_id, sec_arr_names.sec_name[vid]);
    }

    return true;
}

void get_ht_mode(char *htmode, struct airpro_mgr_wlan_radio_params rp, char *radio_name)
{
    char hwmode_brd[8];
    if ( strcmp(radio_name, "wifi1") == 0) {//2.4ghz
        if (strcmp(rp.hwmode, "11BGN") == 0) {
            strcpy(hwmode_brd, "11ng");
        } else if(strcmp(rp.hwmode, "11AX") == 0) {
            strcpy(hwmode_brd, "11axg");
        } else if(strcmp(rp.hwmode, "11BGN_11AX") == 0) {
            strcpy(hwmode_brd, "11axg");
        }
 
    } else if (strcmp(radio_name, "wifi0") == 0) {//5ghz
        if(strcmp(rp.hwmode, "11NA") == 0){
            strcpy(hwmode_brd, "11na");
        } else if(strcmp(rp.hwmode, "11AC") == 0){
            strcpy(hwmode_brd, "11ac");
        } else if(strcmp(rp.hwmode, "11AX") == 0) {
            strcpy(hwmode_brd, "11axa");
        } else if(strcmp(rp.hwmode, "11NA_11AC_11AX") == 0){
            strcpy(hwmode_brd, "11axa");
        }
    } 

    if (strcmp(hwmode_brd, "11ng") == 0) {
        sprintf(htmode, "HT%s", rp.channel_width);
    } else if(strcmp(hwmode_brd, "11na") == 0) {
        sprintf(htmode, "HT%s", rp.channel_width);
    } else if(strcmp(hwmode_brd, "11axa") == 0) {
        sprintf(htmode, "HE%s", rp.channel_width);
    } else if(strcmp(hwmode_brd, "11axg") == 0) {
        sprintf(htmode, "HE%s", rp.channel_width);
    } else if(strcmp(hwmode_brd, "11ac") == 0){
        sprintf(htmode, "VHT%s", rp.channel_width);
    }
}

int util_chan_to_freq(int chan)
{
    if (chan == 14)
        return 2484;
    else if (chan < 14)
        return 2407 + chan * 5;
    else if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
    else
        return 5000 + chan * 5;
    return 0;
}

bool hostapd_chan_switch(char *radio_name, int channel)
{
    //int freq;
    char ifname[12];
    char phyname[8];
    //char cmd[256];

    //freq = 0;
    //freq = util_chan_to_freq(channel);

    if (strcmp(radio_name, "wifi0") == 0) {
        strcpy(ifname, "phy1-ap0");
        strcpy(phyname, "phy1");
    } else if (strcmp(radio_name, "wifi1") == 0) {
        strcpy(ifname, "phy0-ap0");
        strcpy(phyname, "phy0");
    }

    //snprintf(cmd, sizeof(cmd),
      //       "timeout -s KILL 3 hostapd_cli -p /var/run/hostapd -i %s chan_switch 5 %d",
        //      ifname, freq);
#if 0
    sprintf(cmd, "timeout -s KILL 3 hostapd_cli -i %s chan_switch 5 %d", ifname, freq);
    printf("Applying: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to set channel for %s (ret=%d)\n", ifname, ret);
        return false;
    }
#endif
    return true;
}

bool hostapd_set_txpower(const char *radio_name, int txpower_dbm)
{
    char phyname[8];
    char cmd[256];
    int txpower_mbm;
    const int TXPOWER_MIN_DBM = 0;   // adjust as needed (some chipsets min 5–10)
    const int TXPOWER_MAX_DBM = 23;  // MT7915 typical max

    // Map radio name to interface
    if (strcmp(radio_name, "wifi0") == 0) {
        strcpy(phyname, "phy1");
    } else if (strcmp(radio_name, "wifi1") == 0) {
        strcpy(phyname, "phy0");
    } else {
        fprintf(stderr, "Unknown radio name: %s\n", radio_name);
        return false;
    }

    // Clamp value within allowed range
    if (txpower_dbm > TXPOWER_MAX_DBM)
        txpower_dbm = TXPOWER_MAX_DBM;
    else if (txpower_dbm < TXPOWER_MIN_DBM)
        txpower_dbm = TXPOWER_MIN_DBM;

    // Convert dBm → mBm (multiply by 100)
    txpower_mbm = txpower_dbm * 100;

    // Build iw command
    snprintf(cmd, sizeof(cmd), "iw dev %s set txpower fixed %d", phyname, txpower_mbm);
    printf("Applying: %s\n", cmd);

    // Execute command
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to set txpower for %s (ret=%d)\n", phyname, ret);
        return false;
    }

    return true;
}

bool target_config_radio_set(radio_record_t *record)
{
    struct airpro_mgr_wlan_radio_params rad_params;
    char cmd[256];
    int rid = 0;
    char radio_name[8] = {0};
    int ret;

    for (rid = 0; rid < 2; rid++) {
        if (record->radio_param[rid].status == RADIO_SETTING_PRIMARY ) {
        
            memset(&rad_params, 0, sizeof(struct airpro_mgr_wlan_radio_params));
            
            memset(&radio_name, 0, sizeof(radio_name));
            strcpy(radio_name, record->radio_param[rid].record_id);
        
            strcpy(rad_params.country, record->radio_param[rid].country);
        
            strcpy(rad_params.disabled, record->radio_param[rid].disabled);
            strcpy(rad_params.channel_width, record->radio_param[rid].channel_width);
            strcpy(rad_params.hwmode, record->radio_param[rid].hwmode);

            char param[20];
            memset(param, 0, sizeof(param));
            get_ht_mode(param, rad_params, radio_name);
            strcpy(rad_params.htmode, param);

            ret = uci_set_radio_params(radio_name, &rad_params);
            
            memset(cmd, 0, sizeof(cmd));
            sprintf(cmd, "wifi reload %s", radio_name);

            int rc = system(cmd);
            (void)rc;  // System call result may be checked in future
#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_primary_radio_params(radio_name, &rad_params);            
#endif

        } else if (record->radio_param[rid].status == RADIO_SETTING_SECONDARY) {
            memset(&rad_params, 0, sizeof(struct airpro_mgr_wlan_radio_params));
            
            memset(&radio_name, 0, sizeof(radio_name));
            strcpy(radio_name, record->radio_param[rid].record_id);
        
            strcpy(rad_params.channel, record->radio_param[rid].channel);
            strcpy(rad_params.txpower, record->radio_param[rid].txpower);

            ret = uci_set_radio_params(radio_name, &rad_params);

            ret = hostapd_chan_switch(radio_name, atoi(rad_params.channel));
            ret = hostapd_set_txpower(radio_name, atoi(rad_params.txpower));
            //memset(cmd, 0, sizeof(cmd));
            //sprintf(cmd, "wifi reload %s", radio_name);

            //int rc = system(cmd);
            //(void)rc;  // System call result may be checked in future
#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_secondary_radio_params(radio_name, &rad_params);            
#endif

        }
    }
    return ret;
}

void get_encryption_type(char *encrypt_type, const char *encryption)
{

    if (strncmp(encryption, "open", 4) == 0)
        strncpy(encrypt_type, "none", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa-psk", 7) == 0)
        strncpy(encrypt_type, "psk", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa2-psk", 8) == 0)
        strncpy(encrypt_type, "psk2", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa3-psk", 8) == 0)
        strncpy(encrypt_type, "sae", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa/wpa2-psk", 12) == 0)
        strncpy(encrypt_type, "psk-mixed", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa2/wpa3-psk", 13) == 0)
        strncpy(encrypt_type, "sae-mixed", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa2-enterprise", 15) == 0)
        strncpy(encrypt_type, "wpa2", ENCRYPT_TYPE_MAX_LEN);
    else if (strncmp(encryption, "wpa3-enterprise", 15) == 0)
        strncpy(encrypt_type, "wpa3", ENCRYPT_TYPE_MAX_LEN);
    else
        strncpy(encrypt_type, "none", ENCRYPT_TYPE_MAX_LEN);

    encrypt_type[ENCRYPT_TYPE_MAX_LEN - 1] = '\0'; // ensure null-termination
}

bool target_config_vif_set(vif_record_t *record)
{
    struct airpro_mgr_wlan_vap_params vif_params;
    char cmd[256];
    int vid = 0;
    int rc;
    char vif_name[8] = {0};

    for (vid = 0; vid < record->n_vif; vid++) {
        
        if ( record->vif_param[vid].status == VIF_ADD ) {
            //ADD 1
            memset(vif_name, 0, sizeof(vif_name));
            memset(&vif_params, 0, sizeof(vif_params));
            
            strlcpy(vif_name, record->vif_param[vid].record_id, sizeof(vif_name));
            strlcpy(vif_params.record_id, record->vif_param[vid].record_id, sizeof(vif_params.record_id));
            
            strlcpy(vif_params.ssid, record->vif_param[vid].ssid, sizeof(vif_params.ssid));
            
            strlcpy(vif_params.key, record->vif_param[vid].key, sizeof(vif_params.key));
        
            get_encryption_type(vif_params.encryption, record->vif_param[vid].encryption);
            
            strlcpy(vif_params.hide_ssid, record->vif_param[vid].hide_ssid, sizeof(vif_params.hide_ssid));
            
            strlcpy(vif_params.disabled, "0", sizeof(vif_params.disabled));
            
            strlcpy(vif_params.forward_type,  record->vif_param[vid].forward_type, sizeof(vif_params.forward_type)); 
            
            strlcpy(vif_params.vlan_id,  record->vif_param[vid].vlan_id, sizeof(vif_params.vlan_id)); 
        
            if (strncmp(record->vif_param[vid].encryption, "wpa2-enterprise", 15) == 0
                || strncmp(record->vif_param[vid].encryption, "wpa3-enterprise", 15) == 0) {
        
                    strlcpy(vif_params.server_ip, record->vif_param[vid].server_ip, sizeof(vif_params.server_ip));
                    
                    strlcpy(vif_params.auth_port, record->vif_param[vid].auth_port, sizeof(vif_params.auth_port));
                                       
                    strlcpy(vif_params.acct_port, record->vif_param[vid].acct_port, sizeof(vif_params.acct_port));
                    
                    strlcpy(vif_params.secret_key, record->vif_param[vid].secret_key, sizeof(vif_params.secret_key));
            } else {
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.auth_server", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.acct_server", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.auth_port", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.acct_server", vif_name);
                    rc = system(cmd);
                    
            }

#ifdef CONFIG_PLATFORM_MTK 
            if( strcmp(vif_params.forward_type, "Bridge") == 0) {
                int vlan = atoi(record->vif_param[vid].vlan_id);
                if (vlan == 0) {
                    check_existing_vlan(vif_name);
                    strlcpy(vif_params.network, "lan", sizeof(vif_params.network));
                } else if (vlan > 0) {
                    check_existing_vlan(vif_name);
                    set_vlan_network(vlan, vif_name);
                    strlcpy(vif_params.network, record->vif_param[vid].vlan_id, sizeof(vif_params.network));
                    strlcpy(vif_params.vlan_id, record->vif_param[vid].vlan_id, sizeof(vif_params.vlan_id));
                }
            }

            if( strcmp(vif_params.forward_type, "NAT") == 0 && (record->vif_param[vid].is_auth == false)) {
                printf("Ankit: nat true auth false\n");
                strlcpy(vif_params.network, "nat_network", sizeof(vif_params.network));
                //rc = system("ifup nat_network");
                //if (rc == 0) {
                  //  sleep(3);
                //}
            } else {
                strlcpy(vif_params.network, "lan", sizeof(vif_params.network));
            }
#endif
            
            rc = uci_set_vap_params(vif_name, &vif_params);

            memset(cmd, 0, sizeof(cmd));
            sprintf(cmd, "wifi reload %s", vif_name);
            rc = system(cmd);
            if (rc == 0) {
                sleep(3);
            }

            vif_params.is_uprate = record->vif_param[vid].is_uprate;
            vif_params.uprate = record->vif_param[vid].uprate; 
            vif_params.is_downrate = record->vif_param[vid].is_downrate;
            vif_params.downrate = record->vif_param[vid].downrate;
            vif_params.is_auth = record->vif_param[vid].is_auth;
            strlcpy(vif_params.auth_url, record->vif_param[vid].auth_url, sizeof(vif_params.auth_url));

#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_vap_params(vif_name, &vif_params);            
#endif

#ifdef CONFIG_PLATFORM_MTK 
            // Single call to set both uplink and downlink
            air_interface_rate_limit(vif_name, 
                        record->vif_param[vid].is_uprate ? record->vif_param[vid].uprate : 0,
                        record->vif_param[vid].is_downrate ? record->vif_param[vid].downrate : 0,
                        "wlan");
            air_interface_rate_limit(vif_name, 
                        record->vif_param[vid].is_wlan_uprate ? record->vif_param[vid].wlan_uprate : 0,
                        record->vif_param[vid].is_wlan_downrate ? record->vif_param[vid].wlan_downrate : 0,
                        "wlan_per_user");

            //CAPTIVE PORTAL
            //netconf_handle_captive_portal(vif_name, &vif_params);
#endif

        } else if( record->vif_param[vid].status == VIF_DISABLE ) {
            //DISABLE 2
            memset(vif_name, 0, sizeof(vif_name));
            memset(&vif_params, 0, sizeof(vif_params));
            
            strlcpy(vif_name, record->vif_param[vid].record_id, sizeof(vif_name));
            strlcpy(vif_params.record_id, record->vif_param[vid].record_id, sizeof(vif_params.record_id));
            
            strlcpy(vif_params.disabled, "1", sizeof(vif_params.disabled));
            //CAPTIVE PORTAL
            netconf_handle_captive_portal(vif_name, &vif_params);
            uci_set_vap_params(vif_name, &vif_params);
            
            memset(cmd, 0, sizeof(cmd));
            sprintf(cmd, "wifi reload %s", vif_name);
            rc = system(cmd);
            if (rc == 0) {
                sleep(3);
            }
#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_del_vap_params(vif_name, &vif_params);            
#endif
        
        } else if( record->vif_param[vid].status == VIF_MODIFY ) {
            //MODIFY 3
            memset(vif_name, 0, sizeof(vif_name));
            memset(&vif_params, 0, sizeof(vif_params));
            
            strlcpy(vif_name, record->vif_param[vid].record_id, sizeof(vif_name));
            strlcpy(vif_params.record_id, record->vif_param[vid].record_id, sizeof(vif_params.record_id));
            
            strlcpy(vif_params.ssid, record->vif_param[vid].ssid, sizeof(vif_params.ssid));
            
            strlcpy(vif_params.key, record->vif_param[vid].key, sizeof(vif_params.key));
        
            get_encryption_type(vif_params.encryption, record->vif_param[vid].encryption);
            
            strlcpy(vif_params.hide_ssid, record->vif_param[vid].hide_ssid, sizeof(vif_params.hide_ssid));
            
            strlcpy(vif_params.disabled, "0", sizeof(vif_params.disabled));
            
            strlcpy(vif_params.forward_type,  record->vif_param[vid].forward_type, sizeof(vif_params.forward_type)); 
            
            strlcpy(vif_params.vlan_id,  record->vif_param[vid].vlan_id, sizeof(vif_params.vlan_id)); 
            
            if (strncmp(record->vif_param[vid].encryption, "wpa2-enterprise", 15) == 0
                || strncmp(record->vif_param[vid].encryption, "wpa3-enterprise", 15) == 0) {
        
                    strlcpy(vif_params.server_ip, record->vif_param[vid].server_ip, sizeof(vif_params.server_ip));
                    
                    strlcpy(vif_params.auth_port, record->vif_param[vid].auth_port, sizeof(vif_params.auth_port));
                                       
                    strlcpy(vif_params.acct_port, record->vif_param[vid].acct_port, sizeof(vif_params.acct_port));
                    
                    strlcpy(vif_params.secret_key, record->vif_param[vid].secret_key, sizeof(vif_params.secret_key));
            } else {
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.auth_server", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.acct_server", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.auth_port", vif_name);
                    rc = system(cmd);
                    
                    memset(cmd, 0, sizeof(cmd));
                    sprintf(cmd, "uci del wireless.%s.acct_server", vif_name);
                    rc = system(cmd);
            }
            
#ifdef CONFIG_PLATFORM_MTK 
            if( strcmp(record->vif_param[vid].forward_type, "Bridge") == 0) {
                int vlan = atoi(record->vif_param[vid].vlan_id);
                if (vlan == 0) {
                    check_existing_vlan(vif_name);
                    strlcpy(vif_params.network, "lan", sizeof(vif_params.network));
                } else if (vlan > 0) {
                    check_existing_vlan(vif_name);
                    set_vlan_network(vlan, vif_name);
                    strlcpy(vif_params.network, record->vif_param[vid].vlan_id, sizeof(vif_params.network));
                    strlcpy(vif_params.vlan_id, record->vif_param[vid].vlan_id, sizeof(vif_params.vlan_id));
                }
            }

            if( strcmp(vif_params.forward_type, "NAT") == 0 && (record->vif_param[vid].is_auth == false)) {
                printf("Ankit: nat true auth false\n");
                strlcpy(vif_params.network, "nat_network", sizeof(vif_params.network));
                //rc = system("ifup nat_network");
                //if (rc == 0) {
                  //  sleep(3);
                //}
            } else {
                strlcpy(vif_params.network, "lan", sizeof(vif_params.network));
            }
#endif

            uci_set_vap_params(vif_name, &vif_params);
            
            memset(cmd, 0, sizeof(cmd));
            sprintf(cmd, "wifi reload %s", vif_name);
            rc = system(cmd);
            if (rc == 0) {
                sleep(3);
            }
            
            vif_params.is_uprate = record->vif_param[vid].is_uprate;
            vif_params.uprate = record->vif_param[vid].uprate; 
            vif_params.is_downrate = record->vif_param[vid].is_downrate;
            vif_params.downrate = record->vif_param[vid].downrate;
            vif_params.is_auth = record->vif_param[vid].is_auth;
            strlcpy(vif_params.auth_url, record->vif_param[vid].auth_url, sizeof(vif_params.auth_url));

#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_vap_params(vif_name, &vif_params);            
#endif

#ifdef CONFIG_PLATFORM_MTK 
            air_interface_rate_limit(vif_name, 
                        record->vif_param[vid].is_uprate ? record->vif_param[vid].uprate : 0,
                        record->vif_param[vid].is_downrate ? record->vif_param[vid].downrate : 0,
                        "wlan");
            air_interface_rate_limit(vif_name, 
                        record->vif_param[vid].is_wlan_uprate ? record->vif_param[vid].wlan_uprate : 0,
                        record->vif_param[vid].is_wlan_downrate ? record->vif_param[vid].wlan_downrate : 0,
                        "wlan_per_user");
            
            //CAPTIVE PORTAL
            //netconf_handle_captive_portal(vif_name, &vif_params);
#endif

        }
    }

    return true;
}
