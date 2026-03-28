#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "uci_ops.h"  
#include "netconf.h"

#define HOSTAPD_CONTROL_PATH_DEFAULT "/var/run"

uint32_t flags = 0;  // Global variable

static void str_trim(char *s)
{
    if (!s) return;

    /* trim trailing whitespace */
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' '  || s[len-1] == '\t')) {
        s[--len] = '\0';
    }
}

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

bool hostapd_set_txpower(const char *radio_name, int txpower_dbm)
{
    char phyname[12];
    char cmd[256];
    int txpower_mbm;
    const int TXPOWER_MIN_DBM = 0;   // adjust as needed (some chipsets min 5–10)
    const int TXPOWER_MAX_DBM = 23;  // MT7915 typical max

    // Map radio name to interface
    if (strcmp(radio_name, "wifi0") == 0) {
        strcpy(phyname, "phy1-ap0");
    } else if (strcmp(radio_name, "wifi1") == 0) {
        strcpy(phyname, "phy0-ap0");
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

    // Execute command
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to set txpower for %s (ret=%d)\n", phyname, ret);
        return false;
    }

    return true;
}

bool radio_params_match(const char *radio_name,
                        const struct airpro_mgr_wlan_radio_params *rad_params)
{
    char cmd[128];
    char cur_channel[32] = {0};
    char cur_txpower[32] = {0};

    /* ---- get channel ---- */
    snprintf(cmd, sizeof(cmd),
             "uci get wireless.%s.channel 2>/dev/null",
             radio_name);

    if (execute_uci_command(cmd, cur_channel, sizeof(cur_channel)) != 0) {
        return false;
    }
    str_trim(cur_channel);

    /* ---- get txpower ---- */
    snprintf(cmd, sizeof(cmd),
             "uci get wireless.%s.txpower 2>/dev/null",
             radio_name);
    
    if (execute_uci_command(cmd, cur_txpower, sizeof(cur_txpower)) != 0) {
        return false;
    }
    str_trim(cur_txpower);

    /* ---- compare ---- */
    if (strcmp(cur_channel, rad_params->channel) == 0 &&
        strcmp(cur_txpower, rad_params->txpower) == 0) {
        /* SAME → continue */
        return true;
    }

    return false;
}


bool target_config_radio_set(radio_record_t *record)
{
    struct airpro_mgr_wlan_radio_params rad_params;
    bool do_wifi_reload = false;
    int rid = 0;
    char radio_name[8] = {0};
    char phyname[8] = {0};
    int ret;

    for (rid = 0; rid < 2; rid++) {
        if (strcmp(record->radio_param[rid].record_id, "wifi1") == 0) {
            strcpy(phyname, "2.4GHz");
        } else if (strcmp(record->radio_param[rid].record_id, "wifi0") == 0) {
            strcpy(phyname, "5GHz");
        }

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

            if (!sanitize_and_validate_primary_radio_settings(phyname, &rad_params)) {
                printf("Invalid primary radio config for %s — skipping\n", radio_name);
                continue;
            }

            if (strcmp(phyname, "2.4GHz") == 0) {
                if (strcmp(rad_params.channel_width, "20") == 0) {
                    snprintf(rad_params.noscan, sizeof(rad_params.noscan), "%d", 0);
                } else if (strcmp(rad_params.channel_width, "40") == 0) {
                    snprintf(rad_params.noscan, sizeof(rad_params.noscan), "%d", 1);
                }
            }

            ret = uci_set_radio_params(radio_name, &rad_params);
            
            do_wifi_reload = true;
#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_primary_radio_params(radio_name, &rad_params);            
#endif

        } else if (record->radio_param[rid].status == RADIO_SETTING_SECONDARY) {
            memset(&rad_params, 0, sizeof(struct airpro_mgr_wlan_radio_params));
            
            memset(&radio_name, 0, sizeof(radio_name));
            strcpy(radio_name, record->radio_param[rid].record_id);
        
            strcpy(rad_params.channel, record->radio_param[rid].channel);
            strcpy(rad_params.txpower, record->radio_param[rid].txpower);
         
            if (radio_params_match(radio_name, &rad_params)) {
                continue;
            }

            if (!sanitize_and_validate_secondary_radio_settings(radio_name, phyname, &rad_params)) {
                printf(" Invalid secondary radio config for %s — skipping\n", radio_name);
                continue;
            }

            ret = uci_set_radio_params(radio_name, &rad_params);

            if (strcmp(rad_params.channel, "auto") == 0) {
                do_wifi_reload = true;
            } else {
                // Channel switch with error handling
                printf("Applying channel switch for %s to channel %s\n", radio_name, rad_params.channel);
                ret = target_chan_switch(radio_name, atoi(rad_params.channel));
                if (!ret) {
                    fprintf(stderr, "ERROR: Channel switch failed for %s to channel %s\n", 
                            radio_name, rad_params.channel);
                    // Continue to next radio instead of failing completely
                } else {
                    printf("Channel switch successful for %s\n", radio_name);
                }
            }
            sleep(3); 
            // TX power setting with error handling
            printf("Applying TX power for %s to %s dBm\n", radio_name, rad_params.txpower);
            ret = hostapd_set_txpower(radio_name, atoi(rad_params.txpower));
            if (!ret) {
                fprintf(stderr, "ERROR: TX power setting failed for %s to %s dBm\\n",
                        radio_name, rad_params.txpower);
            } else {
                printf("TX power setting successful for %s\\n", radio_name);
            }

#ifdef CONFIG_PLATFORM_MTK_JEDI
            jedi_set_secondary_radio_params(radio_name, &rad_params);            
#endif

        }
    }

    if (do_wifi_reload) {
        //memset(cmd, 0, sizeof(cmd));
        //sprintf(cmd, "wifi");

        int rc = system("wifi");
        if (rc == 0) {
            sleep(3);
        }
    }

    return ret;
}

/* Day-name → 3-letter UCI abbreviation */
static const char *day_abbr(const char *day)
{
    if (!day || !day[0]) return "";
    if (strncasecmp(day, "mon", 3) == 0) return "mon";
    if (strncasecmp(day, "tue", 3) == 0) return "tue";
    if (strncasecmp(day, "wed", 3) == 0) return "wed";
    if (strncasecmp(day, "thu", 3) == 0) return "thu";
    if (strncasecmp(day, "fri", 3) == 0) return "fri";
    if (strncasecmp(day, "sat", 3) == 0) return "sat";
    if (strncasecmp(day, "sun", 3) == 0) return "sun";
    return day;   /* passthrough for already-abbrev'd values */
}

/*
 * target_set_vif_schedule - write schedule entries to /etc/config/wifi-schedule
 *
 * UCI format per entry: '<day>,<enabled>,<start>,<end>'
 *   e.g. 'mon,1,08:00,18:00'
 *
 * Only called when vif_param.is_schedule == true.
 */
static void target_set_vif_schedule(const char *vif_name,
                                    const struct airpro_mgr_wlan_vap_params *p)
{
    char cmd[256];
    int rc;
    int d;

    if (!vif_name || !p || !p->is_schedule)
        return;

    /* 1. Ensure section exists, set flag, and start with clean schedule array */
    snprintf(cmd, sizeof(cmd),
             "uci -c /etc/config set wifi-schedule.%s=ssid_schedule;"
             "uci -c /etc/config set wifi-schedule.%s.is_schedule=1;"
             "uci -c /etc/config del wifi-schedule.%s.schedule 2>/dev/null",
             vif_name, vif_name, vif_name);
    rc = system(cmd);
    (void)rc;

    /* 2. Add one list entry per schedule slot */
    for (d = 0; d < p->n_schedule; d++) {
        const vif_schedule_entry_t *e = &p->schedule[d];
        const char *abbr  = day_abbr(e->day);
        int         en    = e->enabled ? 1 : 0;
        const char *start = e->start[0] ? e->start : "00:00";
        const char *end   = e->end[0]   ? e->end   : "00:00";

        snprintf(cmd, sizeof(cmd),
                 "uci -c /etc/config add_list wifi-schedule.%s.schedule='%s,%d,%s,%s'",
                 vif_name, abbr, en, start, end);
        rc = system(cmd);
        if (rc != 0)
            LOG(ERR, "wifi-schedule: failed to set %s day=%s", vif_name, abbr);
    }

    /* 3. Commit */
    rc = system("uci -c /etc/config commit wifi-schedule");
    if (rc != 0)
        LOG(ERR, "wifi-schedule: uci commit failed for %s", vif_name);
    else
        LOG(INFO, "wifi-schedule: updated %s (%d entries)", vif_name, p->n_schedule);
}

/*
 * target_disable_vif_schedule - mark schedule as disabled (is_schedule=0)
 * in /etc/config/wifi-schedule, leaving the schedule arrays intact. The daemon
 * will read this flag and skip managing this interface.
 */
static void target_disable_vif_schedule(const char *vif_name)
{
    char cmd[256];
    int rc;

    if (!vif_name)
        return;

    /* Set the is_schedule flag to 0 */
    snprintf(cmd, sizeof(cmd),
             "uci -c /etc/config set wifi-schedule.%s.is_schedule=0",
             vif_name);
    rc = system(cmd);
    (void)rc;

    rc = system("uci -c /etc/config commit wifi-schedule");
    if (rc != 0)
        LOG(ERR, "wifi-schedule: commit failed while disabling %s", vif_name);
    else
        LOG(INFO, "wifi-schedule: disabled scheduling flag for %s", vif_name);
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
            strlcpy(vif_params.mobility_id, record->vif_param[vid].mobility_id, sizeof(vif_params.mobility_id));
            
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

            //TODO: check roming configuration IMP***
            const char *enc = vif_params.encryption;
            int ft_local = 0;

            /* Enable only for WPA2-PSK based modes */
            if (!strcmp(enc, "psk") ||
                !strcmp(enc, "psk2") ||
                !strcmp(enc, "psk-mixed")) {
                ft_local = 1;
            }

           snprintf(vif_params.ft_psk_generate_local, sizeof(vif_params.ft_psk_generate_local), "%d",ft_local);

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
            if( strcmp(vif_params.forward_type, "NAT") == 0) {
                printf("Ankit: nat true auth false\n");
                strlcpy(vif_params.network, "nat_network", sizeof(vif_params.network));
            }

#endif
            if (!sanitize_and_validate_vif_params(&vif_params)) {
                fprintf(stderr, "Warning: vif_params contains invalid data, skipping UCI set.\n");
                return -1;
            }
            
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

            /* ---------- Schedule (ADD) ---------- */
            if (record->vif_param[vid].is_schedule)
                target_set_vif_schedule(vif_name, &record->vif_param[vid]);

        } else if( record->vif_param[vid].status == VIF_DISABLE ) {
            //DISABLE 2
            memset(vif_name, 0, sizeof(vif_name));
            memset(&vif_params, 0, sizeof(vif_params));
            
            strlcpy(vif_name, record->vif_param[vid].record_id, sizeof(vif_name));
            strlcpy(vif_params.record_id, record->vif_param[vid].record_id, sizeof(vif_params.record_id));
            
            strlcpy(vif_params.disabled, "1", sizeof(vif_params.disabled));
            //CAPTIVE PORTAL
            //netconf_handle_captive_portal(vif_name, &vif_params);
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

            /* ---------- Schedule (DISABLE) ---------- */
            target_disable_vif_schedule(vif_name);
        
        } else if( record->vif_param[vid].status == VIF_MODIFY ) {
            //MODIFY 3
            memset(vif_name, 0, sizeof(vif_name));
            memset(&vif_params, 0, sizeof(vif_params));
            
            strlcpy(vif_name, record->vif_param[vid].record_id, sizeof(vif_name));
            strlcpy(vif_params.record_id, record->vif_param[vid].record_id, sizeof(vif_params.record_id));
            
            strlcpy(vif_params.ssid, record->vif_param[vid].ssid, sizeof(vif_params.ssid));
            strlcpy(vif_params.mobility_id, record->vif_param[vid].mobility_id, sizeof(vif_params.mobility_id));
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

            //TODO: check roming configuration IMP***
            const char *enc = vif_params.encryption;
            int ft_local = 0;

            /* Enable only for WPA2-PSK based modes */
            if (!strcmp(enc, "psk") ||
                !strcmp(enc, "psk2") ||
                !strcmp(enc, "psk-mixed")) {
                ft_local = 1;
            }

           snprintf(vif_params.ft_psk_generate_local, sizeof(vif_params.ft_psk_generate_local), "%d",ft_local);

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

            if( strcmp(vif_params.forward_type, "NAT") == 0) {
                printf("Ankit: nat true auth false\n");
                strlcpy(vif_params.network, "nat_network", sizeof(vif_params.network));
            }
#endif

            if (!sanitize_and_validate_vif_params(&vif_params)) {
                fprintf(stderr, "Warning: vif_params contains invalid data, skipping UCI set.\n");
                return -1;
            }
            
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

            /* ---------- Schedule (MODIFY) ---------- */
            if (record->vif_param[vid].is_schedule)
                target_set_vif_schedule(vif_name, &record->vif_param[vid]);

        }
    }

    return true;
}

int target_set_roaming_status(int status)
{
    char wireless_section[9][16] = { "wlan1", "wlan2", "wlan3", "wlan4",
                                     "wlan5", "wlan6", "wlan7", "wlan8"};

    char cmd[256] = {0};
    int ret;

    for (int i = 0; i < 8; i++) {
        sprintf(cmd, "uci set wireless.%s.ieee80211r=%d", wireless_section[i], status);
        ret = system(cmd);
        //sprintf(cmd, "uci set wireless.%s.ft_psk_generate_local=%d", wireless_section[i], status);
        //ret = system(cmd);
        //sprintf(cmd, "uci set wireless.%s.ft_over_ds=0", wireless_section[i]);
        //ret = system(cmd);
    }
    system("uci commit wireless");
    system("wifi");

    return ret;
}
