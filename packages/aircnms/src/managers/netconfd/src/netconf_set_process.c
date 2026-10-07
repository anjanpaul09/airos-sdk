#include "log.h"
#include "netconf.h"
#include "portal_manager.h"
#include "dpp_types.h"
#include "netconf_payload_validate.h"
#include "target_apply.h"
#include <jansson.h>

int current_roaming_status = false;
static nat_config_t g_last_nat_config;

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
            struct timespec t_start, t_end;
            clock_gettime(CLOCK_MONOTONIC, &t_start);
            LOG(NOTICE, "WIFI_CONFIG_APPLY: Triggering 'wifi reload' for MT7621 wireless interfaces...");
            int sys_rc = system("wifi reload");
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            double elapsed = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
            LOG(NOTICE, "WIFI_CONFIG_APPLIED: 'wifi reload' completed in %.2fs (exit_code=%d)", elapsed, sys_rc);
        }

        rc = netconf_check_wifi_config();
        LOG(INFO, "WIFI_CONFIG_VERIFY: Status check result=%d", rc);
    } else {
        LOG(INFO, "%s: Setting onboard status and rebooting...", __func__);
        system("uci set aircnms.@aircnms[0].onboard=1");
        system("uci commit aircnms");
        system("reboot");
    }
}

/* ---------- Safe JSON helpers ---------- */

static const char *json_get_str(json_t *obj, const char *key)
{
    json_t *v = json_object_get(obj, key);
    if (!v || !json_is_string(v))
        return "";
    return json_string_value(v);
}

static int json_get_bool(json_t *obj, const char *key, int def)
{
    json_t *v = json_object_get(obj, key);
    if (!v || !json_is_boolean(v))
        return def;
    return json_boolean_value(v);
}

static int json_get_int(json_t *obj, const char *key, int def)
{
    json_t *v = json_object_get(obj, key);
    if (!v || !json_is_integer(v))
        return def;
    return (int)json_integer_value(v);
}

bool netconf_parse_vif_list(json_t *vif_list, vif_record_t *record)
{
    size_t i;
    int n_vif = 0;

    if (!vif_list || !json_is_array(vif_list) || !record) {
        LOG(ERR, "vif_list or record is invalid");
        return false;
    }

    size_t max_vif = sizeof(record->vif_param) /
                     sizeof(record->vif_param[0]);

    json_t *vif;
    json_array_foreach(vif_list, i, vif) {

        if (i >= max_vif) {
            LOG(ERR, "Too many VIF entries (%zu), max=%zu", i, max_vif);
            break;
        }

        if (!json_is_object(vif)) {
            LOG(ERR, "vif[%zu] is not an object", i);
            continue;
        }

        /* ---------- Strings (safe) ---------- */
        strlcpy(record->vif_param[i].record_id, json_get_str(vif, "recordId"), sizeof(record->vif_param[i].record_id));

        strlcpy(record->vif_param[i].ssid, json_get_str(vif, "ssid"), sizeof(record->vif_param[i].ssid));

        strlcpy(record->vif_param[i].encryption, json_get_str(vif, "encryption"), sizeof(record->vif_param[i].encryption));

        strlcpy(record->vif_param[i].forward_type, json_get_str(vif, "forwardType"), sizeof(record->vif_param[i].forward_type));

        strlcpy(record->vif_param[i].key, json_get_str(vif, "key"), sizeof(record->vif_param[i].key));

        strlcpy(record->vif_param[i].device, json_get_str(vif, "radioType"), sizeof(record->vif_param[i].device));

        strlcpy(record->vif_param[i].auth_url, json_get_str(vif, "authUrl"), sizeof(record->vif_param[i].auth_url));
        strlcpy(record->vif_param[i].portal_id,
                json_get_str(vif, "portalId"),
                sizeof(record->vif_param[i].portal_id));
        strlcpy(record->vif_param[i].uam_ip,
                json_get_str(vif, "uamIp"),
                sizeof(record->vif_param[i].uam_ip));
        strlcpy(record->vif_param[i].uam_secret,
                json_get_str(vif, "uamSecret"),
                sizeof(record->vif_param[i].uam_secret));
        strlcpy(record->vif_param[i].nas_id,
                json_get_str(vif, "nasId"),
                sizeof(record->vif_param[i].nas_id));
        strlcpy(record->vif_param[i].net_segment_ip,
                g_last_nat_config.ipaddr,
                sizeof(record->vif_param[i].net_segment_ip));
        strlcpy(record->vif_param[i].net_mask_ip,
                g_last_nat_config.netmask,
                sizeof(record->vif_param[i].net_mask_ip));

        strlcpy(record->vif_param[i].server_name,
                json_get_str(vif, "serverName"),
                sizeof(record->vif_param[i].server_name));
        strlcpy(record->vif_param[i].server_ip,
                json_get_str(vif, "serverIp"),
                sizeof(record->vif_param[i].server_ip));
        strlcpy(record->vif_param[i].secret_key,
                json_get_str(vif, "communicateKey"),
                sizeof(record->vif_param[i].secret_key));

        json_t *j;
        j = json_object_get(vif, "authPort");
        if (json_is_integer(j)) {
            snprintf(record->vif_param[i].auth_port,
                     sizeof(record->vif_param[i].auth_port),
                     "%lld", json_integer_value(j));
        }

        j = json_object_get(vif, "accountPort");
        if (json_is_integer(j)) {
            snprintf(record->vif_param[i].acct_port,
                     sizeof(record->vif_param[i].acct_port),
                     "%lld", json_integer_value(j));
        }

        /* ---------- Booleans ---------- */
        int hidden = json_get_bool(vif, "isHidden", 0);
        sprintf(record->vif_param[i].hide_ssid, "%d", hidden);

        int enable = json_get_bool(vif, "enable", 0);
        sprintf(record->vif_param[i].enable, "%d", enable);
        snprintf(record->vif_param[i].disabled,
                 sizeof(record->vif_param[i].disabled),
                 "%d", enable ? 0 : 1);

        int auth = json_get_bool(vif, "isAuth", 0);
        record->vif_param[i].is_auth = auth;

        /* ---------- Integers ---------- */
        int vlan_id = json_get_int(vif, "vlanId", 0);
        sprintf(record->vif_param[i].vlan_id, "%d", vlan_id);

        record->vif_param[i].status = json_get_int(vif, "status", 0);
        /* A retained configuration is a full desired-state snapshot.  Cloud resets
         * status to DEFAULT after publishing, so DEFAULT must reconcile active
         * slots and clear disabled slots instead of being silently ignored. */
        if (record->vif_param[i].status == 0)
            record->vif_param[i].status = enable ? VIF_MODIFY : VIF_DISABLE;

        /* ---------- Mobility Domain ---------- */
        const char *md_str = json_get_str(vif, "mobilityDomain");
        if (md_str[0] != '\0') {
            uint16_t md = mobility_domain_from_string(md_str);
            if (md == 0x0000)
                md = 0x0001;
            snprintf(record->vif_param[i].mobility_id,
                     sizeof(record->vif_param[i].mobility_id),
                     "%04x", md);
        } else {
            strcpy(record->vif_param[i].mobility_id, "0001");
        }

        /* ---------- Enterprise only ---------- */
        if (strncmp(record->vif_param[i].encryption,
                    "wpa2-enterprise", 15) == 0 ||
            strncmp(record->vif_param[i].encryption,
                    "wpa3-enterprise", 15) == 0) {

            strlcpy(record->vif_param[i].server_name, json_get_str(vif, "serverName"), sizeof(record->vif_param[i].server_name));

            strlcpy(record->vif_param[i].server_ip, json_get_str(vif, "serverIp"), sizeof(record->vif_param[i].server_ip));

            j = json_object_get(vif, "authPort");
            if (json_is_integer(j)) {
                snprintf(record->vif_param[i].auth_port,
                         sizeof(record->vif_param[i].auth_port),
                         "%lld", json_integer_value(j));
            }

            j = json_object_get(vif, "accountPort");
            if (json_is_integer(j)) {
                snprintf(record->vif_param[i].acct_port,
                         sizeof(record->vif_param[i].acct_port),
                         "%lld", json_integer_value(j));
            }

            strlcpy(record->vif_param[i].secret_key, json_get_str(vif, "communicateKey"), sizeof(record->vif_param[i].secret_key));
        }

        /* ---------- Rates ---------- */
        record->vif_param[i].is_uprate = false;
        const char *upr = json_get_str(vif, "uprate");
        if (upr[0]) {
            int v = atoi(upr);
            if (v >= 0) {
                record->vif_param[i].is_uprate = true;
                record->vif_param[i].uprate = v;
            }
        }

        record->vif_param[i].is_downrate = false;
        const char *dnr = json_get_str(vif, "downrate");
        if (dnr[0]) {
            int v = atoi(dnr);
            if (v >= 0) {
                record->vif_param[i].is_downrate = true;
                record->vif_param[i].downrate = v;
            }
        }

        record->vif_param[i].is_wlan_uprate = false;
        const char *wu = json_get_str(vif, "wlanUprate");
        if (wu[0]) {
            int v = atoi(wu);
            if (v >= 0) {
                record->vif_param[i].is_wlan_uprate = true;
                record->vif_param[i].wlan_uprate = v;
            }
        }

        record->vif_param[i].is_wlan_downrate = false;
        const char *wd = json_get_str(vif, "wlanDownrate");
        if (wd[0]) {
            int v = atoi(wd);
            if (v >= 0) {
                record->vif_param[i].is_wlan_downrate = true;
                record->vif_param[i].wlan_downrate = v;
            }
        }

        /* ---------- Schedule ---------- */
        record->vif_param[i].is_schedule = false;
        record->vif_param[i].n_schedule  = 0;

        int is_schedule = json_get_bool(vif, "isSchedule", 0);
        if (is_schedule) {
            json_t *sched_arr = json_object_get(vif, "schedule");
            if (sched_arr && json_is_array(sched_arr)) {
                size_t s, n_sched = 0;
                json_t *entry;
                json_array_foreach(sched_arr, s, entry) {
                    if (s >= MAX_SCHEDULE_DAYS)
                        break;
                    if (!json_is_object(entry))
                        continue;

                    const char *day   = json_get_str(entry, "day");
                    const char *start = json_get_str(entry, "start");
                    const char *end   = json_get_str(entry, "end");
                    int         en    = json_get_bool(entry, "enabled", 0);

                    strncpy(record->vif_param[i].schedule[s].day,
                            day, sizeof(record->vif_param[i].schedule[s].day) - 1);
                    strncpy(record->vif_param[i].schedule[s].start,
                            start, sizeof(record->vif_param[i].schedule[s].start) - 1);
                    strncpy(record->vif_param[i].schedule[s].end,
                            end, sizeof(record->vif_param[i].schedule[s].end) - 1);
                    record->vif_param[i].schedule[s].enabled = (bool)en;
                    n_sched++;
                }
                record->vif_param[i].is_schedule = true;
                record->vif_param[i].n_schedule  = (int)n_sched;
                LOG(INFO, "VIF[%zu] isSchedule=true n_schedule=%zu", i, n_sched);
            }
        }

        n_vif++;
    }

    record->n_vif = n_vif;

    /* ---------- Logging ---------- */
    LOG(INFO, "PARSED_VIF params n_vif=%d", n_vif);
    for (int j = 0; j < n_vif; j++) {
        LOG(INFO,
            "SET_VIF[%d] recordId=%s ssid=%s enc=%s status=%d enable=%s vlanId=%s device=%s is_auth=%d portal_id=%s net=%s/%s radius=%s auth_port=%s acct_port=%s",
            j,
            record->vif_param[j].record_id,
            record->vif_param[j].ssid,
            record->vif_param[j].encryption,
            record->vif_param[j].status,
            record->vif_param[j].enable,
            record->vif_param[j].vlan_id,
            record->vif_param[j].device,
            record->vif_param[j].is_auth,
            record->vif_param[j].portal_id,
            record->vif_param[j].net_segment_ip,
            record->vif_param[j].net_mask_ip,
            record->vif_param[j].server_ip,
            record->vif_param[j].auth_port,
            record->vif_param[j].acct_port);
    }

    return true;
}

bool netconf_parse_radio_list(json_t *radio_list, radio_record_t *record)
{
    int n_radio = 0;
    size_t i;

    if (!radio_list || !json_is_array(radio_list) || !record) {
        LOG(ERR, "radio_list or record is invalid");
        return false;
    }

    size_t max_radio = sizeof(record->radio_param) /
                       sizeof(record->radio_param[0]);

    json_t *radio;
    json_array_foreach(radio_list, i, radio) {

        if (i >= max_radio) {
            LOG(ERR, "Too many radio entries (%zu), max=%zu", i, max_radio);
            break;
        }

        if (!json_is_object(radio))
            continue;

        /* ---------------- radioType ---------------- */
        json_t *j_radioType = json_object_get(radio, "radioType");
        if (j_radioType && json_is_string(j_radioType)) {
            const char *rtype = json_string_value(j_radioType);

            snprintf(record->radio_param[i].radio_type,
                     sizeof(record->radio_param[i].radio_type),
                     "%s", rtype);

            if (strcmp(rtype, "2.4GHz") == 0)
                snprintf(record->radio_param[i].record_id,
                         sizeof(record->radio_param[i].record_id),
                         "wifi1");
            else if (strcmp(rtype, "5GHz") == 0)
                snprintf(record->radio_param[i].record_id,
                         sizeof(record->radio_param[i].record_id),
                         "wifi0");
        }

        /* ---------------- status ---------------- */
        json_t *j_status = json_object_get(radio, "status");
        if (j_status && json_is_integer(j_status))
            record->radio_param[i].status = json_integer_value(j_status);

        if (record->radio_param[i].status == 0)
            record->radio_param[i].status = RADIO_SETTING_PRIMARY;

        /* ---------------- channel ---------------- */
        json_t *j_channel = json_object_get(radio, "channel");
        if (j_channel) {
            if (json_is_string(j_channel)) {
                const char *ch = json_string_value(j_channel);
                if (ch && ch[0]) {
                    snprintf(record->radio_param[i].channel,
                             sizeof(record->radio_param[i].channel),
                             "%s", ch);
                    record->radio_param[i].status = RADIO_SETTING_SECONDARY;
                }
            } else if (json_is_integer(j_channel)) {
                snprintf(record->radio_param[i].channel,
                         sizeof(record->radio_param[i].channel),
                         "%lld", (long long)json_integer_value(j_channel));
                record->radio_param[i].status = RADIO_SETTING_SECONDARY;
            }
        }

        /* ---------------- txpower ---------------- */
        json_t *j_txp = json_object_get(radio, "txpower");
        if (j_txp) {
            if (json_is_string(j_txp)) {
                const char *txp = json_string_value(j_txp);
                int txpower = atoi(txp);
                if (txpower > 0) {
                    snprintf(record->radio_param[i].txpower,
                             sizeof(record->radio_param[i].txpower),
                             "%s", txp);
                    record->radio_param[i].status = RADIO_SETTING_SECONDARY;
                }
            } else if (json_is_integer(j_txp)) {
                int txpower = (int)json_integer_value(j_txp);
                if (txpower > 0 && txpower <= 35) {
                    snprintf(record->radio_param[i].txpower,
                             sizeof(record->radio_param[i].txpower),
                             "%u", (unsigned int)(txpower & 0x7F));
                    record->radio_param[i].status = RADIO_SETTING_SECONDARY;
                }
            }
        }

        /* ---------------- disabled ---------------- */
        int disabled = 0;   /* default = enabled (UCI 0=enabled, 1=disabled) */

        json_t *j_disabled = json_object_get(radio, "disabled");
        if (j_disabled) {
            /* Compatibility contract: cloud's historical `disabled=true`
             * means the radio is enabled; UCI uses the opposite polarity (0=enabled, 1=disabled). */
            if (json_is_boolean(j_disabled)) {
                disabled = json_boolean_value(j_disabled) ? 0 : 1;
            } else if (json_is_string(j_disabled)) {
                const char *ds = json_string_value(j_disabled);
                if (ds && (!strcasecmp(ds, "true") || !strcmp(ds, "1")))
                    disabled = 0;
                else
                    disabled = 1;
            } else if (json_is_integer(j_disabled)) {
                disabled = json_integer_value(j_disabled) ? 0 : 1;
            }
        }

        /* Check for explicit enable/enabled field if disabled wasn't present */
        if (!j_disabled) {
            json_t *j_enable = json_object_get(radio, "enable");
            if (!j_enable) j_enable = json_object_get(radio, "enabled");
            if (j_enable) {
                if (json_is_boolean(j_enable)) {
                    disabled = json_boolean_value(j_enable) ? 0 : 1;
                } else if (json_is_string(j_enable)) {
                    const char *es = json_string_value(j_enable);
                    if (es && (!strcasecmp(es, "true") || !strcmp(es, "1")))
                        disabled = 0;
                    else
                        disabled = 1;
                } else if (json_is_integer(j_enable)) {
                    disabled = json_integer_value(j_enable) ? 0 : 1;
                }
            }
        }

        snprintf(record->radio_param[i].disabled,
                 sizeof(record->radio_param[i].disabled),
                 "%d", disabled);

        /* ---------------- country ---------------- */
        json_t *j_country = json_object_get(radio, "country");
        if (j_country && json_is_string(j_country)) {
            snprintf(record->radio_param[i].country,
                     sizeof(record->radio_param[i].country),
                     "%s", json_string_value(j_country));
        }

        /* ---------------- channelWidth ---------------- */
        json_t *j_cw = json_object_get(radio, "channelWidth");
        if (j_cw && json_is_integer(j_cw)) {
            int cw = json_integer_value(j_cw);
            if (cw < 0) cw = 0;
            if (cw > 9999) cw = 9999;

            snprintf(record->radio_param[i].channel_width,
                     sizeof(record->radio_param[i].channel_width),
                     "%d", cw);
        }

        /* ---------------- userlimit / max_sta ---------------- */
        json_t *j_ul = json_object_get(radio, "userlimit");
        if (!j_ul) j_ul = json_object_get(radio, "max_sta");
        if (j_ul) {
            if (json_is_string(j_ul)) {
                snprintf(record->radio_param[i].user_limit,
                         sizeof(record->radio_param[i].user_limit),
                         "%s", json_string_value(j_ul));
            } else if (json_is_integer(j_ul)) {
                snprintf(record->radio_param[i].user_limit,
                         sizeof(record->radio_param[i].user_limit),
                         "%lld", (long long)json_integer_value(j_ul));
            }
            strlcpy(record->radio_param[i].max_sta, record->radio_param[i].user_limit, sizeof(record->radio_param[i].max_sta));
        }

        /* ---------------- hwmode ---------------- */
        json_t *j_hw = json_object_get(radio, "hwmode");
        if (j_hw && json_is_string(j_hw)) {
            snprintf(record->radio_param[i].hwmode,
                     sizeof(record->radio_param[i].hwmode),
                     "%s", json_string_value(j_hw));
        }

        n_radio++;
    }

    record->n_radio = n_radio;

    /* ---------------- logging ---------------- */
    LOG(INFO, "PARSED_RADIO params n_radio=%d", n_radio);
    for (int j = 0; j < n_radio; j++) {
        LOG(INFO,
            "SET_RADIO[%d] recordId=%s radioType=%s channel=%s txpower=%s disabled=%s country=%s channelWidth=%s hwmode=%s",
            j,
            record->radio_param[j].record_id,
            record->radio_param[j].radio_type,
            record->radio_param[j].channel,
            record->radio_param[j].txpower,
            record->radio_param[j].disabled,
            record->radio_param[j].country,
            record->radio_param[j].channel_width,
            record->radio_param[j].hwmode);
    }

    return true;
}

bool netconf_process_wireless_transaction(json_t *vif_list, json_t *radio_list)
{
    vif_record_t *vif_rec = NULL;
    radio_record_t *radio_rec = NULL;
    bool success = true;

    if (vif_list) {
        vif_rec = calloc(1, sizeof(vif_record_t));
        if (!vif_rec || !netconf_parse_vif_list(vif_list, vif_rec)) {
            LOG(ERR, "Failed to parse VIF list");
            if (vif_rec) free(vif_rec);
            return false;
        }
    }

    if (radio_list) {
        radio_rec = calloc(1, sizeof(radio_record_t));
        if (!radio_rec || !netconf_parse_radio_list(radio_list, radio_rec)) {
            LOG(ERR, "Failed to parse radio list");
            if (vif_rec) free(vif_rec);
            if (radio_rec) free(radio_rec);
            return false;
        }
    }

    /* 1. Read current UCI configuration state */
    target_current_state_t current;
    target_read_current_state(&current);

    /* 2. Build deterministic apply plan */
    target_apply_plan_t plan;
    int plan_rc = target_build_apply_plan(&current, vif_rec, radio_rec, &plan);

    /* 3. Pre-validation safety gate: reject before ANY mutation */
    if (plan_rc != 0 || plan.unsupported_change) {
        LOG(ERR, "[NETCONF] Configuration rejected: %s",
            plan.unsupported_reason[0] ? plan.unsupported_reason : "Unsupported settings requested");
        if (vif_rec) free(vif_rec);
        if (radio_rec) free(radio_rec);
        return false;
    }

    target_dump_apply_plan(&plan);

    /* If plan has no deltas, nothing to do (no-op) */
    if (plan.num_deltas == 0) {
        if (vif_rec) free(vif_rec);
        if (radio_rec) free(radio_rec);
        return true;
    }

    /* 4. Set up scoped apply context */
    target_apply_ctx_t ctx = {
        .plan = &plan,
        .scoped_apply_enabled = true
    };

    /* 5. Stage UCI parameters without triggering global reload */
    if (radio_rec) {
        if (!target_config_radio_set_scoped(radio_rec, &ctx)) {
            LOG(ERR, "[NETCONF] Failed to update radio UCI settings");
            success = false;
        }
    }

    if (success && vif_rec) {
        if (!target_config_vif_set_scoped(vif_rec, &ctx)) {
            LOG(ERR, "[NETCONF] Failed to update wireless interface UCI settings");
            success = false;
        }
    }

    /* 6. Execute apply plan centrally */
    if (success) {
        target_exec_result_t res;
        int exec_rc = target_execute_apply_plan_live(&plan, &res);
        if (exec_rc != TARGET_EXEC_OK || res.status != TARGET_EXEC_OK) {
            LOG(ERR, "[NETCONF] Failed to apply settings (%s on %s): %s",
                res.stage, res.object, res.reason);
            success = false;
        }
    }

    /* 7. Post-actions (rate limits, portals) after interfaces are verified */
    if (success && vif_rec) {
        if (!target_config_vif_post_apply(vif_rec)) {
            LOG(WARNING, "Post-apply actions (rate limiting/portal) reported failure");
        }
    }

    if (vif_rec) free(vif_rec);
    if (radio_rec) free(radio_rec);
    return success;
}

bool netconf_process_vif_list(json_t *vif_list)
{
    return netconf_process_wireless_transaction(vif_list, NULL);
}

bool netconf_process_radio_list(json_t *radio_list)
{
    return netconf_process_wireless_transaction(NULL, radio_list);
}

bool netconf_process_blacklist(json_t *blackList)
{
    bool success = true;
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
                strlcpy(tmp_mac, json_string_value(mac), sizeof(tmp_mac));
                if (strncmp(type, "ssid", 4) == 0) {
                    char ssid[64];
                    strlcpy(ssid, json_string_value(json_object_get(blackList, "ssid")), sizeof(ssid));
                    LOG(INFO, "SET_ACL blacklist add_ssid mac=%s ssid=%s", tmp_mac, ssid);
                    if (!netconf_handle_add_blacklist_ssid(tmp_mac, ssid)) success = false;
                } else {
                    LOG(INFO, "SET_ACL blacklist add mac=%s", tmp_mac);
                    if (!netconf_handle_add_blacklist(tmp_mac)) success = false;
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
                strlcpy(tmp_mac, json_string_value(mac), sizeof(tmp_mac));
                LOG(INFO, "SET_ACL blacklist remove mac=%s", tmp_mac);
                if (!netconf_handle_remove_blacklist(tmp_mac)) success = false;
            }
        }
    }
    return success;
}

int netconf_process_whitelist(json_t *whiteList)
{
    bool success = true;
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
                strlcpy(tmp_mac, json_string_value(mac), sizeof(tmp_mac));
                if (strncmp(type, "ssid", 4) == 0) {
                    char ssid[64];
                    strlcpy(ssid, json_string_value(json_object_get(whiteList, "ssid")), sizeof(ssid));
                    LOG(INFO, "SET_ACL whitelist add_ssid mac=%s ssid=%s", tmp_mac, ssid);
                    if (!netconf_handle_add_whitelist_ssid(tmp_mac, ssid)) success = false;
                } else {
                    LOG(INFO, "SET_ACL whitelist add mac=%s", tmp_mac);
                    if (!netconf_handle_add_whitelist(tmp_mac)) success = false;
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
                strlcpy(tmp_mac, json_string_value(mac), sizeof(tmp_mac));
                LOG(INFO, "SET_ACL whitelist remove mac=%s", tmp_mac);
                if (!netconf_handle_remove_whitelist(tmp_mac)) success = false;
            }
        }
    }
    return success;

}

static bool netconf_payload_has_captive_vif(json_t *root)
{
    json_t *vif_root;
    json_t *vif_list;
    size_t i;
    json_t *vif;

    if (!root)
        return false;

    vif_root = json_object_get(root, "vif");
    vif_list = json_object_get(vif_root, "vifList");
    if (!json_is_array(vif_list))
        return false;

    json_array_foreach(vif_list, i, vif) {
        json_t *is_auth;
        json_t *portal_id;
        bool auth_enabled = false;

        if (!json_is_object(vif))
            continue;

        is_auth = json_object_get(vif, "isAuth");
        if (json_is_boolean(is_auth))
            auth_enabled = json_boolean_value(is_auth);
        else if (json_is_integer(is_auth))
            auth_enabled = json_integer_value(is_auth) != 0;

        portal_id = json_object_get(vif, "portalId");
        if (auth_enabled && json_is_string(portal_id) &&
            json_string_value(portal_id)[0] != '\0')
            return true;
    }

    return false;
}

static bool netconf_payload_has_legacy_nat_vif(json_t *root)
{
    json_t *vif_root;
    json_t *vif_list;
    size_t i;
    json_t *vif;

    if (!root)
        return false;

    vif_root = json_object_get(root, "vif");
    vif_list = json_object_get(vif_root, "vifList");
    if (!json_is_array(vif_list))
        return false;

    json_array_foreach(vif_list, i, vif) {
        json_t *is_auth;
        json_t *forward_type;
        json_t *enable;
        bool auth_enabled = false;
        bool vif_enabled = true;

        if (!json_is_object(vif))
            continue;

        enable = json_object_get(vif, "enable");
        if (json_is_boolean(enable))
            vif_enabled = json_boolean_value(enable);
        else if (json_is_integer(enable))
            vif_enabled = json_integer_value(enable) != 0;

        is_auth = json_object_get(vif, "isAuth");
        if (json_is_boolean(is_auth))
            auth_enabled = json_boolean_value(is_auth);
        else if (json_is_integer(is_auth))
            auth_enabled = json_integer_value(is_auth) != 0;

        forward_type = json_object_get(vif, "forwardType");
        if (vif_enabled && !auth_enabled && json_is_string(forward_type) &&
            strcmp(json_string_value(forward_type), "NAT") == 0)
            return true;
    }

    return false;
}

int netconf_process_nat_config(json_t *nat_config, bool apply_legacy_nat)
{
    bool success = true;
    nat_config_t config;
    const char *ip = NULL;
    const char *mask = NULL;
    json_t *netSegmentIp;
    json_t *netMaskIp;
    json_t *roaming;

    memset(&config, 0, sizeof(config));

    netSegmentIp = json_object_get(nat_config, "netSegmentIp");
    netMaskIp = json_object_get(nat_config, "netMaskIp");
    if (json_is_string(netSegmentIp))
        ip = json_string_value(netSegmentIp);
    if (json_is_string(netMaskIp))
        mask = json_string_value(netMaskIp);

    /* Cloud legitimately sends an empty NAT object for bridge-only networks. */
    if ((ip && ip[0]) || (mask && mask[0])) {
        if (!ip || !ip[0] || !mask || !mask[0]) {
            LOG(ERR, "natConfig requires both netSegmentIp and netMaskIp");
            return false;
        }
        strlcpy(config.ipaddr, ip, sizeof(config.ipaddr));
        strlcpy(config.netmask, mask, sizeof(config.netmask));
        memcpy(&g_last_nat_config, &config, sizeof(g_last_nat_config));
        portal_manager_set_network_config(config.ipaddr, config.netmask);

        if (apply_legacy_nat)
            success = netconf_handle_nat_config(&config);
        else
            LOG(INFO, "natConfig stored for captive portal; legacy nat_network apply skipped");
    } else {
        LOG(INFO, "natConfig empty; legacy NAT unchanged");
    }

    roaming = json_object_get(nat_config, "l2Roaming");
    if (json_is_boolean(roaming)) {
        int new_roaming_status = json_boolean_value(roaming);
        if (new_roaming_status != current_roaming_status) {
            /* target_set_roaming_status follows the shell convention: 0 is success. */
            if (target_set_roaming_status(new_roaming_status) != 0)
                success = false;
            else
                current_roaming_status = new_roaming_status;
        }
    }

    return success;
}

int netconf_process_set_msg(char* buf)
{
    int ret = true;
    int step_ret;
    json_error_t error;
    json_t *root = json_loads(buf, 0, &error);
    if (!root) {
        LOG(ERR, "CONFIG_REJECTED reason=json_parse_error line=%d", error.line);
        return false;
    }
    char validation_error[192] = {0};
    if (!netconf_validate_config_payload(root, validation_error, sizeof(validation_error))) {
        LOG(ERR, "CONFIG_REJECTED reason=%s", validation_error);
        json_decref(root);
        return false;
    }
 
    bool has_captive_vif = netconf_payload_has_captive_vif(root);
    bool has_legacy_nat_vif = netconf_payload_has_legacy_nat_vif(root);
    json_t *nat_config = json_object_get(root, "natConfig");      
    if (nat_config) {
        if (has_captive_vif && has_legacy_nat_vif) {
            LOG(WARNING,
                "natConfig is shared by captive and legacy NAT VIFs; use different subnets or disable legacy NAT to avoid br-nat/chilli IP conflict");
        }
        step_ret = netconf_process_nat_config(nat_config,
                                              !has_captive_vif || has_legacy_nat_vif);
        ret = ret && step_ret;
    }

    json_t *vif_list = json_object_get(json_object_get(root, "vif"), "vifList");      
    json_t *radio_list = json_object_get(json_object_get(root, "radio"), "radioList");
    bool has_vifs = (vif_list && json_is_array(vif_list));
    bool has_radios = (radio_list && json_is_array(radio_list));

    if (has_vifs || has_radios) {
        step_ret = netconf_process_wireless_transaction(
            has_vifs ? vif_list : NULL,
            has_radios ? radio_list : NULL);
        ret = ret && step_ret;
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
    
    char validation_error[192] = {0};
    if (!netconf_validate_acl_payload(root, validation_error, sizeof(validation_error))) {
        LOG(ERR, "ACL_REJECTED reason=%s", validation_error);
        json_decref(root);
        return false;
    }

    json_t *blackList = json_object_get(root, "blackList");
    bool success = true;
    if (blackList && !netconf_process_blacklist(blackList))
        success = false;

    json_t *whiteList = json_object_get(root, "whiteList");
    if (whiteList && !netconf_process_whitelist(whiteList))
        success = false;

    json_decref(root);
    
#ifdef CONFIG_PLATFORM_MTK_JEDI
    netconf_check_wifi_config();
#endif

    return success;
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

    char validation_error[192] = {0};
    if (!netconf_validate_rate_limit_payload(root, validation_error, sizeof(validation_error))) {
        LOG(ERR, "RATE_LIMIT_REJECTED reason=%s", validation_error);
        json_decref(root);
        return false;
    }

    json_t *rate_limit = json_object_get(root, "rateLimit");
    if (rate_limit) {
        strlcpy(tmp_mac, json_string_value(json_object_get(rate_limit, "mac")), sizeof(tmp_mac));
        uplink = atoi(json_string_value(json_object_get(rate_limit, "uplink")));
        downlink = atoi(json_string_value(json_object_get(rate_limit, "downlink")));
    }
    
    os_nif_macaddr_from_str(&mac, tmp_mac); 
    
    // Log parameters before setting
    LOG(INFO, "SET_USER_RL mac=%s uplink=%d downlink=%d", tmp_mac, uplink, downlink);
   
    bool success = air_user_rate_limit(mac.addr,
                       uplink >= 0 ? uplink : 0,
                       downlink >= 0 ? downlink : 0);

    json_decref(root);
    return success;
}
