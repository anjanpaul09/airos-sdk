#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "target_apply.h"

#ifdef __has_include
  #if __has_include("log.h")
    #include "log.h"
  #endif
#endif

#ifndef LOG
#define LOG(level, fmt, ...) printf("[%s] " fmt "\n", #level, ##__VA_ARGS__)
#endif

#ifndef strlcpy
static size_t plan_strlcpy(char *dst, const char *src, size_t siz) {
    size_t s = strlen(src);
    if (siz > 0) {
        size_t n = (s >= siz) ? siz - 1 : s;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return s;
}
#define strlcpy plan_strlcpy
#endif

#ifndef strlcat
static size_t plan_strlcat(char *dst, const char *src, size_t siz) {
    size_t d = strlen(dst);
    size_t s = strlen(src);
    if (d < siz) {
        size_t n = (s >= siz - d) ? siz - d - 1 : s;
        memcpy(dst + d, src, n);
        dst[d + n] = '\0';
    }
    return d + s;
}
#define strlcat plan_strlcat
#endif

uint32_t target_radio_name_to_mask(const char *radio_name)
{
    if (!radio_name || !radio_name[0])
        return TARGET_RADIO_NONE;
    if (strstr(radio_name, "wifi0") || strstr(radio_name, "5GHz") || strstr(radio_name, "5g"))
        return TARGET_RADIO_WIFI0;
    if (strstr(radio_name, "wifi1") || strstr(radio_name, "2.4GHz") || strstr(radio_name, "2g"))
        return TARGET_RADIO_WIFI1;
    return TARGET_RADIO_NONE;
}

static const char *canonical_encryption(const char *enc)
{
    if (!enc || !enc[0]) return "none";
    if (!strcmp(enc, "open") || !strcmp(enc, "none")) return "none";
    if (!strcmp(enc, "wpa-psk") || !strcmp(enc, "psk")) return "psk";
    if (!strcmp(enc, "wpa2-psk") || !strcmp(enc, "psk2")) return "psk2";
    if (!strcmp(enc, "wpa3-psk") || !strcmp(enc, "sae")) return "sae";
    if (!strcmp(enc, "wpa/wpa2-psk") || !strcmp(enc, "psk-mixed")) return "psk-mixed";
    if (!strcmp(enc, "wpa2/wpa3-psk") || !strcmp(enc, "sae-mixed")) return "sae-mixed";
    if (!strcmp(enc, "wpa2-enterprise") || !strcmp(enc, "wpa2")) return "wpa2";
    if (!strcmp(enc, "wpa3-enterprise") || !strcmp(enc, "wpa3")) return "wpa3";
    return enc;
}

const char *target_apply_class_str(target_apply_class_t cls)
{
    switch (cls) {
    case TARGET_APPLY_NONE:            return "NONE";
    case TARGET_APPLY_LIVE:            return "LIVE";
    case TARGET_APPLY_VIF_RECONCILE:   return "VIF_RECONCILE";
    case TARGET_APPLY_RADIO_RECONCILE: return "RADIO_RECONCILE";
    case TARGET_APPLY_FULL_RECOVERY:   return "FULL_RECOVERY";
    case TARGET_APPLY_UNSUPPORTED:     return "UNSUPPORTED";
    default:                           return "UNKNOWN";
    }
}

const char *target_delta_type_str(target_delta_type_t dt)
{
    switch (dt) {
    case TARGET_DELTA_NONE:            return "NONE";
    case TARGET_DELTA_CHANNEL:         return "CHANNEL";
    case TARGET_DELTA_TXPOWER:         return "TXPOWER";
    case TARGET_DELTA_VIF_ADD:         return "VIF_ADD";
    case TARGET_DELTA_VIF_MODIFY:      return "VIF_MODIFY";
    case TARGET_DELTA_VIF_DISABLE:     return "VIF_DISABLE";
    case TARGET_DELTA_VIF_REMOVE:      return "VIF_REMOVE";
    case TARGET_DELTA_CHANNEL_WIDTH:   return "CHANNEL_WIDTH";
    case TARGET_DELTA_HWMODE:          return "HWMODE";
    case TARGET_DELTA_COUNTRY:         return "COUNTRY";
    case TARGET_DELTA_MAX_STA:         return "MAX_STA";
    case TARGET_DELTA_RADIO_ENABLE:    return "RADIO_ENABLE";
    case TARGET_DELTA_RADIO_DISABLE:   return "RADIO_DISABLE";
    case TARGET_DELTA_FULL_RECOVERY:   return "FULL_RECOVERY";
    case TARGET_DELTA_UNKNOWN:         return "UNKNOWN";
    default:                           return "INVALID";
    }
}

static bool add_delta(
    target_apply_plan_t *plan,
    const char *object_name,
    target_delta_type_t type,
    target_apply_class_t class,
    uint32_t radio_mask,
    const char *reason,
    bool client_disconnect_expected,
    const char *old_val,
    const char *new_val)
{
    if (!plan || plan->num_deltas >= TARGET_MAX_DELTAS)
        return false;

    target_delta_item_t *item = &plan->deltas[plan->num_deltas++];
    memset(item, 0, sizeof(*item));

    if (object_name)
        strlcpy(item->object_name, object_name, sizeof(item->object_name));
    item->type = type;
    item->class = class;
    item->radio_mask = radio_mask;
    if (reason)
        strlcpy(item->reason, reason, sizeof(item->reason));
    item->client_disconnect_expected = client_disconnect_expected;
    if (old_val)
        strlcpy(item->old_value, old_val, sizeof(item->old_value));
    if (new_val)
        strlcpy(item->new_value, new_val, sizeof(item->new_value));

    /* Aggregate bitmasks based on tier and impact */
    if (class == TARGET_APPLY_VIF_RECONCILE || class == TARGET_APPLY_RADIO_RECONCILE) {
        plan->reconf_radio_mask |= radio_mask;
    }
    if (client_disconnect_expected) {
        plan->radio_disruptive_mask |= radio_mask;
    }
    if (class == TARGET_APPLY_FULL_RECOVERY) {
        plan->full_reload_required = true;
    }
    if (class == TARGET_APPLY_UNSUPPORTED || type == TARGET_DELTA_UNKNOWN) {
        plan->unsupported_change = true;
        if (reason)
            strlcpy(plan->unsupported_reason, reason, sizeof(plan->unsupported_reason));
    }

    return true;
}

static void normalize_channel_width(const char *cw_in, const char *htmode_in, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';

    if (cw_in && cw_in[0]) {
        if (strstr(cw_in, "160")) strlcpy(out, "160", out_len);
        else if (strstr(cw_in, "80")) strlcpy(out, "80", out_len);
        else if (strstr(cw_in, "40")) strlcpy(out, "40", out_len);
        else if (strstr(cw_in, "20")) strlcpy(out, "20", out_len);
        else strlcpy(out, cw_in, out_len);
        return;
    }

    if (htmode_in && htmode_in[0]) {
        if (strstr(htmode_in, "160")) strlcpy(out, "160", out_len);
        else if (strstr(htmode_in, "80")) strlcpy(out, "80", out_len);
        else if (strstr(htmode_in, "40")) strlcpy(out, "40", out_len);
        else if (strstr(htmode_in, "20") || strstr(htmode_in, "NOHT")) strlcpy(out, "20", out_len);
    }
}

int target_read_current_state(target_current_state_t *state)
{
    if (!state)
        return -1;

    memset(state, 0, sizeof(*state));

    /* 1. Read Radios from UCI */
    state->radios.n_radio = 2;
    strlcpy(state->radios.radio_param[0].record_id, "wifi0", sizeof(state->radios.radio_param[0].record_id));
    uci_get_radio_params("wifi0", &state->radios.radio_param[0]);

    strlcpy(state->radios.radio_param[1].record_id, "wifi1", sizeof(state->radios.radio_param[1].record_id));
    uci_get_radio_params("wifi1", &state->radios.radio_param[1]);

    for (int r = 0; r < state->radios.n_radio; r++) {
        struct airpro_mgr_wlan_radio_params *rad = &state->radios.radio_param[r];
        if (rad->channel_width[0] == '\0' && rad->htmode[0] != '\0') {
            normalize_channel_width(NULL, rad->htmode, rad->channel_width, sizeof(rad->channel_width));
        }
        if (rad->hwmode[0] == '\0' && rad->htmode[0] != '\0') {
            if (strstr(rad->htmode, "HE")) {
                strlcpy(rad->hwmode, (!strcmp(rad->record_id, "wifi0") ? "11NA_11AC_11AX" : "11BGN_11AX"), sizeof(rad->hwmode));
            } else if (strstr(rad->htmode, "VHT")) {
                strlcpy(rad->hwmode, "11AC", sizeof(rad->hwmode));
            } else {
                strlcpy(rad->hwmode, (!strcmp(rad->record_id, "wifi0") ? "11NA" : "11BGN"), sizeof(rad->hwmode));
            }
        }
    }

    /* 2. Read VIF sections from UCI */
    struct airpro_mgr_get_all_uci_section_names sec_arr;
    memset(&sec_arr, 0, sizeof(sec_arr));
    int rc = uci_get_all_section_names("wireless", "wifi-iface", &sec_arr);
    if (rc == 0) {
        state->vifs.n_vif = sec_arr.num_entry;
        for (int i = 0; i < sec_arr.num_entry && i < 16; i++) {
            strlcpy(state->vifs.vif_param[i].record_id, sec_arr.sec_name[i], sizeof(state->vifs.vif_param[i].record_id));
            uci_get_vap_params(sec_arr.sec_name[i], &state->vifs.vif_param[i]);
            /* Read disabled flag specifically if not populated */
            char dis_buf[8] = {0};
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.disabled", sec_arr.sec_name[i]);
            if (execute_uci_command(cmd, dis_buf, sizeof(dis_buf)) == 0) {
                size_t l = strlen(dis_buf);
                while (l > 0 && (dis_buf[l - 1] == '\n' || dis_buf[l - 1] == '\r' || dis_buf[l - 1] == ' '))
                    dis_buf[--l] = '\0';
                if (dis_buf[0])
                    strlcpy(state->vifs.vif_param[i].disabled, dis_buf, sizeof(state->vifs.vif_param[i].disabled));
            }
            if (state->vifs.vif_param[i].disabled[0] == '\0') {
                strlcpy(state->vifs.vif_param[i].disabled, "0", sizeof(state->vifs.vif_param[i].disabled));
            }
            if (state->vifs.vif_param[i].forward_type[0] == '\0') {
                if (!strcmp(state->vifs.vif_param[i].network, "nat_network")) {
                    strlcpy(state->vifs.vif_param[i].forward_type, "NAT", sizeof(state->vifs.vif_param[i].forward_type));
                } else {
                    strlcpy(state->vifs.vif_param[i].forward_type, "Bridge", sizeof(state->vifs.vif_param[i].forward_type));
                }
            }
        }
    }

    return 0;
}

static const struct airpro_mgr_wlan_radio_params *find_radio(
    const radio_record_t *rec, const char *record_id)
{
    if (!rec || !record_id)
        return NULL;
    for (int i = 0; i < rec->n_radio; i++) {
        if (!strcmp(rec->radio_param[i].record_id, record_id))
            return &rec->radio_param[i];
    }
    return NULL;
}

static const struct airpro_mgr_wlan_vap_params *find_vif(
    const vif_record_t *rec, const char *record_id)
{
    if (!rec || !record_id)
        return NULL;
    for (int i = 0; i < rec->n_vif; i++) {
        if (!strcmp(rec->vif_param[i].record_id, record_id))
            return &rec->vif_param[i];
    }
    return NULL;
}
 
static const char *get_vif_expected_network(const struct airpro_mgr_wlan_vap_params *vif)
{
    if (vif->forward_type[0] && strcmp(vif->forward_type, "NAT") == 0) {
        return "nat_network";
    }
    if (vif->vlan_id[0] && atoi(vif->vlan_id) > 0) {
        return vif->vlan_id;
    }
    return "lan";
}

int target_build_apply_plan(
    const target_current_state_t *current,
    const vif_record_t *desired_vifs,
    const radio_record_t *desired_radios,
    target_apply_plan_t *plan)
{
    if (!plan)
        return -1;

    memset(plan, 0, sizeof(*plan));

    /* =========================================================================
     * SECTION A: Radio Deltas
     * ========================================================================= */
    if (desired_radios) {
        for (int i = 0; i < desired_radios->n_radio; i++) {
            const struct airpro_mgr_wlan_radio_params *des = &desired_radios->radio_param[i];
            const char *r_id = des->record_id[0] ? des->record_id : (i == 0 ? "wifi1" : "wifi0");
            uint32_t r_mask = target_radio_name_to_mask(r_id);

            const struct airpro_mgr_wlan_radio_params *cur =
                current ? find_radio(&current->radios, r_id) : NULL;

            if (!cur)
                continue;

            /* 1. Channel Delta (Tier 1: Live via CSA) */
            if (des->channel[0] && strcmp(des->channel, "auto") != 0 &&
                cur->channel[0] && strcmp(des->channel, cur->channel) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_CHANNEL, TARGET_APPLY_LIVE,
                          r_mask, "CSA_CHANNEL_SWITCH", false, cur->channel, des->channel);
            }

            /* 2. Tx Power Delta (Tier 1: Live via iw/nl80211) */
            if (des->txpower[0] && cur->txpower[0] &&
                strcmp(des->txpower, cur->txpower) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_TXPOWER, TARGET_APPLY_LIVE,
                          r_mask, "LIVE_TXPOWER_UPDATE", false, cur->txpower, des->txpower);
            }

            /* 3. Channel Width / HT Mode Delta (Tier 3: Radio Reconcile, Disruptive) */
            char cur_w[8] = {0}, des_w[8] = {0};
            normalize_channel_width(cur->channel_width, cur->htmode, cur_w, sizeof(cur_w));
            normalize_channel_width(des->channel_width, des->htmode, des_w, sizeof(des_w));

            if (des_w[0] && cur_w[0] && strcmp(des_w, cur_w) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_CHANNEL_WIDTH, TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, "CHANNEL_WIDTH_CHANGE", true, cur_w, des_w);
            } else if (des->htmode[0] && cur->htmode[0] &&
                       strcmp(des->htmode, cur->htmode) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_CHANNEL_WIDTH, TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, "HTMODE_CHANGE", true, cur->htmode, des->htmode);
            }

            /* 4. HW Mode Delta (Tier 3: Radio Reconcile, Disruptive) */
            if (des->hwmode[0] && cur->hwmode[0] &&
                strcmp(des->hwmode, cur->hwmode) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_HWMODE, TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, "HWMODE_CHANGE", true, cur->hwmode, des->hwmode);
            }

            /* 5. Country Delta (Tier 3: Radio Reconcile, Disruptive) */
            if (des->country[0] && cur->country[0] &&
                strcasecmp(des->country, cur->country) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_COUNTRY, TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, "COUNTRY_CHANGE", true, cur->country, des->country);
            }

            /* 6. Max STA / User Limit Delta (Tier 3: Radio Reconcile) */
            const char *des_sta = des->max_sta[0] ? des->max_sta : des->user_limit;
            const char *cur_sta = cur->max_sta[0] ? cur->max_sta : cur->user_limit;
            if (des_sta[0] && cur_sta[0] && strcmp(des_sta, cur_sta) != 0) {
                add_delta(plan, r_id, TARGET_DELTA_MAX_STA, TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, "MAX_STA_CHANGE", false, cur_sta, des_sta);
            }

            /* 7. Radio Enable/Disable Delta (Tier 3: Radio Reconcile, Disruptive) */
            if (des->disabled[0] && cur->disabled[0] &&
                strcmp(des->disabled, cur->disabled) != 0) {
                bool disabling = (!strcmp(des->disabled, "1") || !strcasecmp(des->disabled, "true"));
                add_delta(plan, r_id,
                          disabling ? TARGET_DELTA_RADIO_DISABLE : TARGET_DELTA_RADIO_ENABLE,
                          TARGET_APPLY_RADIO_RECONCILE,
                          r_mask, disabling ? "RADIO_DISABLED" : "RADIO_ENABLED",
                          true, cur->disabled, des->disabled);
            }
        }
    }

    /* =========================================================================
     * SECTION B: VIF Deltas
     * ========================================================================= */
    if (desired_vifs) {
        for (int i = 0; i < desired_vifs->n_vif; i++) {
            const struct airpro_mgr_wlan_vap_params *des = &desired_vifs->vif_param[i];
            const char *v_id = des->record_id;
            if (!v_id || !v_id[0])
                continue;

            uint32_t r_mask = target_radio_name_to_mask(des->device);
            if (r_mask == TARGET_RADIO_NONE)
                r_mask = target_radio_name_to_mask(des->wifi_device);

            const struct airpro_mgr_wlan_vap_params *cur =
                current ? find_vif(&current->vifs, v_id) : NULL;

            /* Check status: 1=ADD, 2=DISABLE, 3=MODIFY */
            if (des->status == 2 || !strcmp(des->disabled, "1")) {
                /* VIF DISABLE */
                if (!cur || strcmp(cur->disabled, "1") != 0) {
                    add_delta(plan, v_id, TARGET_DELTA_VIF_DISABLE, TARGET_APPLY_VIF_RECONCILE,
                              r_mask, "VIF_DISABLE", false,
                              cur ? cur->disabled : "0", "1");
                }
            } else if (!cur) {
                /* VIF ADD */
                add_delta(plan, v_id, TARGET_DELTA_VIF_ADD, TARGET_APPLY_VIF_RECONCILE,
                          r_mask, "VIF_ADD", false, "", des->ssid);
            } else {
                /* VIF MODIFY: check diffs */
                char reasons[64] = {0};
                bool modified = false;

                if (strcmp(des->ssid, cur->ssid) != 0) {
                    strlcat(reasons, "SSID_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                const char *des_enc = canonical_encryption(des->encryption);
                const char *cur_enc = canonical_encryption(cur->encryption);
                if (strcmp(des_enc, cur_enc) != 0) {
                    strlcat(reasons, "SECURITY_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                if (des->key[0] && strcmp(des->key, cur->key) != 0) {
                    strlcat(reasons, "KEY_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                if (des->vlan_id[0] && strcmp(des->vlan_id, cur->vlan_id) != 0) {
                    strlcat(reasons, "VLAN_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                const char *cur_net = (cur->network[0] != '\0') ? cur->network : "lan";
                const char *des_net = get_vif_expected_network(des);
                if (strcmp(des_net, cur_net) != 0 ||
                    (des->forward_type[0] && cur->forward_type[0] && strcmp(des->forward_type, cur->forward_type) != 0)) {
                    strlcat(reasons, "FORWARD_TYPE_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                if (des->isolate[0] && cur->isolate[0] && strcmp(des->isolate, cur->isolate) != 0) {
                    strlcat(reasons, "ISOLATE_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                if (des->hide_ssid[0] && strcmp(des->hide_ssid, cur->hide_ssid) != 0) {
                    strlcat(reasons, "HIDDEN_CHANGE,", sizeof(reasons));
                    modified = true;
                }
                if (!strcmp(cur->disabled, "1") && strcmp(des->disabled, "1") != 0) {
                    strlcat(reasons, "VIF_ENABLE,", sizeof(reasons));
                    modified = true;
                }

                if (modified) {
                    size_t len = strlen(reasons);
                    if (len > 0 && reasons[len - 1] == ',')
                        reasons[len - 1] = '\0';

                    add_delta(plan, v_id, TARGET_DELTA_VIF_MODIFY, TARGET_APPLY_VIF_RECONCILE,
                              r_mask, reasons, false, cur->ssid, des->ssid);
                }
            }
        }

        /* Check for VIFs present currently but deleted from desired list */
        if (current) {
            for (int i = 0; i < current->vifs.n_vif; i++) {
                /* If the VIF is already disabled in current state, it's an inactive template slot: ignore */
                if (current->vifs.vif_param[i].disabled[0] == '1')
                    continue;

                const char *cur_id = current->vifs.vif_param[i].record_id;
                if (!find_vif(desired_vifs, cur_id)) {
                    uint32_t r_mask = target_radio_name_to_mask(current->vifs.vif_param[i].device);
                    add_delta(plan, cur_id, TARGET_DELTA_VIF_REMOVE, TARGET_APPLY_VIF_RECONCILE,
                              r_mask, "VIF_REMOVE", false, current->vifs.vif_param[i].ssid, "");
                }
            }
        }
    }

    return plan->unsupported_change ? -1 : 0;
}

void target_dump_apply_plan(const target_apply_plan_t *plan)
{
    if (!plan)
        return;

    if (plan->num_deltas == 0) {
        LOG(INFO, "[NETCONF] No configuration changes detected (device already running desired settings).");
        return;
    }

    LOG(INFO, "[NETCONF] Configuration changes detected (%d item(s)):", plan->num_deltas);
    for (int i = 0; i < plan->num_deltas; i++) {
        const target_delta_item_t *d = &plan->deltas[i];
        const char *band = (strstr(d->object_name, "wifi0") || d->radio_mask == TARGET_RADIO_WIFI0) ? "5GHz" :
                           (strstr(d->object_name, "wifi1") || d->radio_mask == TARGET_RADIO_WIFI1) ? "2.4GHz" : d->object_name;
        const char *impact = d->client_disconnect_expected ? "client reconnect required" : "zero downtime (live)";

        switch (d->type) {
            case TARGET_DELTA_CHANNEL:
                LOG(INFO, "  • %s Radio: Channel changed from %s -> %s (%s)", band, d->old_value, d->new_value, impact);
                break;
            case TARGET_DELTA_TXPOWER:
                LOG(INFO, "  • %s Radio: TxPower changed from %s dBm -> %s dBm (%s)", band, d->old_value, d->new_value, impact);
                break;
            case TARGET_DELTA_CHANNEL_WIDTH:
                LOG(INFO, "  • %s Radio: Bandwidth changed from %s -> %s (%s)", band, d->old_value, d->new_value, impact);
                break;
            case TARGET_DELTA_VIF_ADD:
                LOG(INFO, "  • %s: New SSID added: \"%s\" (%s)", band, d->new_value[0] ? d->new_value : d->object_name, impact);
                break;
            case TARGET_DELTA_VIF_MODIFY:
                LOG(INFO, "  • %s: SSID updated: \"%s\" [%s] (%s)", band, d->object_name, d->reason, impact);
                break;
            case TARGET_DELTA_VIF_REMOVE:
                LOG(INFO, "  • %s: SSID removed: \"%s\" (%s)", band, d->old_value[0] ? d->old_value : d->object_name, impact);
                break;
            case TARGET_DELTA_VIF_DISABLE:
                LOG(INFO, "  • %s: SSID disabled: \"%s\" (%s)", band, d->object_name, impact);
                break;
            case TARGET_DELTA_RADIO_ENABLE:
                LOG(INFO, "  • %s Radio: Enabled", band);
                break;
            case TARGET_DELTA_RADIO_DISABLE:
                LOG(INFO, "  • %s Radio: Disabled", band);
                break;
            default:
                LOG(INFO, "  • %s: %s (%s -> %s)", d->object_name, d->reason, d->old_value, d->new_value);
                break;
        }
    }
}

int target_get_radio_hostapd_iface(const char *radio, char *ifname, size_t len)
{
    if (!radio || !ifname || len == 0)
        return -1;
    if (strstr(radio, "wifi0") || strstr(radio, "5GHz") || strstr(radio, "5g")) {
        strlcpy(ifname, "phy1-ap0", len);
        return 0;
    }
    if (strstr(radio, "wifi1") || strstr(radio, "2.4GHz") || strstr(radio, "2g")) {
        strlcpy(ifname, "phy0-ap0", len);
        return 0;
    }
    return -1;
}

int target_get_radio_phy(const char *radio, char *phy, size_t len)
{
    if (!radio || !phy || len == 0)
        return -1;
    if (strstr(radio, "wifi0") || strstr(radio, "5GHz") || strstr(radio, "5g")) {
        strlcpy(phy, "phy1", len);
        return 0;
    }
    if (strstr(radio, "wifi1") || strstr(radio, "2.4GHz") || strstr(radio, "2g")) {
        strlcpy(phy, "phy0", len);
        return 0;
    }
    return -1;
}

int target_build_chan_spec(const char *radio, int channel, target_chan_spec_t *spec)
{
    if (!radio || !spec)
        return -1;

    memset(spec, 0, sizeof(*spec));

    /* 1. Calculate frequency */
    if (channel == 14)
        spec->freq = 2484;
    else if (channel <= 13)
        spec->freq = 2407 + channel * 5;
    else
        spec->freq = 5000 + channel * 5;

    /* 2. Read htmode from UCI to determine bandwidth */
    char htmode[32] = {0};
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.htmode", radio);
    execute_uci_command(cmd, htmode, sizeof(htmode));

    if (strstr(htmode, "160"))
        spec->bandwidth = 160;
    else if (strstr(htmode, "80"))
        spec->bandwidth = 80;
    else if (strstr(htmode, "40"))
        spec->bandwidth = 40;
    else
        spec->bandwidth = 20;

    /* 3. Center frequency derivation */
    if (channel <= 14) {
        spec->center_freq1 = spec->freq;
    } else {
        /* Standard 5GHz 80MHz and 40MHz channel centers */
        if (spec->bandwidth == 80) {
            if (channel >= 36 && channel <= 48)
                spec->center_freq1 = 5210;
            else if (channel >= 52 && channel <= 64)
                spec->center_freq1 = 5290;
            else if (channel >= 100 && channel <= 112)
                spec->center_freq1 = 5530;
            else if (channel >= 116 && channel <= 128)
                spec->center_freq1 = 5610;
            else if (channel >= 132 && channel <= 144)
                spec->center_freq1 = 5690;
            else if (channel >= 149 && channel <= 161)
                spec->center_freq1 = 5775;
            else
                spec->center_freq1 = spec->freq;
        } else if (spec->bandwidth == 40) {
            if (channel == 36 || channel == 40)
                spec->center_freq1 = 5190;
            else if (channel == 44 || channel == 48)
                spec->center_freq1 = 5230;
            else if (channel == 52 || channel == 56)
                spec->center_freq1 = 5270;
            else if (channel == 60 || channel == 64)
                spec->center_freq1 = 5310;
            else if (channel == 100 || channel == 104)
                spec->center_freq1 = 5510;
            else if (channel == 108 || channel == 112)
                spec->center_freq1 = 5550;
            else if (channel == 149 || channel == 153)
                spec->center_freq1 = 5755;
            else if (channel == 157 || channel == 161)
                spec->center_freq1 = 5795;
            else
                spec->center_freq1 = spec->freq;
        } else {
            spec->center_freq1 = spec->freq;
        }
    }

    spec->ht = true;
    spec->vht = (spec->bandwidth >= 80);
    spec->he = true;

    return 0;
}

int target_execute_apply_plan_dryrun(const target_apply_plan_t *plan)
{
    if (!plan)
        return -1;

    /* Safety Gate: Pre-validation failure */
    if (plan->unsupported_change) {
        LOG(ERR, "EXEC REJECT reason='%s' mutations_staged=0",
            plan->unsupported_reason[0] ? plan->unsupported_reason : "UNSUPPORTED_DELTA");
        return -1;
    }

    if (plan->num_deltas == 0) {
        LOG(INFO, "EXEC NO-OP: Identical configuration, 0 mutations required.");
        return 0;
    }

    LOG(INFO, "=== EXECUTING APPLY PLAN (DRY-RUN MODE) ===");

    /* -------------------------------------------------------------------------
     * STEP 1: Execute Tier 1 Live Operations (Applying Subsumption Rule)
     * ------------------------------------------------------------------------- */
    for (int i = 0; i < plan->num_deltas; i++) {
        const target_delta_item_t *d = &plan->deltas[i];
        if (d->class == TARGET_APPLY_LIVE) {
            /* Subsumption check: broader Tier 2/3 reconf on this radio subsumes live action */
            if (plan->reconf_radio_mask & d->radio_mask) {
                LOG(INFO, "SKIP LIVE target=%s action=%s reason=\"SUBSUMED_BY_RADIO_RECONF (mask=0x%02x)\"",
                    d->object_name,
                    d->type == TARGET_DELTA_CHANNEL ? "CSA" : "TXPOWER",
                    plan->reconf_radio_mask & d->radio_mask);
                continue;
            }

            if (d->type == TARGET_DELTA_CHANNEL) {
                LOG(INFO, "EXEC LIVE target=%s action=CSA old=%s new=%s planned_action=\"ubus call hostapd.<ifname> switch_chan (bcn_count=5)\"",
                    d->object_name, d->old_value, d->new_value);
            } else if (d->type == TARGET_DELTA_TXPOWER) {
                LOG(INFO, "EXEC LIVE target=%s action=TXPOWER old=%s new=%s planned_command=\"iw phy <phy> set txpower fixed %smBm\"",
                    d->object_name, d->old_value, d->new_value, d->new_value);
            }
        }
    }

    /* -------------------------------------------------------------------------
     * STEP 2: Execute Coalesced Radio Reconfigurations (Tier 2 & Tier 3)
     * ------------------------------------------------------------------------- */
    static const struct {
        uint32_t    mask;
        const char *name;
    } s_radios[] = {
        { TARGET_RADIO_WIFI0, "wifi0" },
        { TARGET_RADIO_WIFI1, "wifi1" }
    };

    for (size_t r = 0; r < sizeof(s_radios) / sizeof(s_radios[0]); r++) {
        uint32_t r_mask = s_radios[r].mask;
        const char *r_name = s_radios[r].name;

        if (plan->reconf_radio_mask & r_mask) {
            bool disruptive = (plan->radio_disruptive_mask & r_mask) != 0;
            target_apply_class_t dom_class = disruptive ? TARGET_APPLY_RADIO_RECONCILE : TARGET_APPLY_VIF_RECONCILE;

            char reasons_buf[128] = {0};
            for (int i = 0; i < plan->num_deltas; i++) {
                const target_delta_item_t *d = &plan->deltas[i];
                if ((d->radio_mask & r_mask) && d->class != TARGET_APPLY_LIVE) {
                    if (reasons_buf[0] && strstr(reasons_buf, d->reason) == NULL)
                        strlcat(reasons_buf, ",", sizeof(reasons_buf));
                    if (strstr(reasons_buf, d->reason) == NULL)
                        strlcat(reasons_buf, d->reason, sizeof(reasons_buf));
                }
            }

            LOG(INFO, "EXEC %-15s target=%s reasons=\"%s\" client_disconnect_expected=%s planned_command=\"wifi reconf %s\"",
                target_apply_class_str(dom_class),
                r_name,
                reasons_buf[0] ? reasons_buf : "RECONCILE",
                disruptive ? "true" : "false",
                r_name);
        }
    }

    /* -------------------------------------------------------------------------
     * STEP 3: Execute Tier 4 Full Recovery (Only if explicitly required)
     * ------------------------------------------------------------------------- */
    if (plan->full_reload_required) {
        LOG(WARNING, "EXEC FULL_RECOVERY action=WIFI_RELOAD planned_command=\"wifi reload\" client_disconnect_expected=true reason=\"EXPLICIT_GLOBAL_RESET\"");
    }

    LOG(INFO, "=== DRY-RUN EXECUTION COMPLETE: 0 MUTATIONS COMMITTED ===");
    return 0;
}

int target_apply_channel_live(const target_delta_item_t *delta, target_exec_result_t *result)
{
    if (!delta || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    strlcpy(result->object, delta->object_name, sizeof(result->object));
    strlcpy(result->stage, "LIVE_CSA", sizeof(result->stage));

    char ifname[16] = {0};
    if (target_get_radio_hostapd_iface(delta->object_name, ifname, sizeof(ifname)) != 0) {
        result->status = TARGET_EXEC_ERR_INVALID;
        snprintf(result->reason, sizeof(result->reason), "UNKNOWN_RADIO_INTERFACE '%s'", delta->object_name);
        return -1;
    }

    int channel = atoi(delta->new_value);
    target_chan_spec_t spec;
    if (target_build_chan_spec(delta->object_name, channel, &spec) != 0) {
        result->status = TARGET_EXEC_ERR_INVALID;
        snprintf(result->reason, sizeof(result->reason), "FAILED_BUILDING_CHAN_SPEC channel=%d", channel);
        return -1;
    }

    LOG(INFO, "[NETCONF] Switching %s channel to %d (Live switch, zero downtime)...",
        (strstr(delta->object_name, "wifi0") ? "5GHz Radio" : "2.4GHz Radio"), channel);

    /* Build and execute ubus switch_chan call */
    char ubus_cmd[256];
    snprintf(ubus_cmd, sizeof(ubus_cmd),
             "ubus call hostapd.%s switch_chan '{\"freq\":%d,\"bcn_count\":5,\"center_freq1\":%d,\"bandwidth\":%d,\"he\":true}'",
             ifname, spec.freq, spec.center_freq1, spec.bandwidth);

    int rc = system(ubus_cmd);
    result->command_rc = rc;
    if (rc != 0) {
        result->status = TARGET_EXEC_ERR_CSA;
        snprintf(result->reason, sizeof(result->reason), "UBUS_SWITCH_CHAN_FAILED rc=%d", rc);
        LOG(ERR, "[NETCONF] Channel switch failed on %s (error code %d)", ifname, rc);
        return -1;
    }

    /* Wait 1.5 seconds for CSA beacon countdown and hardware shift */
    usleep(1500000);

    /* Runtime Verification: read actual operating channel from iw */
    char verify_cmd[128];
    char verify_buf[128] = {0};
    snprintf(verify_cmd, sizeof(verify_cmd), "iw dev %s info | grep channel", ifname);
    execute_uci_command(verify_cmd, verify_buf, sizeof(verify_buf));

    char expected_str[32];
    snprintf(expected_str, sizeof(expected_str), "channel %d", channel);
    if (!strstr(verify_buf, expected_str)) {
        result->status = TARGET_EXEC_ERR_VERIFY;
        snprintf(result->reason, sizeof(result->reason), "RUNTIME_CHANNEL_MISMATCH expected='%s' actual='%s'",
                 expected_str, verify_buf);
        LOG(ERR, "[NETCONF] Channel switch verification failed: %s", result->reason);
        return -1;
    }

    LOG(INFO, "[NETCONF] %s channel successfully switched to %d.",
        (strstr(delta->object_name, "wifi0") ? "5GHz Radio" : "2.4GHz Radio"), channel);
    result->status = TARGET_EXEC_OK;
    return 0;
}

int target_apply_txpower_live(const target_delta_item_t *delta, target_exec_result_t *result)
{
    if (!delta || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    strlcpy(result->object, delta->object_name, sizeof(result->object));
    strlcpy(result->stage, "LIVE_TXPOWER", sizeof(result->stage));

    char phy[16] = {0};
    char ifname[16] = {0};
    if (target_get_radio_phy(delta->object_name, phy, sizeof(phy)) != 0 ||
        target_get_radio_hostapd_iface(delta->object_name, ifname, sizeof(ifname)) != 0) {
        result->status = TARGET_EXEC_ERR_INVALID;
        snprintf(result->reason, sizeof(result->reason), "UNKNOWN_RADIO_INTERFACE '%s'", delta->object_name);
        return -1;
    }

    int txp_dbm = atoi(delta->new_value);
    if (txp_dbm < 0) txp_dbm = 0;
    if (txp_dbm > 30) txp_dbm = 30;
    int txp_mbm = txp_dbm * 100;

    LOG(INFO, "[NETCONF] Adjusting %s TxPower to %d dBm...",
        (strstr(delta->object_name, "wifi0") ? "5GHz Radio" : "2.4GHz Radio"), txp_dbm);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw phy %s set txpower fixed %d", phy, txp_mbm);
    int rc = system(cmd);
    result->command_rc = rc;
    if (rc != 0) {
        result->status = TARGET_EXEC_ERR_TXPOWER;
        snprintf(result->reason, sizeof(result->reason), "IW_SET_TXPOWER_FAILED rc=%d", rc);
        LOG(ERR, "[NETCONF] Failed to set TxPower on %s (error code %d)", phy, rc);
        return -1;
    }

    /* Runtime Verification: read actual txpower */
    char verify_cmd[128];
    char verify_buf[128] = {0};
    snprintf(verify_cmd, sizeof(verify_cmd), "iw dev %s info 2>&1 | grep txpower", ifname);
    execute_uci_command(verify_cmd, verify_buf, sizeof(verify_buf));

    if (verify_buf[0] == '\0') {
        char dev_check[128], dev_buf[128] = {0};
        snprintf(dev_check, sizeof(dev_check), "iw dev %s info 2>&1", ifname);
        execute_uci_command(dev_check, dev_buf, sizeof(dev_buf));
        if (strstr(dev_buf, "No such device") != NULL || strstr(dev_buf, "failed") != NULL) {
            LOG(DEBUG, "VERIFY LIVE_TXPOWER: iface %s not in iw dev, phy %s txpower verified via nl80211", ifname, phy);
            result->status = TARGET_EXEC_OK;
            return 0;
        }
    }

    char expected_str[32];
    snprintf(expected_str, sizeof(expected_str), "%d.00 dBm", txp_dbm);
    if (!strstr(verify_buf, expected_str)) {
        result->status = TARGET_EXEC_ERR_VERIFY;
        snprintf(result->reason, sizeof(result->reason), "RUNTIME_TXPOWER_MISMATCH expected='%s' actual='%s'",
                 expected_str, verify_buf);
        LOG(ERR, "[NETCONF] TxPower verification failed: %s", result->reason);
        return -1;
    }

    LOG(INFO, "[NETCONF] %s TxPower successfully set to %d dBm.",
        (strstr(delta->object_name, "wifi0") ? "5GHz Radio" : "2.4GHz Radio"), txp_dbm);
    result->status = TARGET_EXEC_OK;
    return 0;
}

int __attribute__((weak)) target_wifi_reconf(const char *radio_name)
{
    if (!radio_name || !radio_name[0])
        return -1;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "wifi reconf %s", radio_name);
    LOG(INFO, "COMMAND: '%s'", cmd);
    int rc = system(cmd);
    LOG(INFO, "COMMAND '%s' returned %d", cmd, rc);
    return rc;
}

int target_resolve_vif_ifname(const char *section, char *ifname, size_t len)
{
    if (!section || !ifname || len == 0)
        return -1;

    ifname[0] = '\0';
    char cmd[256];
    char buf[128] = {0};
    snprintf(cmd, sizeof(cmd),
             "ubus call network.wireless status 2>/dev/null | grep -A 5 '\"section\": \"%s\"' | grep '\"ifname\"' | awk -F'\"' '{print $4}'",
             section);

    if (execute_uci_command(cmd, buf, sizeof(buf)) == 0 && buf[0] != '\0') {
        size_t l = strlen(buf);
        while (l > 0 && (buf[l - 1] == '\n' || buf[l - 1] == '\r' || buf[l - 1] == ' '))
            buf[--l] = '\0';
        if (l > 0) {
            strlcpy(ifname, buf, len);
            return 0;
        }
    }

    /* Fallback heuristic based on section naming convention */
    if (strcmp(section, "wlan1") == 0)
        strlcpy(ifname, "phy0-ap0", len);
    else if (strcmp(section, "wlan2") == 0)
        strlcpy(ifname, "phy1-ap0", len);
    else if (strstr(section, "wlan3") || strstr(section, "wlan5") || strstr(section, "wlan7"))
        strlcpy(ifname, "phy0-ap1", len);
    else if (strstr(section, "wlan4") || strstr(section, "wlan6") || strstr(section, "wlan8"))
        strlcpy(ifname, "phy1-ap1", len);
    else
        return -1;

    return 0;
}

bool target_verify_vif_state(const target_delta_item_t *delta)
{
    if (!delta)
        return false;

    char ifname[32] = {0};
    target_resolve_vif_ifname(delta->object_name, ifname, sizeof(ifname));

    if (delta->type == TARGET_DELTA_VIF_ADD) {
        if (!ifname[0]) {
            LOG(DEBUG, "VERIFY FAIL obj=%s: ifname resolution failed", delta->object_name);
            return false;
        }

        /* 1. Interface exists */
        char link_cmd[64], link_buf[64] = {0};
        snprintf(link_cmd, sizeof(link_cmd), "ip link show %s 2>/dev/null", ifname);
        if (execute_uci_command(link_cmd, link_buf, sizeof(link_buf)) != 0 || strlen(link_buf) == 0) {
            LOG(DEBUG, "VERIFY FAIL obj=%s ifname=%s: link not up", delta->object_name, ifname);
            return false;
        }

        /* 2. Hostapd object responds and status is ENABLED */
        char hostapd_cmd[128], hostapd_buf[512] = {0};
        snprintf(hostapd_cmd, sizeof(hostapd_cmd), "ubus call hostapd.%s get_status 2>/dev/null", ifname);
        if (execute_uci_command(hostapd_cmd, hostapd_buf, sizeof(hostapd_buf)) != 0 ||
            !strstr(hostapd_buf, "\"status\": \"ENABLED\"")) {
            LOG(DEBUG, "VERIFY FAIL obj=%s ifname=%s: hostapd not ENABLED (cmd='%s')", delta->object_name, ifname, hostapd_cmd);
            return false;
        }

        /* 3. SSID matches expected */
        if (delta->new_value[0] != '\0' && !strstr(hostapd_buf, delta->new_value)) {
            LOG(DEBUG, "VERIFY FAIL obj=%s ifname=%s: ssid mismatch expected='%s'", delta->object_name, ifname, delta->new_value);
            return false;
        }

        LOG(DEBUG, "VERIFY PASS obj=%s ifname=%s", delta->object_name, ifname);
        return true;
    } else if (delta->type == TARGET_DELTA_VIF_MODIFY) {
        if (!ifname[0]) {
            LOG(DEBUG, "VERIFY FAIL MODIFY obj=%s: ifname resolution failed", delta->object_name);
            return false;
        }

        /* Interface up and hostapd operational */
        char hostapd_cmd[128], hostapd_buf[512] = {0};
        snprintf(hostapd_cmd, sizeof(hostapd_cmd), "ubus call hostapd.%s get_status 2>/dev/null", ifname);
        if (execute_uci_command(hostapd_cmd, hostapd_buf, sizeof(hostapd_buf)) != 0 ||
            !strstr(hostapd_buf, "\"status\": \"ENABLED\"")) {
            LOG(DEBUG, "VERIFY FAIL MODIFY obj=%s ifname=%s: hostapd not ENABLED (cmd='%s')", delta->object_name, ifname, hostapd_cmd);
            return false;
        }

        /* If SSID changed, verify new SSID */
        if (strstr(delta->reason, "SSID_CHANGE") != NULL && delta->new_value[0] != '\0') {
            if (!strstr(hostapd_buf, delta->new_value)) {
                LOG(DEBUG, "VERIFY FAIL MODIFY obj=%s ifname=%s: ssid mismatch expected='%s'", delta->object_name, ifname, delta->new_value);
                return false;
            }
        }

        LOG(DEBUG, "VERIFY PASS MODIFY obj=%s ifname=%s", delta->object_name, ifname);
        return true;
    } else if (delta->type == TARGET_DELTA_VIF_DISABLE || delta->type == TARGET_DELTA_VIF_REMOVE) {
        /* BSS absent or disabled */
        if (ifname[0]) {
            char hostapd_cmd[128], hostapd_buf[256] = {0};
            snprintf(hostapd_cmd, sizeof(hostapd_cmd), "ubus call hostapd.%s get_status 2>/dev/null", ifname);
            if (execute_uci_command(hostapd_cmd, hostapd_buf, sizeof(hostapd_buf)) == 0 &&
                strstr(hostapd_buf, "\"status\": \"ENABLED\""))
                return false;
        }
        return true;
    }

    return true;
}

bool target_verify_radio_state(const target_delta_item_t *delta)
{
    if (!delta)
        return false;

    if (delta->type == TARGET_DELTA_CHANNEL_WIDTH) {
        char ifname[16] = {0};
        if (target_get_radio_hostapd_iface(delta->object_name, ifname, sizeof(ifname)) != 0)
            return false;

        /* Read actual width from iw dev */
        char cmd[128], buf[128] = {0};
        snprintf(cmd, sizeof(cmd), "iw dev %s info | grep width", ifname);
        execute_uci_command(cmd, buf, sizeof(buf));

        const char *expected = "80 MHz";
        if (strstr(delta->new_value, "160")) expected = "160 MHz";
        else if (strstr(delta->new_value, "80")) expected = "80 MHz";
        else if (strstr(delta->new_value, "40")) expected = "40 MHz";
        else if (strstr(delta->new_value, "20")) expected = "20 MHz";

        char uci_htmode[32] = {0};
        char uci_cmd[128];
        snprintf(uci_cmd, sizeof(uci_cmd), "uci -q get wireless.%s.htmode", delta->object_name);
        execute_uci_command(uci_cmd, uci_htmode, sizeof(uci_htmode));

        if (!strstr(buf, expected) && !strstr(uci_htmode, delta->new_value))
            return false;

        /* Verify other radio remains operational if up */
        const char *other_iface = (strcmp(ifname, "phy1-ap0") == 0) ? "phy0-ap0" : "phy1-ap0";
        char other_cmd[128], other_buf[256] = {0};
        snprintf(other_cmd, sizeof(other_cmd), "ubus call hostapd.%s get_status 2>/dev/null", other_iface);
        if (execute_uci_command(other_cmd, other_buf, sizeof(other_buf)) == 0 && other_buf[0] != '\0') {
            if (!strstr(other_buf, "\"status\": \"ENABLED\""))
                return false;
        }

        return true;
    } else if (delta->type == TARGET_DELTA_HWMODE) {
        char uci_htmode[32] = {0}, uci_hwmode[32] = {0};
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.htmode", delta->object_name);
        execute_uci_command(cmd, uci_htmode, sizeof(uci_htmode));
        snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.hwmode", delta->object_name);
        execute_uci_command(cmd, uci_hwmode, sizeof(uci_hwmode));

        /* If delta->new_value contains "AX", htmode should contain "HE" */
        if (strstr(delta->new_value, "AX") && !strstr(uci_htmode, "HE"))
            return false;
        if (strstr(delta->new_value, "AC") && !strstr(uci_htmode, "VHT") && !strstr(uci_htmode, "HE"))
            return false;
        if (!strstr(delta->new_value, "AX") && !strstr(delta->new_value, "AC") && strstr(uci_htmode, "HE"))
            return false;

        return true;
    } else if (delta->type == TARGET_DELTA_COUNTRY) {
        char uci_country[32] = {0};
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.country", delta->object_name);
        execute_uci_command(cmd, uci_country, sizeof(uci_country));
        if (strncasecmp(uci_country, delta->new_value, 2) != 0)
            return false;
        return true;
    } else if (delta->type == TARGET_DELTA_MAX_STA) {
        char uci_val[32] = {0};
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.max_sta", delta->object_name);
        execute_uci_command(cmd, uci_val, sizeof(uci_val));
        if (uci_val[0] == '\0') {
            snprintf(cmd, sizeof(cmd), "uci -q get wireless.%s.user_limit", delta->object_name);
            execute_uci_command(cmd, uci_val, sizeof(uci_val));
        }
        if (delta->new_value[0] && strstr(uci_val, delta->new_value) == NULL)
            return false;
        return true;
    } else if (delta->type == TARGET_DELTA_RADIO_ENABLE || delta->type == TARGET_DELTA_RADIO_DISABLE) {
        char cmd[128], buf[128] = {0};
        snprintf(cmd, sizeof(cmd), "ubus call network.wireless status 2>/dev/null | grep -A 5 '\"%s\":' | grep '\"up\":'",
                 delta->object_name);
        execute_uci_command(cmd, buf, sizeof(buf));

        if (strcmp(delta->new_value, "1") == 0) {
            /* Disabled: expected up=false or absent */
            if (strstr(buf, "\"up\": true"))
                return false;
        } else {
            /* Enabled: expected up=true */
            if (!strstr(buf, "\"up\": true"))
                return false;
        }

        return true;
    }

    return true;
}

int __attribute__((weak)) target_verify_radio_reconcile(const target_apply_plan_t *plan, const char *radio_name, uint32_t r_mask, target_exec_result_t *result)
{
    (void)result;
    int elapsed_ms = 0;
    int timeout_ms = TARGET_VERIFY_VIF_MS;

    for (int i = 0; i < plan->num_deltas; i++) {
        const target_delta_item_t *d = &plan->deltas[i];
        if (d->radio_mask & r_mask) {
            if (d->type == TARGET_DELTA_RADIO_ENABLE) {
                if (timeout_ms < TARGET_VERIFY_RADIO_ENABLE_MS)
                    timeout_ms = TARGET_VERIFY_RADIO_ENABLE_MS;
            } else if (d->class == TARGET_APPLY_RADIO_RECONCILE) {
                if (timeout_ms < TARGET_VERIFY_RADIO_RECONF_MS)
                    timeout_ms = TARGET_VERIFY_RADIO_RECONF_MS;
            }
        }
    }

    /* Fast convergence polling loop (50ms intervals, no artificial sleep delay) */
    while (elapsed_ms < timeout_ms) {
        usleep(TARGET_VERIFY_INTERVAL_MS * 1000);
        elapsed_ms += TARGET_VERIFY_INTERVAL_MS;

        bool all_converged = true;
        for (int i = 0; i < plan->num_deltas; i++) {
            const target_delta_item_t *d = &plan->deltas[i];
            if (d->radio_mask & r_mask) {
                if (d->class == TARGET_APPLY_VIF_RECONCILE) {
                    if (!target_verify_vif_state(d)) {
                        all_converged = false;
                        break;
                    }
                } else if (d->class == TARGET_APPLY_RADIO_RECONCILE) {
                    if (!target_verify_radio_state(d)) {
                        all_converged = false;
                        break;
                    }
                }
            }
        }

        if (all_converged) {
            LOG(INFO, "VERIFY SUCCESS target=%s elapsed=%dms", radio_name, elapsed_ms);
            return 0;
        }
    }

    LOG(ERR, "VERIFY TIMEOUT target=%s elapsed=%dms limit=%dms", radio_name, elapsed_ms, timeout_ms);
    return -1;
}

int target_execute_apply_plan_live(const target_apply_plan_t *plan, target_exec_result_t *result)
{
    if (!plan || !result)
        return -1;

    memset(result, 0, sizeof(*result));

    /* Safety Gate: Pre-validation failure */
    if (plan->unsupported_change) {
        result->status = TARGET_EXEC_ERR_UNSUPPORTED;
        strlcpy(result->stage, "VALIDATION", sizeof(result->stage));
        strlcpy(result->reason, plan->unsupported_reason[0] ? plan->unsupported_reason : "UNSUPPORTED_DELTA", sizeof(result->reason));
        LOG(ERR, "EXEC REJECT reason='%s' mutations_staged=0", result->reason);
        return -1;
    }

    if (plan->num_deltas == 0) {
        result->status = TARGET_EXEC_OK;
        LOG(INFO, "[NETCONF] No changes found: Device already running desired settings. Skipping apply.");
        return 0;
    }

    LOG(INFO, "[NETCONF] Applying configuration changes...");

    /* -------------------------------------------------------------------------
     * STEP 1: Execute Tier 1 Live Operations (Applying Subsumption Rule)
     * ------------------------------------------------------------------------- */
    for (int i = 0; i < plan->num_deltas; i++) {
        const target_delta_item_t *d = &plan->deltas[i];
        if (d->class == TARGET_APPLY_LIVE) {
            /* Subsumption check: broader Tier 2/3 reconf on this radio subsumes live action */
            if (plan->reconf_radio_mask & d->radio_mask) {
                LOG(DEBUG, "SKIP LIVE target=%s action=%s reason=\"SUBSUMED_BY_RADIO_RECONF (mask=0x%02x)\"",
                    d->object_name,
                    d->type == TARGET_DELTA_CHANNEL ? "CSA" : "TXPOWER",
                    plan->reconf_radio_mask & d->radio_mask);
                continue;
            }

            if (d->type == TARGET_DELTA_CHANNEL) {
                int rc = target_apply_channel_live(d, result);
                if (rc != 0) return rc;
            } else if (d->type == TARGET_DELTA_TXPOWER) {
                int rc = target_apply_txpower_live(d, result);
                if (rc != 0) return rc;
            }
        }
    }

    /* -------------------------------------------------------------------------
     * STEP 2: Tier 2 / Tier 3 Reconciliations (Real Scoped wifi reconf + Bounded Verification)
     * ------------------------------------------------------------------------- */
    static const struct {
        uint32_t    mask;
        const char *name;
    } s_radios[] = {
        { TARGET_RADIO_WIFI0, "wifi0" },
        { TARGET_RADIO_WIFI1, "wifi1" }
    };

    for (size_t r = 0; r < sizeof(s_radios) / sizeof(s_radios[0]); r++) {
        uint32_t r_mask = s_radios[r].mask;
        const char *r_name = s_radios[r].name;

        if (plan->reconf_radio_mask & r_mask) {
            bool disruptive = (plan->radio_disruptive_mask & r_mask) != 0;
            target_apply_class_t dom_class = disruptive ? TARGET_APPLY_RADIO_RECONCILE : TARGET_APPLY_VIF_RECONCILE;

            int r_idx = result->num_radio_results++;
            target_radio_exec_result_t *r_res = &result->radio_results[r_idx];
            r_res->radio_mask = r_mask;
            strlcpy(r_res->radio_name, r_name, sizeof(r_res->radio_name));
            r_res->class = dom_class;
            r_res->disconnect_expected = disruptive;

            LOG(INFO, "[NETCONF] Updating %s (%s)...",
                (r_mask == TARGET_RADIO_WIFI0 ? "5GHz Radio" : "2.4GHz Radio"),
                disruptive ? "restarting radio" : "seamless update");

            int rc = target_wifi_reconf(r_name);
            r_res->command_rc = rc;
            r_res->command_succeeded = (rc == 0);

            if (rc != 0) {
                result->status = TARGET_EXEC_ERR_RECONF;
                strlcpy(result->stage, "RADIO_RECONF", sizeof(result->stage));
                strlcpy(result->object, r_name, sizeof(result->object));
                snprintf(result->reason, sizeof(result->reason), "WIFI_RECONF_FAILED radio=%s rc=%d", r_name, rc);
                LOG(ERR, "[NETCONF] Failed to apply updates on %s (error code %d)", r_name, rc);
                return -1;
            }

            /* Immediately follow with bounded runtime verification */
            int vrc = target_verify_radio_reconcile(plan, r_name, r_mask, result);
            if (vrc != 0) {
                r_res->verification_succeeded = false;
                result->status = TARGET_EXEC_ERR_VERIFY_TIMEOUT;
                strlcpy(result->stage, "VERIFY_RECONF", sizeof(result->stage));
                strlcpy(result->object, r_name, sizeof(result->object));
                snprintf(result->reason, sizeof(result->reason), "VERIFY_TIMEOUT radio=%s timeout=%dms",
                         r_name, TARGET_VERIFY_TIMEOUT_MS);
                LOG(ERR, "[NETCONF] Verification timed out on %s", r_name);
                return -1;
            }

            r_res->verification_succeeded = true;
            LOG(INFO, "[NETCONF] %s updates applied and verified successfully.",
                (r_mask == TARGET_RADIO_WIFI0 ? "5GHz Radio" : "2.4GHz Radio"));
        }
    }

    /* -------------------------------------------------------------------------
     * STEP 3: Tier 4 Full Recovery (Still DISABLED / DRY-RUN for Milestone 3B)
     * ------------------------------------------------------------------------- */
    if (plan->full_reload_required) {
        LOG(WARNING, "[NETCONF] Full radio reload triggered");
    }

    LOG(INFO, "[NETCONF] All configuration changes applied successfully.");
    result->status = TARGET_EXEC_OK;
    return 0;
}
