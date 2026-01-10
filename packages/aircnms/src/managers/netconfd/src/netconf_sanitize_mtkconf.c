#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "netconf.h"

#define IS_VALID_CHAR(c) (isalnum((unsigned char)(c)) || c == '-' || c == '_' || c == '.' || c == ':' || c == ' ')
#define SAFE_STRCPY(dest, src) strlcpy(dest, (src) ? (src) : "", sizeof(dest))

// --- helpers ---

static bool is_number(const char *s)
{
    if (!s || !*s) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return false;
    }
    return true;
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


static void sanitize_string(char *dst, const char *src, size_t maxlen)
{
    size_t j = 0;
    if (!src) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; src[i] != '\0' && j < maxlen - 1; i++) {
        if (IS_VALID_CHAR(src[i]))
            dst[j++] = src[i];
        else
            dst[j++] = '_';
    }
    dst[j] = '\0';
}

static bool is_valid_ip(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

static bool is_valid_port(const char *port_str)
{
    if (!port_str || !*port_str)
        return false;
    int port = atoi(port_str);
    return port > 0 && port <= 65535;
}

static bool is_valid_encryption(const char *enc)
{
    const char *valid_encs[] = {
        "none", "wep", "psk", "psk2", "psk-mixed", "sae", 
        "sae-mixed", "wpa2", "wpa3", NULL
    };
    for (int i = 0; valid_encs[i]; i++) {
        if (strcmp(enc, valid_encs[i]) == 0)
            return true;
    }
    return false;
}

static bool is_valid_vlan_id(const char *vlan_str)
{
    if (!vlan_str || !*vlan_str)
        return false;
    for (const char *p = vlan_str; *p; ++p) {
        if (!isdigit((unsigned char)*p))
            return false;
    }
    int vlan = atoi(vlan_str);
    return vlan >= 0 && vlan <= 4094;
}

static bool is_valid_ssid(const char *ssid)
{
    size_t len = strlen(ssid);
    return len > 0 && len <= 32;
}

static bool is_valid_key(const char *key, const char *encryption)
{
    if (strcmp(encryption, "none") == 0)
        return true;

    size_t len = strlen(key);
    if (len == 0)
        return false;

    // WPA/WPA2/SAE keys must be 8–63 chars (ASCII) or 64 hex digits
    if ((len >= 8 && len <= 63))
        return true;

    if (len == 64) {
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit((unsigned char)key[i]))
                return false;
        }
        return true;
    }
    return false;
}

// --- main sanitization and validation ---

bool sanitize_and_validate_vif_params(struct airpro_mgr_wlan_vap_params *p)
{
    struct airpro_mgr_wlan_vap_params clean;
    memset(&clean, 0, sizeof(clean));

    // Sanitize all strings first
    sanitize_string(clean.record_id, p->record_id, sizeof(clean.record_id));
    sanitize_string(clean.mobility_id, p->mobility_id, sizeof(clean.mobility_id));
    sanitize_string(clean.ssid, p->ssid, sizeof(clean.ssid));
    sanitize_string(clean.key, p->key, sizeof(clean.key));
    sanitize_string(clean.encryption, p->encryption, sizeof(clean.encryption));
    sanitize_string(clean.hide_ssid, p->hide_ssid, sizeof(clean.hide_ssid));
    sanitize_string(clean.disabled, p->disabled, sizeof(clean.disabled));
    sanitize_string(clean.forward_type, p->forward_type, sizeof(clean.forward_type));
    sanitize_string(clean.vlan_id, p->vlan_id, sizeof(clean.vlan_id));
    sanitize_string(clean.network, p->network, sizeof(clean.network));
    sanitize_string(clean.server_ip, p->server_ip, sizeof(clean.server_ip));
    sanitize_string(clean.auth_port, p->auth_port, sizeof(clean.auth_port));
    sanitize_string(clean.acct_port, p->acct_port, sizeof(clean.acct_port));
    sanitize_string(clean.secret_key, p->secret_key, sizeof(clean.secret_key));

    bool valid = true;

    // --- Logical checks ---
    if (!is_valid_ssid(clean.ssid)) {
        fprintf(stderr, "Invalid SSID: '%s'\n", clean.ssid);
        valid = false;
    }

    if (!is_valid_encryption(clean.encryption)) {
        fprintf(stderr, "Invalid encryption type: '%s'\n", clean.encryption);
        SAFE_STRCPY(clean.encryption, "none");
    }

    if (!is_valid_key(clean.key, clean.encryption)) {
        fprintf(stderr, "Invalid key for encryption '%s'\n", clean.encryption);
        clean.key[0] = '\0';
    }

    if (!is_valid_vlan_id(clean.vlan_id)) {
        fprintf(stderr, "Invalid VLAN ID: '%s', setting to 0\n", clean.vlan_id);
        SAFE_STRCPY(clean.vlan_id, "0");
    }

    if (strcmp(clean.encryption, "wpa2-enterprise") == 0 ||
        strcmp(clean.encryption, "wpa3-enterprise") == 0) {

        if (!is_valid_ip(clean.server_ip)) {
            fprintf(stderr, "Invalid RADIUS server IP: '%s'\n", clean.server_ip);
            valid = false;
        }
        if (!is_valid_port(clean.auth_port) || !is_valid_port(clean.acct_port)) {
            fprintf(stderr, "Invalid RADIUS port(s)\n");
            valid = false;
        }
        if (strlen(clean.secret_key) == 0) {
            fprintf(stderr, "Empty RADIUS secret\n");
            valid = false;
        }
    }

    // Default forward type if empty
    if (strlen(clean.forward_type) == 0)
        SAFE_STRCPY(clean.forward_type, "Bridge");

    // Copy sanitized+validated structure back
    memcpy(p, &clean, sizeof(clean));
    return valid;
}

void get_ht_mode(char *htmode, struct airpro_mgr_wlan_radio_params rp, const char *radio_name)
{
    char hwmode_brd[8] = {0};

    /* Determine HW mode string */
    if (strcmp(radio_name, "wifi1") == 0) {  // 2.4 GHz
        if (strcmp(rp.hwmode, "11B") == 0 || strcmp(rp.hwmode, "11G") == 0 || strcmp(rp.hwmode, "11BGN") == 0) {
            strcpy(hwmode_brd, "11ng");
        } else if (strcmp(rp.hwmode, "11AX") == 0 || strcmp(rp.hwmode, "11BGN_11AX") == 0) {
            strcpy(hwmode_brd, "11axg");
        }
    } else if (strcmp(radio_name, "wifi0") == 0) {  // 5 GHz
        if (strcmp(rp.hwmode, "11NA") == 0) {
            strcpy(hwmode_brd, "11na");
        } else if (strcmp(rp.hwmode, "11AC") == 0) {
            strcpy(hwmode_brd, "11ac");
        } else if (strcmp(rp.hwmode, "11AX") == 0 || strcmp(rp.hwmode, "11NA_11AC_11AX") == 0) {
            strcpy(hwmode_brd, "11axa");
        }
    }

    /* Map to proper HT/VHT/HE mode based on HW mode */
    if (strcmp(hwmode_brd, "11ng") == 0) {
        // 802.11n on 2.4GHz
        sprintf(htmode, "HT%s", rp.channel_width);
    } else if (strcmp(hwmode_brd, "11na") == 0) {
        // 802.11n on 5GHz
        sprintf(htmode, "HT%s", rp.channel_width);
    } else if (strcmp(hwmode_brd, "11ac") == 0) {
        // 802.11ac on 5GHz
        sprintf(htmode, "VHT%s", rp.channel_width);
    } else if (strcmp(hwmode_brd, "11axa") == 0) {
        // 802.11ax (Wi-Fi 6) on 5GHz
        sprintf(htmode, "HE%s", rp.channel_width);
    } else if (strcmp(hwmode_brd, "11axg") == 0) {
        // 802.11ax (Wi-Fi 6) on 2.4GHz
        sprintf(htmode, "HE%s", rp.channel_width);
    } else {
        // Default fallback
        strcpy(htmode, "HT20");
    }
}

bool sanitize_and_validate_primary_radio_settings(const char *band,
                                                  struct airpro_mgr_wlan_radio_params *params)
{
    if (!band || !params) return false;

    /* --- sanitize disabled --- */
    if (strcmp(params->disabled, "0") && strcmp(params->disabled, "1")) {
        printf("Invalid disabled=%s → set to 0\n", params->disabled);
        strcpy(params->disabled, "0");
    }

    /* --- sanitize country --- */
    if (strlen(params->country) < 2) {
        printf("Empty country → default to 'IN'\n");
        strcpy(params->country, "IN");
    } else {
        // uppercase normalization
        for (int i = 0; i < 2; i++)
            params->country[i] = toupper(params->country[i]);
        params->country[2] = '\0';
    }

    /* --- sanitize channel width --- */
    int cw = atoi(params->channel_width);
    if (strcmp(band, "2.4GHz") == 0) {
        if (cw != 20 && cw != 40) {
            printf("Invalid width %d for 2.4GHz → default 20\n", cw);
            strcpy(params->channel_width, "40");
        }
    } else if (strcmp(band, "5GHz") == 0) {
        if (cw != 20 && cw != 40 && cw != 80 && cw != 160) {
            printf("Invalid width %d for 5GHz → default 80\n", cw);
            strcpy(params->channel_width, "80");
        }
    }

    /* --- sanitize htmode --- */
    if (strcmp(band, "2.4GHz") == 0) {
        if (strlen(params->htmode) == 0) {
            printf("Missing htmode → fallback to HE40\n");
            strcpy(params->htmode, "HE40");
        }
    } else if (strcmp(band, "5GHz") == 0) {
        if (strlen(params->htmode) == 0) {
            printf("Missing htmode → fallback to HE80\n");
            strcpy(params->htmode, "HE80");
        }
    }

    return true;
}

bool sanitize_and_validate_secondary_radio_settings(const char* radio_name, const char *band,
                                                    struct airpro_mgr_wlan_radio_params *params)
{
    //char htmode[32] = {0};
    //char cmd[128];
    if (!band || !params) return false;

    const char *ch_str  = params->channel;
    const char *txp_str = params->txpower;

    /* ---------- TX POWER ---------- */
    int txp = atoi(txp_str);   // txpower is always numeric

    if (strcmp(band, "2.4GHz") == 0) {
        if (txp < 0 || txp > 30) {
            printf("Invalid 2.4GHz txpower=%d → default 20\n", txp);
            strcpy(params->txpower, "20");
        }
    } 
    else if (strcmp(band, "5GHz") == 0) {

        /* ---------- CHANNEL ---------- */
        if (strcmp(ch_str, "auto") == 0) {
            /* valid, do nothing */
        }
        else if (is_number(ch_str)) {
            int ch = atoi(ch_str);
            if (ch < 36 || ch > 165) {
                printf("Invalid 5GHz channel=%d → default 36\n", ch);
                strcpy(params->channel, "36");
            }
        }
        else {
            /* garbage value */
            printf("Invalid 5GHz channel=%s → default auto\n", ch_str);
            strcpy(params->channel, "auto");
        }

        /* ---------- TX POWER ---------- */
        if (txp < 0 || txp > 30) {
            printf("Invalid 5GHz txpower=%d → default 23\n", txp);
            strcpy(params->txpower, "23");
        }
    }

    return true;
}

